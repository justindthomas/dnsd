"""SIGHUP reload — forwarder-table swap + listener rebind.

dnsd re-reads `/etc/dnsd/router.yaml` on SIGHUP, atomically swaps
the recursor handler (so cache + reactor + VCL session state carry
over), publishes the new forwarder table to the control socket,
and diffs the listener set against the new config. Listeners
removed from config are aborted; listeners added are spawned with
the same retry-on-FIB-race logic as initial bind. Cache is NOT
flushed across reload.

Each test patches `/etc/dnsd/router.yaml` in-place, sends SIGHUP,
verifies the change took effect, then restores the canonical
config and re-SIGHUPs so the rest of the suite sees the original
listeners.
"""

import time

CANONICAL_CONFIG_REMOTE = "/tmp/router.yaml.canonical"


def _save_canonical(ssh):
    """Snapshot the current router.yaml on the VM so we can put it
    back at test teardown."""
    rc, _, _ = ssh(
        f"cp /etc/dnsd/router.yaml {CANONICAL_CONFIG_REMOTE}"
    )
    assert rc == 0, "snapshot of canonical router.yaml failed"


def _restore_canonical_and_reload(ssh):
    """Put back the snapshot and SIGHUP dnsd. Done at end of every
    reload test so the next test starts from a known config."""
    rc, _, _ = ssh(
        f"cp {CANONICAL_CONFIG_REMOTE} /etc/dnsd/router.yaml && pkill -HUP dnsd"
    )
    assert rc == 0, "restoring router.yaml failed"
    time.sleep(0.5)


def _patch_yaml_remote(ssh, python_replace_script: str):
    """Run a small Python snippet on the VM that mutates
    /etc/dnsd/router.yaml. Caller supplies the body; the wrapper
    just imports pathlib + opens the file."""
    full = (
        "import pathlib; "
        "p = pathlib.Path('/etc/dnsd/router.yaml'); "
        "text = p.read_text(); "
        f"{python_replace_script}; "
        "p.write_text(text)"
    )
    rc, out, err = ssh(f"python3 -c \"{full}\"")
    assert rc == 0, f"yaml patch failed: {out} {err}"


def test_sighup_reloads_forwarder_table(ssh, dnsd_query):
    """Add a forwarder via router.yaml + SIGHUP — `dnsd-query
    forwarders` must reflect it."""
    _save_canonical(ssh)
    try:
        before = dnsd_query("forwarders")
        before_domains = {f["domain"].rstrip(".") for f in before["forwarders"]}
        assert "example.com" not in before_domains, before_domains

        # Append a new forwarder block.
        _patch_yaml_remote(
            ssh,
            "old = '    - domain: iana.org\\n      servers: [1.1.1.1]'; "
            "text = text.replace(old, old + '\\n    - domain: example.com\\n      servers: [9.9.9.9]')",
        )
        rc, _, _ = ssh("pkill -HUP dnsd")
        assert rc == 0
        time.sleep(0.5)

        after = dnsd_query("forwarders")
        after_domains = {f["domain"].rstrip(".") for f in after["forwarders"]}
        assert "example.com" in after_domains, (
            f"reload didn't publish new forwarder: {after}"
        )
        assert "iana.org" in after_domains, (
            f"reload dropped existing forwarder: {after}"
        )
    finally:
        _restore_canonical_and_reload(ssh)


def test_sighup_aborts_removed_listener(ssh):
    """Drop the v6 listener from router.yaml + SIGHUP — VPP's
    session table should no longer show the v6 LISTEN sessions."""
    _save_canonical(ssh)
    try:
        # Confirm v6 listener is up before the test.
        rc, before, _ = ssh(
            "vppctl -s /run/vpp/cli.sock show session verbose 2>&1 | "
            "grep -c 'db8:99::2:53.*LISTEN' || true"
        )
        assert int(before.strip() or "0") >= 2, (
            f"precondition: v6 listeners not up, got {before!r}"
        )

        # Strip the wan-v6 listener block via Python regex.
        _patch_yaml_remote(
            ssh,
            "import re; "
            "text = re.sub(r'    - name: wan-v6.*?dns64: true\\n', '', text, flags=re.DOTALL)",
        )
        rc, _, _ = ssh("pkill -HUP dnsd")
        assert rc == 0
        time.sleep(1.0)

        rc, after, _ = ssh(
            "vppctl -s /run/vpp/cli.sock show session verbose 2>&1 | "
            "grep -c 'db8:99::2:53.*LISTEN' || true"
        )
        assert int(after.strip() or "0") == 0, (
            f"v6 listeners still in VPP after reload: {after!r}"
        )

        # The journal log line is the contract operators look at.
        rc, journal, _ = ssh(
            "journalctl -u dnsd.service --since '10 seconds ago' --no-pager | "
            "grep -c 'aborting listener.*wan-v6' || true"
        )
        assert int(journal.strip() or "0") >= 2, (
            f"expected abort log lines for both v6 protocols: {journal!r}"
        )
    finally:
        _restore_canonical_and_reload(ssh)


def test_sighup_spawns_added_listener(ssh):
    """Drop v6 + reload, then put it back + reload — second reload
    must re-spawn the v6 listeners. Verifies the add-listener
    branch of the diff."""
    _save_canonical(ssh)
    try:
        # First reload: remove v6.
        _patch_yaml_remote(
            ssh,
            "import re; "
            "text = re.sub(r'    - name: wan-v6.*?dns64: true\\n', '', text, flags=re.DOTALL)",
        )
        ssh("pkill -HUP dnsd")
        time.sleep(1.0)

        # Second reload: restore canonical (v6 back).
        rc, _, _ = ssh(
            f"cp {CANONICAL_CONFIG_REMOTE} /etc/dnsd/router.yaml && pkill -HUP dnsd"
        )
        assert rc == 0
        time.sleep(1.5)  # give the listener-bind retry path a beat

        rc, count, _ = ssh(
            "vppctl -s /run/vpp/cli.sock show session verbose 2>&1 | "
            "grep -c 'db8:99::2:53.*LISTEN' || true"
        )
        assert int(count.strip() or "0") >= 2, (
            f"v6 listeners didn't come back after second reload: {count!r}"
        )
    finally:
        _restore_canonical_and_reload(ssh)


def test_sighup_invalid_config_keeps_old_state(ssh, dnsd_query):
    """A malformed router.yaml must NOT swap state — the daemon
    keeps serving with the previous handler + listener set. Any
    other behaviour means a typo can take the resolver offline."""
    _save_canonical(ssh)
    try:
        before = dnsd_query("forwarders")

        # Introduce a syntax error.
        _patch_yaml_remote(
            ssh,
            "text = text + '\\n!!!!  bad yaml  !!!!\\n'",
        )
        rc, _, _ = ssh("pkill -HUP dnsd")
        assert rc == 0
        time.sleep(0.5)

        # Forwarder table should be unchanged.
        after = dnsd_query("forwarders")
        assert before == after, (
            f"reload with bad yaml mutated state — before={before}, after={after}"
        )

        # Journal should call out the abort.
        rc, journal, _ = ssh(
            "journalctl -u dnsd.service --since '10 seconds ago' --no-pager | "
            "grep -c 'reload aborted' || true"
        )
        assert int(journal.strip() or "0") >= 1, (
            f"expected 'reload aborted' log line: {journal!r}"
        )
    finally:
        _restore_canonical_and_reload(ssh)
