# dnsd integration tests

Self-contained integration harness for `dnsd`. Just VPP + the
daemon, configured for exactly what dnsd needs — no external
supervisor, no sibling daemons.

## Topology

```
┌─ build host ──────────────────────────────────────────────┐
│                                                           │
│   br-dnsdtest (10.99.0.0/24)                              │
│      │                                                    │
│      ├──── tap-dnsdtest ──── virtio-net ──┐               │
│      │                                    │               │
│   10.99.0.1                        ┌──────▼──────────┐    │
│   (host side,                      │  dnsd-test-vm   │    │
│    where dig runs)                 │   ┌──────────┐  │    │
│                                    │   │   VPP    │  │    │
│                                    │   │ (af_xdp  │  │    │
│                                    │   │  on      │  │    │
│                                    │   │ enp0s4)  │  │    │
│                                    │   └──┬───────┘  │    │
│                                    │      │ VCL      │    │
│                                    │   ┌──▼───────┐  │    │
│                                    │   │   dnsd   │  │    │
│                                    │   └──────────┘  │    │
│                                    │  10.99.0.2      │    │
│                                    └─────────────────┘    │
└───────────────────────────────────────────────────────────┘
```

* Primary NIC (`enp0s3`, QEMU user-net) → SSH access on port 2290
* Secondary NIC (`enp0s4`, `tap-dnsdtest` on `br-dnsdtest`) →
  VPP grabs this via `af_xdp`, binds `10.99.0.2/24` on `wan`.
* `dnsd` listens on `10.99.0.2:53` (UDP + TCP) through VCL.
* Test client is the build host itself — it's on `br-dnsdtest`
  with IP `10.99.0.1`, and fires queries at `10.99.0.2`.

## Commands

```bash
# One-time: build the golden qcow2 (installs VPP, sets up configs).
# Takes ~5-10 min first run; subsequent re-runs reuse the golden.
./build-vm.sh

# Run the integration tests. Clones golden → boots → builds a
# bookworm-compatible dnsd binary if needed → SCPs it in →
# pytest → teardown.
./run-tests.sh

# Debug: boot the VM and leave it running.
./run-tests.sh --no-teardown
# Then: ssh -p 2290 root@localhost   (password: dnsd)
#       VNC at :50
```

## Iteration on dnsd source

`run-tests.sh` auto-locates a Bookworm-compatible `dnsd` binary:

1. Explicit `--dnsd-binary <path>`.
2. `DNSD_TEST_BINARY` env var.
3. `tests/integration/.work/dnsd-bookworm` (built by
   `build-bookworm.sh`).
4. Falls through to calling `build-bookworm.sh` which builds it in a
   podman container (first run ~3-5 min; cached thereafter).

SCPs the binary into the VM and restarts the `dnsd.service` unit
before running pytest — no need to rebuild the golden image for
source edits.

## Layout

```
tests/integration/
├── README.md
├── build-vm.sh           # Build golden qcow2 (first-run: 5-10 min)
├── build-bookworm.sh     # Build dnsd binary in bookworm container
├── run-tests.sh          # Boot + test + teardown
├── vm-assets/            # Files baked into the VM
│   ├── cloud-init.yaml   # user-data for first-boot setup
│   ├── startup.conf      # VPP minimal config
│   ├── vcl.conf          # VCL client config for dnsd
│   ├── commands.txt      # VPP CLI commands (af_xdp, addresses)
│   ├── router.yaml       # dnsd config (one forwarder for iana.org)
│   ├── vpp-test.service  # systemd unit bringing up VPP
│   ├── dnsd.service      # systemd unit bringing up dnsd
│   └── configure-vpp.sh  # Runs after VPP boots to set up app namespace
└── pytests/              # Test scenarios
    ├── conftest.py
    └── test_smoke.py
```
