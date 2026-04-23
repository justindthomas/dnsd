#!/bin/bash
# Post-VPP-boot configuration that can't be expressed in startup.conf.
#
# VPP's app-namespace binding needs a sw_if_index and that's only
# known after the af_xdp interface comes up, so we issue it as a
# CLI command here instead of in the bootstrap script.

set -euo pipefail

VPPCTL="vppctl -s /run/vpp/cli.sock"

# Wait for VPP's CLI socket + for `wan` to show up.
for _ in $(seq 1 30); do
    if $VPPCTL show version 2>/dev/null | grep -q 'vpp v'; then
        break
    fi
    sleep 1
done

for _ in $(seq 1 30); do
    if $VPPCTL show interface wan 2>/dev/null | grep -q '^wan '; then
        break
    fi
    sleep 1
done

# Look up the sw_if_index for `wan` and bind the default app
# namespace to it so dnsd (running as a VCL app in the default
# namespace) can actually see traffic on that interface.
idx=$($VPPCTL show interface wan 2>/dev/null | awk '/^wan/ {print $2}')
if [ -z "$idx" ]; then
    echo "[-] wan interface didn't come up; aborting" >&2
    $VPPCTL show interface 2>&1 | head -20 >&2
    exit 1
fi

$VPPCTL app ns add id default secret 0 sw_if_index "$idx"
echo "[+] bound app-namespace default → wan (sw_if_index=$idx)"

# Summary for the systemd log.
$VPPCTL show app ns
$VPPCTL show interface address
