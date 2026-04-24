#!/bin/bash
# Post-VPP-start configuration.
#
# Runs from vpp-test.service's ExecStartPost after VPP has started
# and is serving its CLI. Three things to do:
#
#   1. Wait for `wan` to exist (dpdk plugin created it from the
#      startup.conf `dpdk { dev 0000:00:04.0 { name wan } }` block).
#   2. Bring it up + promisc on + assign the IPs. Doing this here
#      rather than in /etc/vpp/commands.txt because during VPP's
#      exec-commands phase, virtio-dpdk's carrier is still down
#      and `set interface ip address` silently fails on an op-down
#      interface.
#   3. Bind the default app-namespace to wan's sw_if_index so
#      vcl-rs apps (dnsd) can see the interface.

set -euo pipefail

VPPCTL="vppctl -s /run/vpp/cli.sock"

# Wait for VPP CLI.
for _ in $(seq 1 30); do
    if $VPPCTL show version 2>/dev/null | grep -q 'vpp v'; then break; fi
    sleep 1
done

# Wait for `wan` to show up.
for _ in $(seq 1 30); do
    if $VPPCTL show interface wan 2>/dev/null | grep -q '^wan '; then break; fi
    sleep 1
done

# Bring the interface up. promisc on is required for virtio-dpdk
# to register carrier-up (virtio PMD doesn't assert carrier on
# admin-up alone). Without promisc, ARP requests from the host are
# dropped as 'arp-disabled' and no L3 works.
$VPPCTL set interface promisc on wan
$VPPCTL set interface state wan up

# Assign IPs. Must be AFTER state-up + promisc-on, or addresses
# don't take effect.
$VPPCTL set interface ip address wan 10.99.0.2/24
$VPPCTL set interface ip address wan 2001:db8:99::2/64

# Default route → the host side of the test bridge. run-tests.sh
# enables IP forwarding + MASQUERADE on the host, so this lets
# dnsd's forwarder reach the real internet (1.1.1.1, etc.) via
# VPP → tap → br-dnsdtest → host's default NIC.
$VPPCTL ip route add 0.0.0.0/0 via 10.99.0.1

# Same for IPv6 — default via the host's v6 address on the bridge.
# run-tests.sh enables v6 forwarding + MASQUERADE through ip6tables
# nat, so dnsd's recursor can reach AAAA root servers over v6.
$VPPCTL ip route add ::/0 via 2001:db8:99::1

# App-namespace binding — vcl-rs apps in the default namespace
# can only see traffic on interfaces registered with the ns.
idx=$($VPPCTL show interface wan 2>/dev/null | awk '/^wan/ {print $2}')
if [ -z "$idx" ]; then
    echo "[-] wan didn't get a sw_if_index; VPP state is broken" >&2
    $VPPCTL show interface 2>&1 | head -20 >&2
    exit 1
fi
$VPPCTL app ns add id default secret 0 sw_if_index "$idx"
echo "[+] default app-namespace → wan (sw_if_index=$idx)"

# Visible summary for the systemd log.
$VPPCTL show app ns
$VPPCTL show interface address
