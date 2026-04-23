#!/bin/bash
#
# Run the dnsd integration tests.
#
# Flow:
#   1. Ensure golden qcow2 exists (runs build-vm.sh if not).
#   2. Create a bridge + TAP for the VPP-owned NIC.
#   3. Clone the golden qcow2 → test disk (ephemeral).
#   4. Launch the VM with two NICs:
#        - user-net on 2290/tcp → SSH
#        - TAP on br-dnsdtest → VPP's wan interface
#   5. Wait for dnsd to come up (ssh probe).
#   6. Run pytest against the VM.
#   7. Teardown (unless --no-teardown).
#
# Flags:
#   --rebuild          Force rebuild of the golden image.
#   --no-teardown      Leave the VM + bridge running for manual poking.
#   --dnsd-binary X    SCP a fresh dnsd into the VM before testing.
#   -k PATTERN         Forward to pytest.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DNSD_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORK="${DNSD_TEST_WORK:-$SCRIPT_DIR/.work}"
GOLDEN="${DNSD_TEST_GOLDEN:-$WORK/dnsd-test-golden.qcow2}"
SSH_KEY="$WORK/ssh-key"
TEST_DISK="$WORK/dnsd-test-run.qcow2"
SERIAL_LOG="$WORK/run-serial.log"
PIDFILE="$WORK/run.pid"

BRIDGE="${DNSD_TEST_BRIDGE:-br-dnsdtest}"
TAP="${DNSD_TEST_TAP:-tap-dnsdtest}"
NET="${DNSD_TEST_NET:-10.99.0}"
HOST_IP="${DNSD_TEST_HOST_IP:-${NET}.1}"
VM_IP="${DNSD_TEST_VM_IP:-${NET}.2}"

# 2290 collides with an unrelated FreeBSD VM on the current build
# host; 2293 is outside every slim-suite range we've seen
# (ospfd 2240-2242, bgpd 2250-2251, dhcpd 2260-2261, dnsd-slim
# 2270-2271) and leaves 2291-2292 free for future nearby suites.
SSH_PORT="${DNSD_TEST_SSH_PORT:-2293}"
VNC_DISPLAY="${DNSD_TEST_VNC:-53}"

REBUILD=false
TEARDOWN=true
DNSD_BINARY=""
PYTEST_K=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --rebuild)        REBUILD=true; shift ;;
        --no-teardown)    TEARDOWN=false; shift ;;
        --dnsd-binary)    DNSD_BINARY="$2"; shift 2 ;;
        -k)               PYTEST_K="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0"
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

log()  { echo "[run-tests] $*"; }

mkdir -p "$WORK"

# 1. Golden.
if [ ! -f "$GOLDEN" ] || [ "$REBUILD" = true ]; then
    log "building golden image..."
    BUILD_ARGS=()
    [ "$REBUILD" = true ] && BUILD_ARGS+=(--rebuild)
    "$SCRIPT_DIR/build-vm.sh" "${BUILD_ARGS[@]}"
fi

# 2. Bridge + TAP.
if ! ip link show "$BRIDGE" &>/dev/null; then
    log "creating bridge $BRIDGE + tap $TAP"
    sudo ip link add "$BRIDGE" type bridge
    sudo ip link set "$BRIDGE" up
fi
sudo ip addr add "$HOST_IP/24" dev "$BRIDGE" 2>/dev/null || true

if ! ip link show "$TAP" &>/dev/null; then
    sudo ip tuntap add "$TAP" mode tap
    sudo ip link set "$TAP" up
    sudo ip link set "$TAP" master "$BRIDGE"
fi

# 3. Clone golden.
rm -f "$TEST_DISK"
qemu-img create -f qcow2 -b "$GOLDEN" -F qcow2 "$TEST_DISK"

# 4. Launch.
QEMU="${QEMU:-qemu-system-x86_64}"
QEMU_ACCEL=""
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    QEMU_ACCEL="-enable-kvm -cpu host"
fi

teardown() {
    if [ "$TEARDOWN" = false ]; then
        log "leaving VM running (--no-teardown)"
        return
    fi
    if [ -f "$PIDFILE" ]; then
        kill -TERM "$(cat "$PIDFILE")" 2>/dev/null || true
        rm -f "$PIDFILE"
    fi
    sudo ip link del "$TAP" 2>/dev/null || true
    sudo ip addr del "$HOST_IP/24" dev "$BRIDGE" 2>/dev/null || true
    sudo ip link del "$BRIDGE" 2>/dev/null || true
}
trap teardown EXIT

log "booting test VM"
rm -f "$SERIAL_LOG"
MAC="$(echo -n "$TAP" | md5sum | sed 's/^\(..\)\(..\)\(..\)\(..\).*$/52:54:\1:\2:\3:\4/')"
# shellcheck disable=SC2086
$QEMU $QEMU_ACCEL \
    -name dnsd-test-run \
    -m 4096 -smp 2 \
    -drive "file=$TEST_DISK,format=qcow2,if=virtio" \
    -netdev "user,id=user0,hostfwd=tcp::${SSH_PORT}-:22" \
    -device virtio-net-pci,netdev=user0,mac=52:54:00:dd:00:02 \
    -netdev "tap,id=tap0,ifname=${TAP},script=no,downscript=no" \
    -device "virtio-net-pci,netdev=tap0,mac=$MAC" \
    -vnc ":${VNC_DISPLAY}" \
    -serial file:"$SERIAL_LOG" \
    -monitor none \
    -daemonize \
    -pidfile "$PIDFILE"

# 5. Wait for dnsd to come up (control socket at /run/dnsd.sock
# inside the VM — dnsd-query talks to it).
log "waiting for SSH..."
for i in $(seq 1 60); do
    if ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o IdentitiesOnly=yes -o LogLevel=ERROR -o ConnectTimeout=3 \
        -p "$SSH_PORT" root@localhost 'true' 2>/dev/null; then
        log "  SSH ready"
        break
    fi
    sleep 2
done

# 5b. Auto-locate a bookworm-compatible dnsd binary if the caller
# didn't pass --dnsd-binary. Search: explicit flag > env var >
# build/.work > build-bookworm.sh output.
if [ -z "$DNSD_BINARY" ] && [ -n "${DNSD_TEST_BINARY:-}" ]; then
    DNSD_BINARY="$DNSD_TEST_BINARY"
fi
if [ -z "$DNSD_BINARY" ] && [ -f "$WORK/dnsd-bookworm" ]; then
    DNSD_BINARY="$WORK/dnsd-bookworm"
fi
if [ -z "$DNSD_BINARY" ]; then
    log "no dnsd binary supplied; building one via build-bookworm.sh"
    "$SCRIPT_DIR/build-bookworm.sh"
    DNSD_BINARY="$WORK/dnsd-bookworm"
fi

if [ ! -f "$DNSD_BINARY" ]; then
    log "[-] dnsd binary not found at $DNSD_BINARY"
    exit 1
fi
log "side-loading dnsd + dnsd-query from $DNSD_BINARY"
SSHX="ssh -i $SSH_KEY -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -p $SSH_PORT root@localhost"
SCPX="scp -i $SSH_KEY -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -P $SSH_PORT"
$SCPX "$DNSD_BINARY" root@localhost:/tmp/dnsd-new
if [ -f "$WORK/dnsd-query-bookworm" ]; then
    $SCPX "$WORK/dnsd-query-bookworm" root@localhost:/tmp/dnsd-query-new
fi
$SSHX <<'REMOTE'
set -e
install -m 755 /tmp/dnsd-new /usr/local/bin/dnsd
if [ -f /tmp/dnsd-query-new ]; then
    install -m 755 /tmp/dnsd-query-new /usr/local/bin/dnsd-query
fi
rm -f /tmp/dnsd-new /tmp/dnsd-query-new
systemctl restart dnsd.service
REMOTE

log "waiting for dnsd listener readiness (up to 60s)..."
for i in $(seq 1 60); do
    if $SSHX 'dnsd-query stats 2>/dev/null | grep -q queries_udp' 2>/dev/null; then
        log "  dnsd ready"
        break
    fi
    sleep 1
done

# 6. Pytest.
export DNSD_TEST_SSH_PORT="$SSH_PORT"
export DNSD_TEST_VM_IP="$VM_IP"
export DNSD_TEST_HOST_IP="$HOST_IP"
export DNSD_TEST_SSH_KEY="$SSH_KEY"

PYTEST_ARGS=("$SCRIPT_DIR/pytests")
[ -n "$PYTEST_K" ] && PYTEST_ARGS+=(-k "$PYTEST_K")

log "running pytest..."
cd "$SCRIPT_DIR"
python3 -m pytest "${PYTEST_ARGS[@]}" -v
