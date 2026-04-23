#!/bin/bash
#
# Build the dnsd integration test golden image.
#
# First-run flow:
#   1. Clone Debian-12 cloud qcow2 → dnsd-test-golden.qcow2
#   2. Seed with cloud-init (user-data + meta-data + our vm-assets)
#   3. First-boot runs cloud-init which installs VPP + dnsd + configs
#   4. After setup completes, shut down the VM
#   5. Golden image is ready for run-tests.sh to clone
#
# Re-run reuses the existing golden unless --rebuild is passed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DNSD_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ASSETS="$SCRIPT_DIR/vm-assets"

# Where we keep artefacts. Keep them inside the dnsd repo under
# tests/integration/ so nothing bleeds into the user's ~ unless they
# override.
WORK="${DNSD_TEST_WORK:-$SCRIPT_DIR/.work}"
GOLDEN="${DNSD_TEST_GOLDEN:-$WORK/dnsd-test-golden.qcow2}"
BASE_IMAGE="${DNSD_BASE_IMAGE:-/var/lib/images/debian-12-generic-amd64.qcow2}"

REBUILD=false
for arg in "$@"; do
    case $arg in
        --rebuild) REBUILD=true ;;
        -h|--help)
            sed -n '2,/^$/p' "$0"
            exit 0
            ;;
    esac
done

log() { echo "[build-vm] $*"; }

mkdir -p "$WORK"

if [ -f "$GOLDEN" ] && [ "$REBUILD" != true ]; then
    log "golden already present at $GOLDEN (pass --rebuild to rebuild)"
    exit 0
fi

if [ ! -f "$BASE_IMAGE" ]; then
    echo "[-] base image not found: $BASE_IMAGE" >&2
    echo "    set DNSD_BASE_IMAGE to a Debian-12 cloud qcow2" >&2
    exit 1
fi

# Generate an ephemeral SSH keypair for test access. Lives alongside
# the golden image — both run-tests.sh and interactive ssh use it.
SSH_KEY="$WORK/ssh-key"
if [ ! -f "$SSH_KEY" ]; then
    log "generating test SSH keypair → $SSH_KEY"
    ssh-keygen -t ed25519 -N '' -f "$SSH_KEY" -q -C "dnsd-test"
fi
SSH_PUBKEY="$(cat "$SSH_KEY.pub")"

# Pre-fetch fd.io's GPG key on the build host. curl-during-cloud-init
# has been flaky enough to waste two build cycles; bake the key in so
# the VM's apt just works.
FDIO_KEY="$WORK/fdio-release.gpg"
if [ ! -s "$FDIO_KEY" ]; then
    log "fetching fd.io GPG key"
    curl -fsSL https://packagecloud.io/fdio/release/gpgkey | gpg --dearmor -o "$FDIO_KEY"
fi

rm -f "$GOLDEN"
log "cloning base → $GOLDEN"
qemu-img create -f qcow2 -b "$BASE_IMAGE" -F qcow2 "$GOLDEN" 20G

# Build the cloud-init seed ISO. cloud-localds combines
# user-data + meta-data into a NoCloud-format ISO that cloud-init
# auto-discovers when attached as a second disk.
log "building cloud-init seed"
SEED="$WORK/seed.iso"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
# Substitute our SSH pubkey into the template before cloud-localds
# bakes it into the seed.
sed "s|__SSH_PUBKEY__|${SSH_PUBKEY}|g" "$ASSETS/cloud-init.yaml" > "$TMPDIR/user-data"
cat > "$TMPDIR/meta-data" <<EOF
instance-id: dnsd-test-vm
local-hostname: dnsd-test-vm
EOF
cloud-localds "$SEED" "$TMPDIR/user-data" "$TMPDIR/meta-data"

# Build an extra config ISO that drops our dnsd-specific files into
# the guest at /mnt/dnsd-assets. cloud-init's user-data runcmd
# copies them to their final paths.
log "bundling vm-assets into config ISO"
ASSETS_ISO="$WORK/assets.iso"
# Stage all the files (including the pre-fetched fd.io gpg key) in
# one directory so genisoimage can snapshot them with stable names.
STAGE="$TMPDIR/assets"
mkdir -p "$STAGE"
cp "$ASSETS/startup.conf"        "$STAGE/"
cp "$ASSETS/vcl.conf"            "$STAGE/"
cp "$ASSETS/commands.txt"        "$STAGE/"
cp "$ASSETS/router.yaml"         "$STAGE/"
cp "$ASSETS/configure-vpp.sh"    "$STAGE/"
cp "$ASSETS/vpp-test.service"    "$STAGE/"
cp "$ASSETS/dnsd.service"        "$STAGE/"
cp "$FDIO_KEY"                   "$STAGE/fdio-release.gpg"
genisoimage -quiet -output "$ASSETS_ISO" -volid DNSDASSETS \
    -joliet -rock "$STAGE"/

# cloud-init.yaml already contains the asset-install runcmd in
# the right order (mount ISO → copy → enable). No post-processing
# needed.

# Boot the VM so cloud-init can do its thing. No KVM accel assumed
# since the build host's kvm group membership may not be in this
# shell's sg context — callers can set QEMU=$(sg kvm -c 'qemu-system...
# if they need speed.
QEMU="${QEMU:-qemu-system-x86_64}"
QEMU_ACCEL=""
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    QEMU_ACCEL="-enable-kvm -cpu host"
else
    log "kvm not accessible in this shell — booting without accel (slower)"
    QEMU_ACCEL="-cpu qemu64"
fi

BUILD_SERIAL="$WORK/build-serial.log"
rm -f "$BUILD_SERIAL"

log "booting build VM (cloud-init; ~5-10 min first time)"
set -x
$QEMU $QEMU_ACCEL \
    -name dnsd-test-build \
    -m 2048 -smp 2 \
    -drive "file=$GOLDEN,format=qcow2,if=virtio" \
    -drive "file=$SEED,format=raw,if=virtio,readonly=on" \
    -drive "file=$ASSETS_ISO,format=raw,media=cdrom,readonly=on" \
    -netdev user,id=user0,hostfwd=tcp::2289-:22 \
    -device virtio-net-pci,netdev=user0,mac=52:54:00:dd:00:01 \
    -nographic \
    -serial file:"$BUILD_SERIAL" \
    -monitor none &
QEMU_PID=$!
set +x

# Wait for SSH to come up (signals that cloud-init has at least set
# up ssh + root password). Then wait for /var/lib/dnsd-test-vm.assets-installed.
log "waiting for SSH + cloud-init to finish (PID=$QEMU_PID)"
for i in $(seq 1 120); do
    if sshpass -p dnsd ssh \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o ConnectTimeout=3 \
        -p 2289 root@localhost \
        'test -f /var/lib/dnsd-test-vm.assets-installed && test -f /var/lib/dnsd-test-vm.setup-done' 2>/dev/null; then
        log "setup complete after ${i}x5s poll"
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "[-] build VM died before setup completed" >&2
        tail -40 "$BUILD_SERIAL" >&2
        exit 1
    fi
    sleep 5
done

log "shutting down build VM"
sshpass -p dnsd ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -p 2289 root@localhost \
    'systemctl poweroff' 2>/dev/null || true
wait "$QEMU_PID" 2>/dev/null || true

log "golden image ready: $GOLDEN"
