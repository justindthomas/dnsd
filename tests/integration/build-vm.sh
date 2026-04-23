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
cp "$ASSETS/cloud-init.yaml" "$TMPDIR/user-data"
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
genisoimage -quiet -output "$ASSETS_ISO" -volid DNSDASSETS \
    -joliet -rock \
    "$ASSETS/startup.conf" \
    "$ASSETS/vcl.conf" \
    "$ASSETS/commands.txt" \
    "$ASSETS/router.yaml" \
    "$ASSETS/configure-vpp.sh" \
    "$ASSETS/vpp-test.service" \
    "$ASSETS/dnsd.service"

# Extend cloud-init to mount that ISO and drop the files where the
# systemd units expect them. We do this by appending to the
# user-data before building the seed, so cloud-init drives the copy.
log "extending user-data with asset-install step"
# Rebuild user-data with the mount-and-install step appended to runcmd.
cat > "$TMPDIR/user-data.final" <<'EOF'
EOF
awk '1; END { print "" }' "$ASSETS/cloud-init.yaml" > "$TMPDIR/user-data.final"
cat >> "$TMPDIR/user-data.final" <<'EOF'
  - [mkdir, -p, /mnt/dnsd-assets, /etc/vpp, /etc/dnsd, /usr/local/bin]
  - [mount, -o, ro, -t, iso9660, LABEL=DNSDASSETS, /mnt/dnsd-assets]
  - [cp, /mnt/dnsd-assets/startup.conf, /etc/vpp/startup.conf]
  - [cp, /mnt/dnsd-assets/vcl.conf, /etc/vpp/vcl.conf]
  - [cp, /mnt/dnsd-assets/commands.txt, /etc/vpp/commands.txt]
  - [cp, /mnt/dnsd-assets/router.yaml, /etc/dnsd/router.yaml]
  - [install, -m, "755", /mnt/dnsd-assets/configure-vpp.sh, /usr/local/bin/configure-vpp.sh]
  - [cp, /mnt/dnsd-assets/vpp-test.service, /etc/systemd/system/vpp-test.service]
  - [cp, /mnt/dnsd-assets/dnsd.service, /etc/systemd/system/dnsd.service]
  - [systemctl, daemon-reload]
  - [touch, /var/lib/dnsd-test-vm.assets-installed]
EOF
cloud-localds "$SEED" "$TMPDIR/user-data.final" "$TMPDIR/meta-data"

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
