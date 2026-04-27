#!/bin/bash
#
# Compile dnsd + dnsd-query in a Debian-bookworm podman container.
# Needed because the test VM runs Bookworm (glibc 2.36)
# while most build hosts run Trixie/Sid/macOS — a Rust binary built
# on Trixie won't run on Bookworm.
#
# Produces:
#   tests/integration/.work/dnsd-bookworm
#   tests/integration/.work/dnsd-query-bookworm

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DNSD_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORK="${DNSD_TEST_WORK:-$SCRIPT_DIR/.work}"
mkdir -p "$WORK"

# If a sibling vcl-rs checkout exists, prefer mounting it into the
# container over cloning fresh from GitHub — lets local vcl-rs changes
# flow through to the build without needing to push first. Override
# with DNSD_VCL_RS_PATH if it lives somewhere else.
VCL_RS_LOCAL="${DNSD_VCL_RS_PATH:-$DNSD_ROOT/../vcl-rs}"
if [ -d "$VCL_RS_LOCAL" ] && [ -f "$VCL_RS_LOCAL/Cargo.toml" ]; then
    VCL_RS_MOUNT=( -v "$VCL_RS_LOCAL:/vcl-rs-src:ro" )
    USE_LOCAL_VCL=1
else
    VCL_RS_MOUNT=()
    USE_LOCAL_VCL=0
fi

# Same pattern for vpp-api — dnsd uses it for VPP interface
# enumeration (auto-detecting the v6 source IP for upstream queries).
VPP_API_LOCAL="${DNSD_VPP_API_PATH:-$DNSD_ROOT/../vpp-api}"
if [ -d "$VPP_API_LOCAL" ] && [ -f "$VPP_API_LOCAL/Cargo.toml" ]; then
    VPP_API_MOUNT=( -v "$VPP_API_LOCAL:/vpp-api-src:ro" )
    USE_LOCAL_VPP_API=1
else
    VPP_API_MOUNT=()
    USE_LOCAL_VPP_API=0
fi

log() { echo "[build-bookworm] $*"; }

if ! command -v podman &>/dev/null; then
    echo "[-] podman not found — install it or use --dnsd-binary <path> to supply a prebuilt Bookworm binary" >&2
    exit 1
fi

CONTAINER_CMD="podman"
if ! podman info &>/dev/null 2>&1; then
    CONTAINER_CMD="sudo podman"
fi

# Mount the dnsd repo read-only, the work dir read-write. cargo
# target dir lives inside the container to avoid polluting the host's
# target/ (which may have incompatible cached artefacts from a
# non-bookworm rustc toolchain).
log "compiling dnsd in bookworm container..."
$CONTAINER_CMD run --rm \
    -v "$DNSD_ROOT:/src:ro" \
    -v "$WORK:/out" \
    "${VCL_RS_MOUNT[@]}" \
    "${VPP_API_MOUNT[@]}" \
    -e USE_LOCAL_VCL="$USE_LOCAL_VCL" \
    -e USE_LOCAL_VPP_API="$USE_LOCAL_VPP_API" \
    -w /root \
    debian:bookworm bash -c '
        set -euo pipefail
        apt-get update -qq
        apt-get install -y -qq curl build-essential pkg-config libssl-dev ca-certificates gnupg git

        # Rust via rustup.
        curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
        # shellcheck disable=SC1091
        source ~/.cargo/env

        # Install VPP 25.10 libraries so libvppcom is available at
        # link time. We dont actually run VPP in the container; we
        # just need the .so for cargo to link against.
        curl -fsSL https://packagecloud.io/fdio/release/gpgkey | gpg --dearmor -o /usr/share/keyrings/fdio-release.gpg
        echo "deb [signed-by=/usr/share/keyrings/fdio-release.gpg] https://packagecloud.io/fdio/release/debian bookworm main" \
            > /etc/apt/sources.list.d/fdio-release.list
        cat > /etc/apt/preferences.d/vpp <<EOF
Package: vpp* libvppinfra*
Pin: version 25.10*
Pin-Priority: 1000
EOF
        apt-get update -qq
        mkdir -p /tmp/vpp-debs /tmp/vpp-extract
        cd /tmp/vpp-debs
        apt-get download libvppinfra=25.10-release vpp=25.10-release 2>/dev/null \
            || apt-get download libvppinfra vpp 2>/dev/null \
            || true
        for deb in *.deb; do [ -f "$deb" ] && dpkg-deb -x "$deb" /tmp/vpp-extract; done
        for lib in libvppcom libvppinfra libsvm libvlibmemory; do
            cp /tmp/vpp-extract/usr/lib/x86_64-linux-gnu/${lib}*.so.* /usr/lib/x86_64-linux-gnu/ 2>/dev/null || true
        done
        for v in /usr/lib/x86_64-linux-gnu/libvppcom.so.* /usr/lib/x86_64-linux-gnu/libvppinfra.so.* \
                 /usr/lib/x86_64-linux-gnu/libsvm.so.*    /usr/lib/x86_64-linux-gnu/libvlibmemoryclient.so.*; do
            [ -f "$v" ] && ln -sf "$v" "${v%%.*}.so"
        done
        ldconfig 2>/dev/null || true

        # dnsd has [patch] entries pointing vcl-rs and vpp-api at
        # ../vcl-rs and ../vpp-api respectively, so clones (or bind-
        # mounted copies) must sit next to /root/dnsd-src at
        # /root/vcl-rs and /root/vpp-api. Prefer host checkouts when
        # mounted — lets local changes flow through without pushing.
        if [ "$USE_LOCAL_VCL" = "1" ]; then
            cp -r /vcl-rs-src /root/vcl-rs
        else
            git clone --quiet --depth 1 https://github.com/justindthomas/vcl-rs.git /root/vcl-rs
        fi
        if [ "$USE_LOCAL_VPP_API" = "1" ]; then
            cp -r /vpp-api-src /root/vpp-api
        else
            git clone --quiet --depth 1 https://github.com/justindthomas/vpp-api.git /root/vpp-api
        fi

        cp -r /src /root/dnsd-src
        export CARGO_TARGET_DIR=/root/cargo-target
        cd /root/dnsd-src
        cargo build --release --quiet --bin dnsd --bin dnsd-query

        cp "$CARGO_TARGET_DIR/release/dnsd"       /out/dnsd-bookworm
        cp "$CARGO_TARGET_DIR/release/dnsd-query" /out/dnsd-query-bookworm
        chmod +x /out/dnsd-bookworm /out/dnsd-query-bookworm
    '

log "built: $WORK/dnsd-bookworm"
log "built: $WORK/dnsd-query-bookworm"
file "$WORK/dnsd-bookworm" 2>/dev/null | head -1
