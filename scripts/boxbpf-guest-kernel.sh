#!/usr/bin/env bash
# Runs the box policy engine against a guest kernel.
#
# Builds `crates/boxbpf/examples/guest_selftest.rs` as a static musl binary,
# packs it as /init of an initramfs with nothing else in it, and boots the
# kernel in QEMU. As PID 1 the program loads and attaches the engine the way
# the guest daemon does, then compares kernel verdicts with the evaluator.
# It prints PASS/FAIL lines and powers off.
#
# Usage: scripts/boxbpf-guest-kernel.sh [BZIMAGE | floor]
#   BZIMAGE defaults to .scratch/vmlinuz, where `just guest-kernel` and
#   `just kernel` put the guest kernel.
#   `floor` runs the oldest kernel the engine supports, 5.19: Ubuntu's
#   generic 5.19.0-50 image, fetched once into .scratch/ (12 MB, needs curl
#   and dpkg-deb) and checked against the digest below.
#
# Needs: clang, the x86_64-unknown-linux-musl Rust target, cpio, gzip,
# qemu-system-x86_64 and /dev/kvm.
#
# Exit code: 0 when every check passed, 1 otherwise.
set -euo pipefail

cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
kernel="${1:-.scratch/vmlinuz}"
target=x86_64-unknown-linux-musl

floor_release=5.19.0-50
floor_deb="http://archive.ubuntu.com/ubuntu/pool/main/l/linux-hwe-5.19/linux-image-unsigned-${floor_release}-generic_${floor_release}.50_amd64.deb"
floor_sha256=b225ba82fa3c297c22e23808506a986dd464b2d32b14d9bb1629a38e7a3b144f

if [ "$kernel" = floor ]; then
    kernel=".scratch/vmlinuz-floor-$floor_release"
    if [ ! -f "$kernel" ]; then
        for tool in curl dpkg-deb sha256sum; do
            command -v "$tool" >/dev/null || { echo "$tool is not installed (needed to fetch the 5.19 kernel)" >&2; exit 1; }
        done
        fetched="$(mktemp -d)"
        curl -sSfL -o "$fetched/image.deb" "$floor_deb"
        echo "$floor_sha256  $fetched/image.deb" | sha256sum -c --quiet
        mkdir -p .scratch
        dpkg-deb --fsys-tarfile "$fetched/image.deb" \
            | tar -xO "./boot/vmlinuz-$floor_release-generic" > "$kernel.part"
        mv "$kernel.part" "$kernel"
        rm -rf "$fetched"
    fi
fi

[ -f "$kernel" ] || { echo "no kernel at $kernel: pass a bzImage, or run \`just guest-kernel\`" >&2; exit 1; }
for tool in qemu-system-x86_64 cpio gzip; do
    command -v "$tool" >/dev/null || { echo "$tool is not installed" >&2; exit 1; }
done
[ -w /dev/kvm ] || { echo "/dev/kvm is not usable by this user" >&2; exit 1; }

cargo build -p boxbpf --example guest_selftest --target "$target" --locked
bin="${CARGO_TARGET_DIR:-target}/$target/debug/examples/guest_selftest"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root"/{proc,sys,dev}
cp "$bin" "$work/root/init"
(cd "$work/root" && find . | cpio -o -H newc --quiet | gzip -1) > "$work/initramfs.gz"

timeout 120 qemu-system-x86_64 -enable-kvm -cpu host -m 512 -nographic -no-reboot \
    -kernel "$kernel" -initrd "$work/initramfs.gz" \
    -append "console=ttyS0 quiet panic=-1 rdinit=/init" > "$work/console.log" 2>&1 || true

# The first line the program prints follows the firmware's on the same line.
tr -d '\r' < "$work/console.log" | grep -aoE '(PASS|FAIL|INFO|RESULT) guest.*' || true
if tr -d '\r' < "$work/console.log" | grep -aq '^RESULT guest pass'; then
    exit 0
fi
echo "the guest self-test did not pass; last console lines:" >&2
tail -n 20 "$work/console.log" >&2
exit 1
