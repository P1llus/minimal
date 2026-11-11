#!/usr/bin/env bash
# Runs the box policy engine against a guest kernel.
#
# Builds `crates/boxbpf/examples/guest_selftest.rs` as a static musl binary,
# packs it as /init of an initramfs with nothing else in it, and boots the
# kernel in QEMU. As PID 1 the program loads and attaches the engine the way
# the guest daemon does, then compares kernel verdicts with the evaluator.
# It prints PASS/FAIL lines and powers off.
#
# Usage: scripts/boxbpf-guest-kernel.sh [BZIMAGE]
#   BZIMAGE defaults to .scratch/vmlinuz, where `just guest-kernel` and
#   `just kernel` put the guest kernel.
#
# Needs: clang, the x86_64-unknown-linux-musl Rust target, cpio, gzip,
# qemu-system-x86_64 and /dev/kvm.
#
# Exit code: 0 when every check passed, 1 otherwise.
set -euo pipefail

cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
kernel="${1:-.scratch/vmlinuz}"
target=x86_64-unknown-linux-musl

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

tr -d '\r' < "$work/console.log" | grep -E '^(PASS|FAIL|INFO|RESULT) ' || true
if tr -d '\r' < "$work/console.log" | grep -q '^RESULT guest pass'; then
    exit 0
fi
echo "the guest self-test did not pass; last console lines:" >&2
tail -n 20 "$work/console.log" >&2
exit 1
