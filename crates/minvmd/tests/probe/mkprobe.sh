#!/bin/bash
# mkprobe.sh <out.cpio>: builds the probe guest's initramfs from this host's
# binaries and the shared libraries they need.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=$1
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root"/{bin,usr/bin,etc,proc,sys,dev,tmp,run,www}
for b in bash ip bridge socat curl cat sleep mount mkdir; do
  p=$(type -P "$b") || { echo "mkprobe: this host has no $b" >&2; exit 3; }
  p=$(readlink -f "$p")
  cp -L "$p" "$root/usr/bin/$b"
  for l in $(ldd "$p" 2>/dev/null | grep -o '/[^ ]*' | sort -u); do
    mkdir -p "$root$(dirname "$l")"
    [ -e "$root$l" ] || cp -L "$l" "$root$l"
  done
done
busybox=$(type -P busybox) || { echo "mkprobe: this host has no busybox" >&2; exit 3; }
ldd "$busybox" >/dev/null 2>&1 && { echo "mkprobe: busybox must be static (busybox-static)" >&2; exit 3; }
cp -L "$busybox" "$root/bin/busybox"
ln -s ../usr/bin/bash "$root/bin/bash"
ln -s ../usr/bin/bash "$root/bin/sh"
# Name lookups in curl need the resolver's plugins, which ldd does not list.
for l in libnss_files.so.2 libnss_dns.so.2 libresolv.so.2; do
  p=$(find /usr/lib /lib -name "$l" 2>/dev/null | head -1)
  [ -n "$p" ] && { mkdir -p "$root$(dirname "$p")"; cp -L "$p" "$root$p"; }
done
echo 'root:x:0:0:root:/:/bin/bash' > "$root/etc/passwd"
echo 'hosts: files dns' > "$root/etc/nsswitch.conf"
echo '127.0.0.1 localhost' > "$root/etc/hosts"
: > "$root/etc/resolv.conf"
cp "$here/init" "$root/init"
chmod +x "$root/init"
( cd "$root" && find . | cpio -o -H newc --quiet ) > "$out"
