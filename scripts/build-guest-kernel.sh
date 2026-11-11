#!/usr/bin/env bash
# Build the guest kernel locally, with BTF, instead of fetching the prebuilt
# (scripts/fetch-prebuilt.sh kernel). The config is the pkgs `virtio-linux`
# recipe plus the BPF tracing options below. The output is what libkrun
# loads: a bzImage on x86_64, a raw Image on aarch64.
#
# Usage: scripts/build-guest-kernel.sh <dest> [workdir]
#   workdir: holds the tarball, the source tree and copies of .config,
#            System.map and the unstripped vmlinux (default .scratch/guest-kernel)
# Env:   JOBS overrides the make parallelism (default nproc).
set -euo pipefail

DEST="${1:?usage: build-guest-kernel.sh <dest> [workdir]}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${2:-$ROOT/.scratch/guest-kernel}"

VERSION=6.12.114
SHA256=7a8589912bd7a8adb07fed074283652cf482a35facef8954554654f0154b4af3
URL="https://cdn.kernel.org/pub/linux/kernel/v${VERSION%%.*}.x/linux-$VERSION.tar.xz"
JOBS="${JOBS:-$(nproc)}"

[ "$(uname -s)" = Linux ] || { echo "build-guest-kernel: needs a Linux host" >&2; exit 1; }
for tool in curl make gcc bison flex bc perl pahole; do
  command -v "$tool" >/dev/null 2>&1 || { echo "'$tool' not found" >&2; exit 1; }
done

case "$(uname -m)" in
  x86_64)  TARGET=bzImage; ARTIFACT=arch/x86/boot/bzImage ;;
  aarch64) TARGET=Image;   ARTIFACT=arch/arm64/boot/Image ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

mkdir -p "$WORK"
DEST="$(cd "$(dirname "$DEST")" && pwd)/$(basename "$DEST")"
WORK="$(cd "$WORK" && pwd)"
TARBALL="$WORK/linux-$VERSION.tar.xz"
SRC="$WORK/linux-$VERSION"

if ! echo "$SHA256  $TARBALL" | sha256sum -c --status 2>/dev/null; then
  curl -fL --max-time 600 "$URL" -o "$TARBALL.part"
  echo "$SHA256  $TARBALL.part" | sha256sum -c --status || {
    echo "sha256 mismatch for $URL" >&2; rm -f "$TARBALL.part"; exit 1; }
  mv "$TARBALL.part" "$TARBALL"
  rm -rf "$SRC"
fi
if [ ! -f "$SRC/Makefile" ]; then
  rm -rf "$SRC.tmp" && mkdir "$SRC.tmp"
  tar -xJf "$TARBALL" -C "$SRC.tmp"
  mv "$SRC.tmp/linux-$VERSION" "$SRC" && rmdir "$SRC.tmp"
fi
cd "$SRC"

# Fixed build stamp, so two builds from the same tree match. The version
# counter (#N) otherwise goes up on every relink of a reused tree.
export KBUILD_BUILD_TIMESTAMP="@${SOURCE_DATE_EPOCH:-0}"
export KBUILD_BUILD_USER=builder
export KBUILD_BUILD_HOST=minimal
export KBUILD_BUILD_VERSION=1

# `pahole -j` writes BTF types in thread completion order, so the image
# differs between builds. Run it single-threaded through a wrapper.
PAHOLE_REAL="$(command -v pahole)"
cat > "$WORK/pahole-serial" <<EOF
#!/bin/sh
for a; do shift; [ "\$a" = -j ] || set -- "\$@" "\$a"; done
exec "$PAHOLE_REAL" "\$@"
EOF
chmod +x "$WORK/pahole-serial"
# Kconfig records the host rustc version in .config, and IKCONFIG puts .config
# in the image. Rust is off, so hide rustc: whether it is installed should not
# change the image.
MAKE_ARGS=(PAHOLE="$WORK/pahole-serial" RUSTC=rustc-not-used)
# With debug info on, the source path ends up in the vDSO build ID, which is
# in the image. Map it away so the work dir does not change the output.
export KCFLAGS="-ffile-prefix-map=$SRC=." KAFLAGS="-ffile-prefix-map=$SRC=."

make "${MAKE_ARGS[@]}" defconfig
[ "$TARGET" = bzImage ] && make "${MAKE_ARGS[@]}" kvm_guest.config

CFG="scripts/config --file .config"
REQUIRED=()
FORBIDDEN=()
# kconfig drops a symbol it cannot satisfy without an error, so every option
# set through want/nope is checked against the final .config below.
want() { local s; for s in "$@"; do $CFG --enable "$s"; REQUIRED+=("$s"); done; }
nope() { local s; for s in "$@"; do $CFG --disable "$s"; FORBIDDEN+=("$s"); done; }

# Modules stay on so tristates can sit at =m (never built: only $TARGET is).
# MODULES=n would promote them to =y.
$CFG --enable MODULES
# Signing generates a new key per build, which breaks reproducibility.
$CFG --disable MODULE_SIG

# virtio guest drivers
want VIRTIO VIRTIO_PCI VIRTIO_MMIO VIRTIO_MMIO_CMDLINE_DEVICES
want VIRTIO_BLK VIRTIO_NET VIRTIO_CONSOLE VIRTIO_BALLOON VIRTIO_INPUT
want VIRTIO_IOMMU
want HW_RANDOM HW_RANDOM_VIRTIO
$CFG --enable VIRTIO_PCI_LEGACY
want SCSI_VIRTIO NET_FAILOVER
nope DRM_I915 DRM_VIRTIO_GPU DRM
want MEMORY_HOTPLUG MEMORY_HOTREMOVE VIRTIO_MEM
want ZONE_DEVICE LIBNVDIMM VIRTIO_PMEM DAX FS_DAX
want VSOCKETS VIRTIO_VSOCKETS
# Without a loopback transport a guest process cannot reach the guest
# daemon's vsock listener; only the host can.
nope VSOCKETS_LOOPBACK
want FUSE_FS VIRTIO_FS FUSE_DAX FUSE_PASSTHROUGH
want NET_9P NET_9P_VIRTIO 9P_FS
want IP_PNP IP_PNP_DHCP

# namespaces and cgroups
want NAMESPACES UTS_NS IPC_NS PID_NS NET_NS USER_NS TIME_NS
want CGROUPS MEMCG CPUSETS CGROUP_PIDS CGROUP_FREEZER CGROUP_DEVICE
want CGROUP_CPUACCT CGROUP_SCHED BLK_CGROUP CGROUP_HUGETLB CGROUP_MISC
want CGROUP_PERF CGROUP_BPF CGROUP_NET_PRIO CGROUP_NET_CLASSID NET_CLS_CGROUP
want PSI TASKSTATS TASK_DELAY_ACCT TASK_IO_ACCOUNTING

# /proc and process introspection
want PROC_CHILDREN PROC_PAGE_MONITOR PROC_KCORE CHECKPOINT_RESTORE USERFAULTFD

# syscalls container runtimes expect
want SECCOMP SECCOMP_FILTER
want SYSVIPC SYSVIPC_SYSCTL POSIX_MQUEUE POSIX_MQUEUE_SYSCTL UNIX98_PTYS
want EPOLL SIGNALFD TIMERFD EVENTFD AIO IO_URING FUTEX
want BINFMT_ELF BINFMT_SCRIPT BINFMT_MISC
want HUGETLBFS TRANSPARENT_HUGEPAGE

# BPF. BPF_EVENTS needs KPROBE_EVENTS or UPROBE_EVENTS, which sit under FTRACE.
want BPF_SYSCALL BPF_JIT CGROUP_BPF PERF_EVENTS KPROBES
want FTRACE KPROBE_EVENTS UPROBE_EVENTS BPF_EVENTS

# BTF for CO-RE programs, generated by pahole from DWARF. pahole needs the
# DWARF, so DEBUG_INFO goes on; it ends up in vmlinux, not in the image.
$CFG --disable DEBUG_INFO_NONE --disable DEBUG_INFO_REDUCED --disable DEBUG_INFO_SPLIT
want DEBUG_INFO DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT DEBUG_INFO_BTF
# fentry/fexit trampolines and kprobe_multi links.
want FUNCTION_TRACER DYNAMIC_FTRACE DYNAMIC_FTRACE_WITH_DIRECT_CALLS FPROBE
want BPF_STREAM_PARSER
# The running config at /proc/config.gz.
want IKCONFIG IKCONFIG_PROC

# container networking
want VETH TUN WIREGUARD MACVLAN IPVLAN DUMMY BRIDGE BRIDGE_NETFILTER
want VLAN_8021Q IPV6
want NETFILTER NETFILTER_ADVANCED NETFILTER_XTABLES
want NF_CONNTRACK NF_NAT NF_NAT_MASQUERADE
want NF_TABLES NF_TABLES_INET NF_TABLES_IPV4 NF_TABLES_IPV6
want NFT_CT NFT_NAT NFT_MASQ NFT_COMPAT NFT_LIMIT NFT_LOG
want NFT_REJECT NFT_REJECT_IPV4 NFT_REJECT_IPV6 NFT_FIB_IPV4 NFT_FIB_IPV6
# The guest minimald's `inet minimal_class` table: `socket cgroupv2`, `ct mark`
# and `reject with icmpx`.
want NFT_SOCKET NF_SOCKET_IPV4 NF_SOCKET_IPV6 SOCK_CGROUP_DATA NFT_REJECT_INET
want NF_CONNTRACK_MARK
want IP_NF_IPTABLES IP_NF_IPTABLES_LEGACY IP_NF_FILTER IP_NF_NAT IP_NF_MANGLE
want IP_NF_TARGET_MASQUERADE IP_NF_TARGET_REJECT IP_NF_TARGET_REDIRECT
want IP6_NF_IPTABLES IP6_NF_IPTABLES_LEGACY IP6_NF_FILTER IP6_NF_NAT
want IP6_NF_MANGLE IP6_NF_TARGET_MASQUERADE IP6_NF_TARGET_REJECT
want NETFILTER_XT_NAT NETFILTER_XT_MARK NETFILTER_XT_MATCH_ADDRTYPE
want NETFILTER_XT_MATCH_CONNTRACK NETFILTER_XT_MATCH_MULTIPORT
want NETFILTER_XT_MATCH_COMMENT NETFILTER_XT_MATCH_STATE
want NETFILTER_XT_TARGET_MASQUERADE NETFILTER_XT_TARGET_REDIRECT
want NETFILTER_XT_TARGET_LOG NF_LOG_SYSLOG NF_LOG_IPV4 NF_LOG_IPV6 NF_LOG_ARP
want INET_DIAG INET_TCP_DIAG INET_UDP_DIAG UNIX_DIAG NETLINK_DIAG PACKET_DIAG
# IFB depends on NET_ACT_MIRRED.
want NET_SCH_INGRESS NET_SCH_FQ_CODEL NET_CLS_BPF NET_ACT_BPF
want NET_ACT_MIRRED IFB

# block devices and filesystems
want BLK_DEV_LOOP BLK_DEV_DM DM_SNAPSHOT DM_THIN_PROVISIONING DM_CRYPT
want BLK_DEV_INITRD RD_GZIP RD_XZ RD_ZSTD
want EXT4_FS EXT4_FS_POSIX_ACL EXT4_FS_SECURITY
want SQUASHFS SQUASHFS_XZ SQUASHFS_ZSTD EROFS_FS EROFS_FS_ZIP
want ISO9660_FS VFAT_FS NLS_CODEPAGE_437 NLS_ISO8859_1 NLS_UTF8 NLS_ASCII
want AUTOFS_FS
want TMPFS TMPFS_POSIX_ACL TMPFS_XATTR TMPFS_INODE64
want PROC_FS SYSFS DEVTMPFS DEVTMPFS_MOUNT
want OVERLAY_FS OVERLAY_FS_REDIRECT_DIR OVERLAY_FS_INDEX
want OVERLAY_FS_XINO_AUTO OVERLAY_FS_METACOPY
want FANOTIFY FANOTIFY_ACCESS_PERMISSIONS

# LSMs. No SECURITY_LOCKDOWN_LSM: it selects MODULE_SIG. LSM must name only
# LSMs that are built in.
want SECURITY SECURITY_NETWORK SECURITY_LANDLOCK SECURITY_YAMA BPF_LSM
$CFG --set-str LSM "landlock,yama,bpf"

# Nested KVM. Arch-specific symbols, so not asserted.
$CFG --enable VIRTUALIZATION --enable KVM --enable KVM_INTEL --enable KVM_AMD

# defconfig hardware a virtio guest cannot reach
nope CFG80211 MAC80211 RFKILL
nope ETHERNET
nope NFS_FS ROOT_NFS SUNRPC
nope USB_SUPPORT
nope INTEL_IOMMU AMD_IOMMU
nope PCCARD YENTA AGP HOTPLUG_PCI
nope MACINTOSH_DRIVERS NVRAM WATCHDOG DMADEVICES
nope BLK_DEV_MD
nope HIBERNATION
nope KEXEC CRASH_DUMP
nope QUOTA
nope I2C HPET

make "${MAKE_ARGS[@]}" olddefconfig

missing=()
for sym in "${REQUIRED[@]}"; do
  grep -qx "CONFIG_${sym}=y" .config || missing+=("CONFIG_${sym}")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "error: required options not =y after olddefconfig (renamed, unmet dependency, or =m):" >&2
  printf '  %s\n' "${missing[@]}" >&2
  exit 1
fi
resurrected=()
for sym in "${FORBIDDEN[@]}"; do
  if grep -qx "CONFIG_${sym}=y" .config; then resurrected+=("CONFIG_${sym}"); fi
done
if [ "${#resurrected[@]}" -gt 0 ]; then
  echo "error: disabled options came back =y after olddefconfig (something selects them):" >&2
  printf '  %s\n' "${resurrected[@]}" >&2
  exit 1
fi

make "${MAKE_ARGS[@]}" -j"$JOBS" "$TARGET"

cp .config "$WORK/config"
cp System.map "$WORK/System.map"
cp vmlinux "$WORK/vmlinux"
mkdir -p "$(dirname "$DEST")"
cp "$ARTIFACT" "$DEST.tmp" && mv "$DEST.tmp" "$DEST"
echo "build-guest-kernel: $DEST ($(stat -c %s "$DEST") bytes); config, System.map, vmlinux in $WORK"
