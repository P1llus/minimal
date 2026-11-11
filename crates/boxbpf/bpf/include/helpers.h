/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/*
 * Section and map macros, byte order, and the kernel helpers the programs
 * call. A helper is called through a pointer whose value is its number in
 * the kernel's helper table (enum bpf_func_id).
 */
#ifndef BOXBPF_HELPERS_H
#define BOXBPF_HELPERS_H

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "the programs are written for little-endian targets"
#endif
#define bpf_htons(x) ((__u16)__builtin_bswap16((__u16)(x)))
#define bpf_ntohs(x) bpf_htons(x)
#define bpf_htonl(x) ((__u32)__builtin_bswap32((__u32)(x)))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static __u32 (*bpf_get_smp_processor_id)(void) = (void *)8;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *)46;
static __u64 (*bpf_skb_ancestor_cgroup_id)(struct __sk_buff *skb, int ancestor_level) = (void *)83;
static struct bpf_sock *(*bpf_sk_fullsock)(struct bpf_sock *sk) = (void *)95;
static void *(*bpf_sk_storage_get)(void *map, void *sk, void *value, __u64 flags) = (void *)107;
static __u64 (*bpf_get_current_ancestor_cgroup_id)(int ancestor_level) = (void *)123;
static __u64 (*bpf_ktime_get_boot_ns)(void) = (void *)125;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static int (*bpf_set_retval)(int retval) = (void *)187;

#endif /* BOXBPF_HELPERS_H */
