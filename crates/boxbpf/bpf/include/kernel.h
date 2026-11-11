/* SPDX-License-Identifier: (GPL-2.0-only WITH Linux-syscall-note) OR MIT */
/*
 * The kernel UAPI the programs use, and nothing else: context structs,
 * packet headers, a few enum values. All of it is stable ABI, so the
 * programs need no type information from the running kernel.
 */
#ifndef BOXBPF_KERNEL_H
#define BOXBPF_KERNEL_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef __u16 __be16;
typedef __u32 __be32;

#define __bpf_md_ptr(type, name) \
	union { type name; __u64 :64; } __attribute__((aligned(8)))

enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_RINGBUF = 27,
};

#define BPF_ANY                     0
#define BPF_F_NO_PREALLOC           1
#define BPF_SK_STORAGE_GET_F_CREATE 1

#define AF_INET        2
#define AF_INET6       10
#define SOCK_STREAM    1
#define SOCK_DGRAM     2
#define IPPROTO_ICMP   1
#define IPPROTO_TCP    6
#define IPPROTO_UDP    17
#define IPPROTO_ICMPV6 58
#define ETH_P_IP       0x0800
#define ETH_P_IPV6     0x86DD
#define EPERM          1
#define NULL           ((void *)0)

struct bpf_flow_keys;

struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
	__u32 src_ip4;
	__u32 src_ip6[4];
	__u32 src_port;
	__be16 dst_port;
	__u16 :16;
	__u32 dst_ip4;
	__u32 dst_ip6[4];
	__u32 state;
	__s32 rx_queue_mapping;
};

struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;     /* network order */
	__u32 user_ip6[4];  /* network order */
	__u32 user_port;    /* network order */
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 msg_src_ip4;
	__u32 msg_src_ip6[4];
	__bpf_md_ptr(struct bpf_sock *, sk);
};

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	__bpf_md_ptr(struct bpf_flow_keys *, flow_keys);
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__bpf_md_ptr(struct bpf_sock *, sk);
	__u32 gso_size;
	__u8  tstamp_type;
	__u32 :24;
	__u64 hwtstamp;
};

/* Both targets of the BPF backend we build for are little-endian hosts. */
struct iphdr {
	__u8  ihl:4, version:4;
	__u8  tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8  ttl;
	__u8  protocol;
	__u16 check;
	__be32 saddr;
	__be32 daddr;
};

struct ipv6hdr {
	__u8  priority:4, version:4;
	__u8  flow_lbl[3];
	__be16 payload_len;
	__u8  nexthdr;
	__u8  hop_limit;
	__u8  saddr[16];
	__u8  daddr[16];
};

#endif /* BOXBPF_KERNEL_H */
