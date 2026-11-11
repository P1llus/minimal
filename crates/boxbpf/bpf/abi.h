/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/*
 * Map and event layouts shared with userspace.
 *
 * netpol::abi declares the same structs in Rust. The build generates
 * abi_check.h from that module and compiles it with this file, so the two
 * sides cannot drift apart unnoticed. Change BP_ABI_VERSION with any change
 * of layout or meaning.
 *
 * Byte order: addresses are stored as they sit in a packet. An IPv4 address
 * in a 16-byte field takes the first four bytes, the rest is zero. Ports
 * are host order everywhere in this file.
 */
#ifndef BOXBPF_ABI_H
#define BOXBPF_ABI_H

#define BP_ABI_VERSION 3

/* Directions. They index bp_box_cfg.default_action and are part of rule keys. */
#define BP_DIR_EGRESS  0 /* address = destination, port = destination port */
#define BP_DIR_INGRESS 1 /* address = source, port = local port */
#define BP_DIR_BIND    2 /* address = local address, port = local port */
#define BP_DIR_COUNT   3

/* Protocol bits. BP_P_ICMP is ICMP in IPv4 rules and ICMPv6 in IPv6 rules. */
#define BP_P_TCP   1
#define BP_P_UDP   2
#define BP_P_ICMP  4

#define BP_DENY     0
#define BP_ALLOW    1
#define BP_REDIRECT 2 /* egress only: rewrite the destination to an endpoint */

/* bp_box_cfg.flags */
#define BP_F_CHECK_SRC (1u << 0) /* egress source must be addr4 or addr6 */
#define BP_F_LOG_FLOWS (1u << 1) /* event for each allowed connect and send */
#define BP_F_HAS_SETS  (1u << 2) /* the box has name-set rules: look up pins */

/*
 * Keyed by box id: the cgroup id of the box cgroup.
 *
 * `generation` is part of the key of every rule, set and endpoint entry of
 * the box. Userspace writes a new policy under a new generation beside the
 * old one, and the write of this struct switches from one to the other. A
 * program reads the struct once and so sees one policy, never a mix. The
 * generation also ends the verdicts sockets have cached.
 */
struct bp_box_cfg {
	__u32 flags;
	__u32 generation;
	__u8  default_action[BP_DIR_COUNT];
	__u8  _pad;
	__u16 refuse_errno; /* for a refused system call; 0 means EPERM */
	__u16 _pad2;
	__u32 addr4;
	__u8  addr6[16];
};

#define BP_RULES_MAX 32
#define BP_NO_RULE   0xffff

struct bp_rule {
	__u16 prio;       /* position in the box's list; the lowest match wins */
	__u8  proto_mask;
	__u8  action;
	__u16 port_lo;    /* TCP and UDP: port. ICMP: message type. */
	__u16 port_hi;
	__u8  endpoint;   /* BP_REDIRECT: index of the box's endpoint */
	__u8  _pad[3];
};

/*
 * The rules of one prefix or one name set, sorted by prio. A longest-prefix
 * lookup returns one entry only, so userspace copies the rules of covering
 * prefixes into each entry.
 */
struct bp_rules {
	__u16 count; /* rules in use, from r[0] */
	__u16 _pad;
	struct bp_rule r[BP_RULES_MAX];
};

/*
 * LPM keys. Box id, generation and direction take the first 128 bits, so
 * prefixlen is 128 + the address prefix length. Byte arrays keep the
 * structs free of padding, which an LPM key must not have.
 */
#define BP_RULE_KEY_BASE 128

struct bp_rule4_key {
	__u32 prefixlen;
	__u8  box_id[8];     /* native-endian u64 */
	__u8  generation[4]; /* native-endian u32 */
	__u8  dir;
	__u8  _zero[3];
	__u8  addr[4];
};

struct bp_rule6_key {
	__u32 prefixlen;
	__u8  box_id[8];
	__u8  generation[4];
	__u8  dir;
	__u8  _zero[3];
	__u8  addr[16];
};

/* An address the resolver answered for a name, and the set of that name. */
struct bp_pin_key {
	__u64 box_id;
	__u8  addr[16];
	__u8  family; /* 4 or 6 */
	__u8  _pad[7];
};

/* A set id is a hash of the name pattern, the same under every generation.
 * A pin of a set the box's current generation has no entry for admits
 * nothing. */
struct bp_pin_val {
	__u64 expiry_ns; /* boot-time clock; ignored once it has passed */
	__u64 set_id;
};

struct bp_set_key {
	__u64 box_id;
	__u64 set_id;
	__u32 generation;
	__u8  dir;
	__u8  _pad[3];
};

struct bp_endpoint_key {
	__u64 box_id;
	__u32 generation;
	__u8  idx;
	__u8  _pad[3];
};

/* Endpoint indexes of a box are below this. */
#define BP_ENDPOINTS_MAX 4

/* Where a redirect sends a flow. It never changes the flow's family. */
struct bp_endpoint {
	__u8  addr6[16];
	__u32 addr4;
	__u16 port4; /* 0: no IPv4 address */
	__u16 port6; /* 0: no IPv6 address */
};

/* Per-CPU. Userspace creates the entry with the box. */
struct bp_stats {
	__u64 tx_pkts;
	__u64 tx_bytes;
	__u64 rx_pkts;
	__u64 rx_bytes;
	__u64 tx_drop;
	__u64 rx_drop;
	__u64 refused; /* refusals at a system call */
	__u64 ev_lost; /* events lost to a full ring buffer */
};

/* The box's end of a flow to one of its endpoints, as the endpoint sees its
 * peer. The value says which box and where the flow was first headed: the
 * endpoint itself, or the destination a redirect rule took it from. */
struct bp_flow_key {
	__u8  saddr[16];
	__u16 sport;
	__u8  proto;  /* one BP_P_* bit */
	__u8  family;
};

struct bp_flow_val {
	__u64 box_id;
	__u8  orig_addr[16];
	__u16 orig_port;
	__u8  orig_family;
	__u8  endpoint;
	__u32 _pad;
};

/*
 * Every record of the event ring buffer starts with this. A reader skips a
 * kind it does not know by `size` and reads at most what it knows of a kind
 * that has grown: fields are only ever appended.
 */
struct bp_ev_hdr {
	__u16 kind;
	__u16 size;  /* whole record, header included */
	__u32 cpu;
	__u64 ts_ns; /* boot-time clock */
	__u64 box_id;
};

/* Record kinds. */
#define BP_EV_NET 1

/* bp_ev_net.hook */
#define BP_H_SOCK_CREATE 1
#define BP_H_CONNECT4    2
#define BP_H_CONNECT6    3
#define BP_H_SENDMSG4    4
#define BP_H_SENDMSG6    5
#define BP_H_BIND4       6
#define BP_H_BIND6       7
#define BP_H_EGRESS      8
#define BP_H_INGRESS     9

/* bp_ev_net.reason */
#define BP_R_NO_CFG      1 /* the cgroup has no bp_box_cfg entry */
#define BP_R_RULE        2 /* a rule of a prefix decided */
#define BP_R_SET_RULE    3 /* a rule of a name set decided */
#define BP_R_DEFAULT     4 /* no rule matched */
#define BP_R_SRC_ADDR    5
#define BP_R_SOCK_TYPE   6
#define BP_R_MALFORMED   7
#define BP_R_NOT_STEERED 8 /* packet to a redirect destination no system-call hook rewrote */
#define BP_R_NO_ENDPOINT 9 /* redirect without an endpoint address of the flow's family */
#define BP_R_NO_MEMORY   10 /* no memory to remember which box a new socket belongs to */

struct bp_ev_net {
	struct bp_ev_hdr hdr;
	__u8  hook;
	__u8  verdict;   /* BP_DENY, BP_ALLOW or BP_REDIRECT */
	__u8  reason;
	__u8  family;    /* 4 or 6: of the addresses below */
	__u16 l4proto;   /* IPPROTO_*; for sock_create the protocol asked for */
	__u16 sock_type; /* SOCK_*; 0 in the packet hooks */
	__u16 sport;
	__u16 dport;     /* for ICMP the message type */
	__u32 pid;       /* 0 in the packet hooks */
	__u32 rule;      /* prio of the deciding rule, BP_NO_RULE if none */
	__u8  saddr[16];
	__u8  daddr[16];
	__u32 _pad;
	__u64 cookie;    /* socket cookie */
};

#endif /* BOXBPF_ABI_H */
