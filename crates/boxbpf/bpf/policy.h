/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/* Maps, events, counters and the rule evaluation every hook shares. */
#ifndef BOXBPF_POLICY_H
#define BOXBPF_POLICY_H

#include "kernel.h"
#include "helpers.h"
#include "abi.h"
#include "abi_check.h"
#include "box_id.h"

/* max_entries are defaults. The loader can set each one before load. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct bp_box_cfg);
} box_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct bp_rule4_key);
	__type(value, struct bp_rules);
} rules4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct bp_rule6_key);
	__type(value, struct bp_rules);
} rules6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct bp_pin_key);
	__type(value, struct bp_pin_val);
} pins SEC(".maps");

/* Written from userspace only, so nothing is gained by allocating every
 * entry up front. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct bp_set_key);
	__type(value, struct bp_rules);
} set_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct bp_endpoint_key);
	__type(value, struct bp_endpoint);
} endpoints SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct bp_stats);
} stats SEC(".maps");

/* Bounded per box by flows_per_box, so no box can fill it for the others. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct bp_flow_key);
	__type(value, struct bp_flow_val);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct bp_usage);
} box_use SEC(".maps");

/* Set at load. */
const volatile __u32 flows_per_box = 1024;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} events SEC(".maps");

/* Per-socket state. Not part of the ABI: userspace never reads it. */
#define ST_REWRITTEN 1
#define ST_FLOW      2 /* flow_key names an entry of the flows map */

struct sk_state {
	/* A destination the connect/sendmsg hook rewrote. recvmsg and
	 * getpeername use it to show the application what it asked for.
	 * Addresses are in flow form: IPv4 in the first word, also when the
	 * socket is AF_INET6 and the application wrote a v4-mapped address. */
	__u32 orig[4];
	__u32 to[4];
	__u16 orig_port; /* network order, as the hooks see it */
	__u16 to_port;   /* network order */
	__u8  flags;
	__u8  family;    /* of orig and to: a redirect never changes family */
	__u8  endpoint;
	/* The last destination the egress hook allowed. */
	__u8  ok_pbit;
	__u32 ok_addr[4];
	__u16 ok_port;
	__u8  ok_family;
	__u8  _pad;
	__u32 ok_generation;
	/* The entry this socket has in the flows map, removed with the socket. */
	struct bp_flow_key flow_key;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct sk_state);
} sk_state SEC(".maps");

/*
 * UDP has no SYN, so each socket remembers the peers it was allowed to talk
 * to and in which direction the rules allowed it. A packet the rules would
 * deny still passes when the other direction admitted that peer on this
 * socket: it is a reply. A rule change (cfg->generation) forgets all of it.
 *
 * The state is the socket's own, so no box can push another box's peers
 * out. A socket remembers its last UDP_PEERS peers. One that talks to more
 * at the same time loses the reply exemption for the oldest, and their
 * replies are judged by the rules alone.
 */
#define UDP_PEERS 64 /* a power of two */

struct udp_peer {
	__u32 addr[4];
	__u16 port;
	__u8  family;
	__u8  dirs; /* 1 << BP_DIR_EGRESS, 1 << BP_DIR_INGRESS; 0: free */
};

struct udp_state {
	__u32 generation;
	__u32 next; /* the slot the next new peer takes */
	struct udp_peer peer[UDP_PEERS];
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct udp_state);
} udp_state SEC(".maps");

/*
 * Events of one box are limited by a token bucket, so a box that provokes
 * refusals as fast as it can fills neither the ring buffer nor the reader's
 * time, and the events of other boxes get through. What the bucket turns
 * away is counted in bp_stats.ev_limited.
 *
 * Two CPUs may update a bucket at once and lose one of the updates. The
 * limit is then off by an event, which does not matter.
 */
#define EV_BURST     256
#define EV_REFILL_NS 15625000ULL /* 64 events a second */

struct ev_bucket {
	__u64 last_ns; /* when the last token was earned */
	__u32 tokens;
	__u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct ev_bucket);
} ev_buckets SEC(".maps");

static __always_inline __u8 proto_bit(__u32 l4)
{
	switch (l4) {
	case IPPROTO_TCP:
		return BP_P_TCP;
	case IPPROTO_UDP:
		return BP_P_UDP;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		return BP_P_ICMP;
	}
	return 0;
}

static __always_inline struct bp_stats *stats_of(__u64 box)
{
	return bpf_map_lookup_elem(&stats, &box);
}

/* What is being decided. One shape for every hook and both families. */
struct flow {
	__u64 box;
	__u32 addr[4]; /* the remote address; for bind the local one */
	__u16 port;    /* see BP_DIR_*; for ICMP the message type */
	__u8  pbit;
	__u8  family;  /* 4 or 6. A v4-mapped IPv6 address is family 4. */
	__u8  dir;
};

struct verdict {
	__u16 rule; /* prio of the deciding rule, BP_NO_RULE if none */
	__u8  action;
	__u8  reason;
	__u8  endpoint;
};

struct ev_args {
	__u64 box;
	__u64 cookie;
	__u32 pid;
	__u32 rule;
	__u16 l4proto;
	__u16 sock_type;
	__u16 sport;
	__u16 dport;
	__u8  hook;
	__u8  verdict;
	__u8  reason;
	__u8  family;
	__u32 saddr[4];
	__u32 daddr[4];
};

/* Takes a token of the box's bucket. 0 when there is none. */
static __always_inline int ev_admit(__u64 box, __u64 now)
{
	struct ev_bucket fresh = { .last_ns = now, .tokens = EV_BURST - 1 };
	struct ev_bucket *b = bpf_map_lookup_elem(&ev_buckets, &box);
	__u64 earned = 0;
	__u32 tokens;

	if (!b) {
		bpf_map_update_elem(&ev_buckets, &box, &fresh, BPF_ANY);
		return 1;
	}
	tokens = b->tokens;
	if (now > b->last_ns)
		earned = (now - b->last_ns) / EV_REFILL_NS;
	if (earned) {
		tokens = earned >= EV_BURST || tokens + earned >= EV_BURST ? EV_BURST : tokens + earned;
		b->last_ns += earned * EV_REFILL_NS;
	}
	if (!tokens)
		return 0;
	b->tokens = tokens - 1;
	return 1;
}

static __always_inline void emit_net(const struct ev_args *a)
{
	__u64 now = bpf_ktime_get_boot_ns();
	struct bp_stats *s;
	struct bp_ev_net *e;

	if (!ev_admit(a->box, now)) {
		s = stats_of(a->box);
		if (s)
			s->ev_limited++;
		return;
	}
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		s = stats_of(a->box);
		if (s)
			s->ev_lost++;
		return;
	}
	e->hdr.kind = BP_EV_NET;
	e->hdr.size = sizeof(*e);
	e->hdr.cpu = bpf_get_smp_processor_id();
	e->hdr.ts_ns = now;
	e->hdr.box_id = a->box;
	e->hook = a->hook;
	e->verdict = a->verdict;
	e->reason = a->reason;
	e->family = a->family;
	e->l4proto = a->l4proto;
	e->sock_type = a->sock_type;
	e->sport = a->sport;
	e->dport = a->dport;
	e->pid = a->pid;
	e->rule = a->rule;
	__builtin_memcpy(e->saddr, a->saddr, 16);
	__builtin_memcpy(e->daddr, a->daddr, 16);
	e->_pad = 0;
	e->cookie = a->cookie;
	bpf_ringbuf_submit(e, 0);
}

/* The first rule of a sorted list that matches, if it beats what we have. */
static __always_inline void scan(const struct bp_rules *rs, const struct flow *f, __u8 reason,
				 struct verdict *v)
{
	__u32 count = rs->count;

	for (__u32 i = 0; i < BP_RULES_MAX; i++) {
		const struct bp_rule *r = &rs->r[i];

		if (i >= count || r->prio >= v->rule)
			return;
		if ((r->proto_mask & f->pbit) && f->port >= r->port_lo && f->port <= r->port_hi) {
			v->rule = r->prio;
			v->action = r->action;
			v->endpoint = r->endpoint;
			v->reason = reason;
			return;
		}
	}
}

/*
 * The whole policy: the rules of the longest matching prefix, the rules of
 * the name set the address is pinned to, lowest prio wins, else the default
 * of the direction.
 */
static __always_inline void decide(const struct bp_box_cfg *cfg, const struct flow *f,
				   struct verdict *v)
{
	const struct bp_rules *rs;
	__u32 generation = cfg->generation;

	v->rule = BP_NO_RULE;
	v->endpoint = 0;

	if (f->family == 4) {
		struct bp_rule4_key k = {};

		k.prefixlen = BP_RULE_KEY_BASE + 32;
		__builtin_memcpy(k.box_id, &f->box, 8);
		__builtin_memcpy(k.generation, &generation, 4);
		k.dir = f->dir;
		__builtin_memcpy(k.addr, f->addr, 4);
		rs = bpf_map_lookup_elem(&rules4, &k);
	} else {
		struct bp_rule6_key k = {};

		k.prefixlen = BP_RULE_KEY_BASE + 128;
		__builtin_memcpy(k.box_id, &f->box, 8);
		__builtin_memcpy(k.generation, &generation, 4);
		k.dir = f->dir;
		__builtin_memcpy(k.addr, f->addr, 16);
		rs = bpf_map_lookup_elem(&rules6, &k);
	}
	if (rs)
		scan(rs, f, BP_R_RULE, v);

	if (cfg->flags & BP_F_HAS_SETS) {
		struct bp_pin_key pk = {};
		struct bp_pin_val *pin;

		pk.box_id = f->box;
		__builtin_memcpy(pk.addr, f->addr, 16);
		pk.family = f->family;
		pin = bpf_map_lookup_elem(&pins, &pk);
		if (pin && pin->expiry_ns > bpf_ktime_get_boot_ns()) {
			struct bp_set_key sk = {};

			sk.box_id = f->box;
			sk.set_id = pin->set_id;
			sk.generation = generation;
			sk.dir = f->dir;
			rs = bpf_map_lookup_elem(&set_rules, &sk);
			if (rs)
				scan(rs, f, BP_R_SET_RULE, v);
		}
	}

	if (v->rule == BP_NO_RULE) {
		v->reason = BP_R_DEFAULT;
		v->action = f->dir < BP_DIR_COUNT && cfg->default_action[f->dir] == BP_ALLOW ?
				    BP_ALLOW : BP_DENY;
	}
}

static __always_inline int peer_is(const struct udp_peer *e, const __u32 *addr, __u16 port,
				   __u8 family)
{
	return e->dirs && e->port == port && e->family == family && e->addr[0] == addr[0] &&
	       e->addr[1] == addr[1] && e->addr[2] == addr[2] && e->addr[3] == addr[3];
}

/* Did the rules of direction `dir` admit this peer on this socket since the
 * last rule change? `sk` is a full socket or NULL. */
static __always_inline int peer_admitted(void *sk, const __u32 *addr, __u16 port, __u8 family,
					 __u8 dir, __u32 generation)
{
	struct udp_state *us;

	if (!sk)
		return 0;
	us = bpf_sk_storage_get(&udp_state, sk, 0, 0);
	if (!us || us->generation != generation)
		return 0;
	for (__u32 i = 0; i < UDP_PEERS; i++) {
		const struct udp_peer *e = &us->peer[i];

		if ((e->dirs & (1 << dir)) && peer_is(e, addr, port, family))
			return 1;
	}
	return 0;
}

static __always_inline void peer_admit(void *sk, const __u32 *addr, __u16 port, __u8 family,
				       __u8 dir, __u32 generation)
{
	struct udp_state *us;
	struct udp_peer *e;
	__u32 slot;

	if (!sk)
		return;
	us = bpf_sk_storage_get(&udp_state, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (!us)
		return;
	if (us->generation != generation) {
		for (__u32 i = 0; i < UDP_PEERS; i++)
			us->peer[i].dirs = 0;
		us->next = 0;
		us->generation = generation;
	}
	for (__u32 i = 0; i < UDP_PEERS; i++) {
		e = &us->peer[i];
		if (peer_is(e, addr, port, family)) {
			e->dirs |= 1 << dir;
			return;
		}
	}
	slot = us->next & (UDP_PEERS - 1);
	e = &us->peer[slot];
	__builtin_memcpy(e->addr, addr, 16);
	e->port = port;
	e->family = family;
	e->dirs = 1 << dir;
	us->next = slot + 1;
}

#endif /* BOXBPF_POLICY_H */
