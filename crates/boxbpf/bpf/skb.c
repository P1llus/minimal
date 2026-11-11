/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/*
 * Packet hooks. They see every packet a box socket sends or receives, in any
 * network namespace, and identify the box by the socket's cgroup.
 *
 * Flows are admitted, not packets:
 *  - TCP: only a bare SYN is checked. Any other segment belongs to a
 *    connection whose SYN this side or the other side admitted.
 *  - UDP: a packet to or from a peer that the rules of the other direction
 *    admitted on this socket is a reply.
 *  - ICMP: an echo reply is a reply. A ping socket receives nothing else.
 */

struct pkt {
	__u32 saddr[4];
	__u32 daddr[4];
	__u16 sport;
	__u16 dport;
	__u8  family; /* 4 or 6 */
	__u8  l4;
	__u8  pbit;
	__u8  tcp_flags;
	__u8  icmp_type;
	__u8  later_frag;
};

#define TCP_SYN 0x02
#define TCP_ACK 0x10

#define ICMP_ECHOREPLY     0
#define ICMPV6_ECHO_REPLY  129

#define NEXTHDR_HOP      0
#define NEXTHDR_ROUTING  43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_DEST     60

static __always_inline int parse(struct __sk_buff *skb, struct pkt *p)
{
	__u8 l4hdr[14];
	__u32 off;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr ip;

		if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)))
			return -1;
		if (ip.ihl < 5)
			return -1;
		p->family = 4;
		p->l4 = ip.protocol;
		p->saddr[0] = ip.saddr;
		p->daddr[0] = ip.daddr;
		p->later_frag = (bpf_ntohs(ip.frag_off) & 0x1fff) != 0;
		off = ip.ihl * 4;
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6;
		__u8 nh;

		if (bpf_skb_load_bytes(skb, 0, &ip6, sizeof(ip6)))
			return -1;
		p->family = 6;
		__builtin_memcpy(p->saddr, ip6.saddr, 16);
		__builtin_memcpy(p->daddr, ip6.daddr, 16);
		nh = ip6.nexthdr;
		off = sizeof(ip6);
		/* Skip the extension headers a host stack emits. The kernel's
		 * own MLD reports carry a hop-by-hop header, for one. */
		for (int i = 0; i < 4; i++) {
			__u8 eh[8];

			if (nh != NEXTHDR_HOP && nh != NEXTHDR_ROUTING && nh != NEXTHDR_DEST &&
			    nh != NEXTHDR_FRAGMENT)
				break;
			if (bpf_skb_load_bytes(skb, off, eh, sizeof(eh)))
				return -1;
			if (nh == NEXTHDR_FRAGMENT) {
				if (((eh[2] << 8) | eh[3]) & 0xfff8)
					p->later_frag = 1;
				off += 8;
			} else {
				off += (eh[1] + 1) * 8;
			}
			nh = eh[0];
		}
		p->l4 = nh;
	} else {
		return -1;
	}

	p->pbit = proto_bit(p->l4);
	if (p->later_frag)
		return 0;
	if (p->l4 == IPPROTO_TCP) {
		if (bpf_skb_load_bytes(skb, off, l4hdr, 14))
			return -1;
		p->tcp_flags = l4hdr[13];
	} else if (p->l4 == IPPROTO_UDP) {
		if (bpf_skb_load_bytes(skb, off, l4hdr, 4))
			return -1;
	} else if (p->pbit == BP_P_ICMP) {
		if (bpf_skb_load_bytes(skb, off, l4hdr, 1))
			return -1;
		p->icmp_type = l4hdr[0];
		return 0;
	} else {
		return 0;
	}
	p->sport = (l4hdr[0] << 8) | l4hdr[1];
	p->dport = (l4hdr[2] << 8) | l4hdr[3];
	return 0;
}

static __always_inline void skb_event(struct __sk_buff *skb, __u64 box, __u8 hook,
				      const struct pkt *p, const struct verdict *v)
{
	struct ev_args a = {};

	a.box = box;
	a.cookie = bpf_get_socket_cookie(skb);
	a.rule = v->rule;
	a.l4proto = p->l4;
	a.sport = p->sport;
	a.dport = p->pbit == BP_P_ICMP ? p->icmp_type : p->dport;
	a.hook = hook;
	a.verdict = BP_DENY;
	a.reason = v->reason;
	a.family = p->family;
	__builtin_memcpy(a.saddr, p->saddr, 16);
	__builtin_memcpy(a.daddr, p->daddr, 16);
	emit_net(&a);
}

static __always_inline int drop(struct __sk_buff *skb, __u64 box, __u8 hook, const struct pkt *p,
				struct verdict *v, __u8 reason)
{
	struct bp_stats *s = stats_of(box);

	if (s) {
		if (hook == BP_H_EGRESS)
			s->tx_drop++;
		else
			s->rx_drop++;
	}
	if (reason) {
		v->reason = reason;
		v->rule = BP_NO_RULE;
	}
	skb_event(skb, box, hook, p, v);
	return 0;
}

static __always_inline struct sk_state *skb_state(struct __sk_buff *skb, int create)
{
	struct bpf_sock *sk = skb->sk;

	if (!sk)
		return NULL;
	sk = bpf_sk_fullsock(sk);
	if (!sk)
		return NULL;
	return bpf_sk_storage_get(&sk_state, sk, 0, create ? BPF_SK_STORAGE_GET_F_CREATE : 0);
}

static __always_inline int addr_eq(const __u32 *a, const __u32 *b)
{
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

#define ICMPV6_MLD_REPORT   131
#define ICMPV6_MLD_DONE     132
#define ICMPV6_ROUTER_SOL   133
#define ICMPV6_NEIGHBOUR_SOL 135
#define ICMPV6_MLD2_REPORT  143

/*
 * Sources a box with BP_F_CHECK_SRC may use: its own addresses and loopback.
 * A box can bind any link-local address (IPV6_FREEBIND needs no privilege),
 * so of those only its own passes. The unspecified IPv6 address passes for
 * what the kernel sends before the interface has an address: duplicate
 * address detection and the multicast reports that go with it.
 */
static __always_inline int src_ok(const struct bp_box_cfg *cfg, const struct pkt *p)
{
	__u32 own[4];

	if (p->family == 4)
		return (cfg->addr4 && p->saddr[0] == cfg->addr4) ||
		       (p->saddr[0] & bpf_htonl(0xff000000)) == bpf_htonl(0x7f000000);
	if (!(p->saddr[0] | p->saddr[1] | p->saddr[2])) {
		if (p->saddr[3] == bpf_htonl(1))
			return 1;
		if (!p->saddr[3])
			return p->pbit == BP_P_ICMP && !p->later_frag &&
			       (p->icmp_type == ICMPV6_MLD_REPORT ||
				p->icmp_type == ICMPV6_MLD_DONE ||
				p->icmp_type == ICMPV6_ROUTER_SOL ||
				p->icmp_type == ICMPV6_NEIGHBOUR_SOL ||
				p->icmp_type == ICMPV6_MLD2_REPORT);
	}
	/* Word compares: older clang turns a memcmp builtin into a call, which
	 * BPF does not have. An all-zero config address matches nothing here:
	 * the unspecified source was dealt with above. */
	__builtin_memcpy(own, cfg->addr6, 16);
	if (addr_eq(p->saddr, own))
		return 1;
	__builtin_memcpy(own, cfg->ll6, 16);
	return addr_eq(p->saddr, own);
}

static __always_inline int to_endpoint(const struct bp_endpoint *ep, const struct pkt *p)
{
	__u32 addr[4];

	if (p->family == 4)
		return ep->port4 && ep->port4 == p->dport && ep->addr4 == p->daddr[0];
	__builtin_memcpy(addr, ep->addr6, 16);
	return ep->port6 && ep->port6 == p->dport && addr_eq(addr, p->daddr);
}

/*
 * Tells the box's endpoints who their peer is. A flow of a box to one of its
 * own endpoints gets an entry under the box's end of it, whether a rule
 * redirected it there or the box dialled the endpoint itself. An endpoint
 * serves only peers that have one. The entry goes when the socket does
 * (bp_sock_release), so a later socket with the same address and port does
 * not inherit it.
 */
static __always_inline void record_flow(__u64 box, const struct bp_box_cfg *cfg,
					const struct pkt *p, struct sk_state *st)
{
	struct bp_endpoint_key ek = {};
	struct bp_flow_key fk = {};
	struct bp_flow_val fv = {};
	struct bp_endpoint *ep;
	__u32 i;

	ek.box_id = box;
	ek.generation = cfg->generation;
	for (i = 0; i < BP_ENDPOINTS_MAX; i++) {
		ek.idx = i;
		ep = bpf_map_lookup_elem(&endpoints, &ek);
		if (ep && to_endpoint(ep, p))
			break;
	}
	if (i == BP_ENDPOINTS_MAX)
		return;

	__builtin_memcpy(fk.saddr, p->saddr, 16);
	fk.sport = p->sport;
	fk.proto = p->pbit;
	fk.family = p->family;
	fv.box_id = box;
	fv.endpoint = i;
	fv.orig_family = p->family;
	if ((st->flags & ST_REWRITTEN) && st->to_port == bpf_htons(p->dport) &&
	    st->family == p->family && addr_eq(st->to, p->daddr)) {
		__builtin_memcpy(fv.orig_addr, st->orig, 16);
		fv.orig_port = bpf_ntohs(st->orig_port);
	} else {
		__builtin_memcpy(fv.orig_addr, p->daddr, 16);
		fv.orig_port = p->dport;
	}

	/* A socket has one local end at a time. If it moved, the old entry
	 * would outlive the socket. */
	if ((st->flags & ST_FLOW) &&
	    (st->flow_key.sport != fk.sport || st->flow_key.proto != fk.proto ||
	     st->flow_key.family != fk.family ||
	     !addr_eq((const __u32 *)st->flow_key.saddr, (const __u32 *)fk.saddr)))
		bpf_map_delete_elem(&flows, &st->flow_key);
	bpf_map_update_elem(&flows, &fk, &fv, BPF_ANY);
	st->flow_key = fk;
	st->flags |= ST_FLOW;
}

SEC("cgroup_skb/egress")
int bp_egress(struct __sk_buff *skb)
{
	__u64 box = skb_box(skb);
	struct bp_box_cfg *cfg = bpf_map_lookup_elem(&box_cfg, &box);
	struct verdict v = {};
	struct bp_stats *s;
	struct sk_state *st;
	struct pkt p = {};
	struct flow f = {};

	if (parse(skb, &p))
		return drop(skb, box, BP_H_EGRESS, &p, &v, BP_R_MALFORMED);
	if (!cfg)
		return drop(skb, box, BP_H_EGRESS, &p, &v, BP_R_NO_CFG);
	if ((cfg->flags & BP_F_CHECK_SRC) && !src_ok(cfg, &p))
		return drop(skb, box, BP_H_EGRESS, &p, &v, BP_R_SRC_ADDR);

	if (p.pbit == BP_P_TCP && (p.later_frag || (p.tcp_flags & (TCP_SYN | TCP_ACK)) != TCP_SYN))
		goto pass;

	f.box = box;
	f.dir = BP_DIR_EGRESS;
	f.family = p.family;
	f.pbit = p.pbit;
	f.port = p.pbit == BP_P_ICMP ? p.icmp_type : p.dport;
	__builtin_memcpy(f.addr, p.daddr, 16);

	/* A socket that keeps talking to the destination it was last allowed
	 * skips the lookups. A pin that expires does not cut an open flow, a
	 * rule change does, because userspace changes cfg->generation. Fragments
	 * after the first carry no ports and follow the first one. */
	st = skb_state(skb, 0);
	if (st && p.pbit && st->ok_pbit == p.pbit && st->ok_family == p.family &&
	    addr_eq(st->ok_addr, p.daddr) && st->ok_generation == cfg->generation &&
	    (p.later_frag || st->ok_port == f.port)) {
		/* The entry may have been evicted since the first packet. */
		if (st->flags & ST_FLOW)
			record_flow(box, cfg, &p, st);
		goto pass;
	}
	if (p.later_frag)
		return drop(skb, box, BP_H_EGRESS, &p, &v, BP_R_MALFORMED);

	decide(cfg, &f, &v);
	if (v.action == BP_REDIRECT) {
		/* Only a syscall hook can rewrite a destination. A packet
		 * still headed for the original one did not pass through it. */
		v.reason = BP_R_NOT_STEERED;
		v.action = BP_DENY;
	}
	if (v.action == BP_DENY) {
		if (p.pbit == BP_P_UDP) {
			struct udp_peer up;

			peer_key(&up, bpf_get_socket_cookie(skb), p.daddr, p.dport);
			if (peer_admitted(&up, BP_DIR_INGRESS, cfg->generation))
				goto pass;
		}
		return drop(skb, box, BP_H_EGRESS, &p, &v, 0);
	}

	st = skb_state(skb, 1);
	if (st) {
		st->ok_pbit = p.pbit;
		st->ok_family = p.family;
		__builtin_memcpy(st->ok_addr, p.daddr, 16);
		st->ok_port = f.port;
		st->ok_generation = cfg->generation;
		record_flow(box, cfg, &p, st);
	}
	if (p.pbit == BP_P_UDP) {
		struct udp_peer up;

		peer_key(&up, bpf_get_socket_cookie(skb), p.daddr, p.dport);
		peer_admit(&up, BP_DIR_EGRESS, cfg->generation);
	}

pass:
	s = stats_of(box);
	if (s) {
		s->tx_pkts++;
		s->tx_bytes += skb->len;
	}
	return 1;
}

SEC("cgroup_skb/ingress")
int bp_ingress(struct __sk_buff *skb)
{
	__u64 box = skb_box(skb);
	struct bp_box_cfg *cfg = bpf_map_lookup_elem(&box_cfg, &box);
	struct verdict v = {};
	struct bp_stats *s;
	struct udp_peer up;
	struct pkt p = {};
	struct flow f = {};

	if (parse(skb, &p))
		return drop(skb, box, BP_H_INGRESS, &p, &v, BP_R_MALFORMED);
	if (!cfg)
		return drop(skb, box, BP_H_INGRESS, &p, &v, BP_R_NO_CFG);

	if (p.later_frag)
		goto pass;
	if (p.pbit == BP_P_TCP && (p.tcp_flags & (TCP_SYN | TCP_ACK)) != TCP_SYN)
		goto pass;
	if (p.pbit == BP_P_ICMP &&
	    p.icmp_type == (p.family == 4 ? ICMP_ECHOREPLY : ICMPV6_ECHO_REPLY))
		goto pass;
	if (p.pbit == BP_P_UDP) {
		peer_key(&up, bpf_get_socket_cookie(skb), p.saddr, p.sport);
		if (peer_admitted(&up, BP_DIR_EGRESS, cfg->generation))
			goto pass;
	}

	f.box = box;
	f.dir = BP_DIR_INGRESS;
	f.family = p.family;
	f.pbit = p.pbit;
	f.port = p.pbit == BP_P_ICMP ? p.icmp_type : p.dport;
	__builtin_memcpy(f.addr, p.saddr, 16);
	decide(cfg, &f, &v);
	if (v.action != BP_ALLOW)
		return drop(skb, box, BP_H_INGRESS, &p, &v, 0);
	/* So the reply gets out, whatever the egress rules say. */
	if (p.pbit == BP_P_UDP)
		peer_admit(&up, BP_DIR_INGRESS, cfg->generation);

pass:
	s = stats_of(box);
	if (s) {
		s->rx_pkts++;
		s->rx_bytes += skb->len;
	}
	return 1;
}
