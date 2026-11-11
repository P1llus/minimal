/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/*
 * Syscall-time hooks: sock_create, connect, sendmsg, recvmsg, getpeername, bind.
 *
 * They give the application an errno at once, and they are the only place a
 * destination can be rewritten. The packet hooks in skb.c stay authoritative.
 * The caller may be any task that holds the socket: the box is the socket's.
 *
 * `sf` is the socket's family, a compile-time constant in every caller: the
 * verifier rejects a read of user_ip6 in an IPv4 hook and the other way round.
 */

#define ICMP_ECHO        8
#define ICMPV6_ECHO_REQ  128

static __always_inline int refuse(__u64 box, __u16 err)
{
	struct bp_stats *s = stats_of(box);

	if (s)
		s->refused++;
	bpf_set_retval(-(int)(err ? err : EPERM));
	return 0;
}

static __always_inline int is_v4_mapped(const struct bpf_sock_addr *ctx)
{
	return ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 &&
	       ctx->user_ip6[2] == bpf_htonl(0xffff);
}

/*
 * The sockaddr as a flow: family 4 or 6 and the address in flow form. An
 * AF_INET6 socket with a v4-mapped address speaks IPv4 on the wire, so it is
 * an IPv4 flow and gets the IPv4 rules. Where it shows up depends on the
 * call: connect() reaches connect6, sendto() reaches sendmsg4.
 */
static __always_inline __u8 sa_get(const struct bpf_sock_addr *ctx, __u8 sf, __u32 *a)
{
	if (sf == 4) {
		a[0] = ctx->user_ip4;
		a[1] = a[2] = a[3] = 0;
		return 4;
	}
	if (is_v4_mapped(ctx)) {
		a[0] = ctx->user_ip6[3];
		a[1] = a[2] = a[3] = 0;
		return 4;
	}
	a[0] = ctx->user_ip6[0];
	a[1] = ctx->user_ip6[1];
	a[2] = ctx->user_ip6[2];
	a[3] = ctx->user_ip6[3];
	return 6;
}

/* Writes a flow-form address back in the form the socket's family needs. */
static __always_inline void sa_set(struct bpf_sock_addr *ctx, __u8 sf, __u8 family, const __u32 *a)
{
	if (sf == 4) {
		ctx->user_ip4 = a[0];
	} else if (family == 4) {
		ctx->user_ip6[0] = 0;
		ctx->user_ip6[1] = 0;
		ctx->user_ip6[2] = bpf_htonl(0xffff);
		ctx->user_ip6[3] = a[0];
	} else {
		ctx->user_ip6[0] = a[0];
		ctx->user_ip6[1] = a[1];
		ctx->user_ip6[2] = a[2];
		ctx->user_ip6[3] = a[3];
	}
}

/*
 * The kernel sends a flow to 0.0.0.0 or :: to this host: an IPv4 socket
 * bound to an address dials that address, anything else dials loopback.
 * The flow is judged as the address it will reach. Judged as written it
 * would pass a deny of loopback here and time out at the packet hook, and
 * miss a redirect.
 */
static __always_inline void to_this_host(const struct bpf_sock_addr *ctx, __u8 sf, struct flow *f)
{
	if (f->family == 4 && !f->addr[0]) {
		__u32 bound = sf == 4 ? ctx->sk->src_ip4 : 0;

		f->addr[0] = bound ? bound : bpf_htonl(0x7f000001);
	} else if (f->family == 6 && !(f->addr[0] | f->addr[1] | f->addr[2] | f->addr[3])) {
		f->addr[3] = bpf_htonl(1);
	}
}

static __always_inline void sa_flow(const struct bpf_sock_addr *ctx, __u8 sf, __u8 dir,
				    struct flow *f)
{
	f->dir = dir;
	f->pbit = proto_bit(ctx->protocol);
	f->family = sa_get(ctx, sf, f->addr);
	if (dir == BP_DIR_EGRESS)
		to_this_host(ctx, sf, f);
	/* A ping socket can only send echo requests, and the type is not in
	 * the sockaddr. */
	if (f->pbit == BP_P_ICMP)
		f->port = f->family == 4 ? ICMP_ECHO : ICMPV6_ECHO_REQ;
	else
		f->port = bpf_ntohs(ctx->user_port);
}

static __always_inline void sa_event(struct bpf_sock_addr *ctx, __u8 hook, const struct flow *f,
				     const struct verdict *v)
{
	struct ev_args a = {};

	a.box = f->box;
	a.cookie = bpf_get_socket_cookie(ctx);
	a.pid = bpf_get_current_pid_tgid() >> 32;
	a.rule = v->rule;
	a.l4proto = ctx->protocol;
	a.sock_type = ctx->type;
	a.dport = f->port;
	a.hook = hook;
	a.verdict = v->action;
	a.reason = v->reason;
	a.family = f->family;
	__builtin_memcpy(a.daddr, f->addr, 16);
	emit_net(&a);
}

/*
 * Rewrites the destination to the endpoint of a redirect rule and remembers
 * what the application asked for. Returns 0 on success.
 *
 * The endpoint must be of the flow's family. The kernel refuses a sendmsg6
 * program that turns an IPv6 destination into a v4-mapped one (ENOTSUPP in
 * udpv6_sendmsg), and an AF_INET socket cannot reach an IPv6 endpoint at all.
 */
static __always_inline int steer(struct bpf_sock_addr *ctx, __u8 sf, const struct bp_box_cfg *cfg,
				 const struct flow *f, const struct verdict *v)
{
	struct bp_endpoint_key ek = {};
	struct bp_endpoint *ep;
	struct sk_state *st;
	__u32 to[4] = {};
	__u16 port;

	ek.box_id = f->box;
	ek.generation = cfg->generation;
	ek.idx = v->endpoint;
	ep = bpf_map_lookup_elem(&endpoints, &ek);
	if (!ep)
		return -1;
	if (f->family == 4) {
		to[0] = ep->addr4;
		port = ep->port4;
	} else {
		__builtin_memcpy(to, ep->addr6, 16);
		port = ep->port6;
	}
	if (!port)
		return -1;

	st = bpf_sk_storage_get(&sk_state, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (!st)
		return -1;
	__builtin_memcpy(st->orig, f->addr, 16);
	st->orig_port = ctx->user_port;
	__builtin_memcpy(st->to, to, 16);
	st->to_port = bpf_htons(port);
	st->family = f->family;
	st->endpoint = v->endpoint;
	st->flags |= ST_REWRITTEN;

	sa_set(ctx, sf, f->family, to);
	ctx->user_port = bpf_htons(port);
	return 0;
}

static __always_inline int sa_out(struct bpf_sock_addr *ctx, __u8 hook, __u8 sf)
{
	struct bp_box_cfg *cfg;
	struct verdict v = {};
	struct flow f = {};

	f.box = sock_box(ctx->sk);
	sa_flow(ctx, sf, BP_DIR_EGRESS, &f);
	cfg = bpf_map_lookup_elem(&box_cfg, &f.box);
	if (!cfg) {
		v.reason = BP_R_NO_CFG;
		v.rule = BP_NO_RULE;
		sa_event(ctx, hook, &f, &v);
		return refuse(f.box, EPERM);
	}

	decide(cfg, &f, &v);

	if (v.action == BP_DENY && f.pbit == BP_P_UDP) {
		/* A reply to a peer the ingress hook let in. */
		struct udp_peer up;

		peer_key(&up, bpf_get_socket_cookie(ctx), f.addr, f.port);
		if (peer_admitted(&up, BP_DIR_INGRESS, cfg->generation))
			return 1;
	}
	if (v.action == BP_REDIRECT && steer(ctx, sf, cfg, &f, &v)) {
		v.action = BP_DENY;
		v.reason = BP_R_NO_ENDPOINT;
	}
	if (v.action == BP_DENY) {
		sa_event(ctx, hook, &f, &v);
		return refuse(f.box, cfg->refuse_errno);
	}
	if (cfg->flags & BP_F_LOG_FLOWS)
		sa_event(ctx, hook, &f, &v);
	return 1;
}

SEC("cgroup/connect4")
int bp_connect4(struct bpf_sock_addr *ctx)
{
	return sa_out(ctx, BP_H_CONNECT4, 4);
}

SEC("cgroup/sendmsg4")
int bp_sendmsg4(struct bpf_sock_addr *ctx)
{
	return sa_out(ctx, BP_H_SENDMSG4, 4);
}

SEC("cgroup/connect6")
int bp_connect6(struct bpf_sock_addr *ctx)
{
	return sa_out(ctx, BP_H_CONNECT6, 6);
}

SEC("cgroup/sendmsg6")
int bp_sendmsg6(struct bpf_sock_addr *ctx)
{
	return sa_out(ctx, BP_H_SENDMSG6, 6);
}

/* Show the application the address it asked for, not the endpoint that answered. */
static __always_inline int restore(struct bpf_sock_addr *ctx, __u8 sf)
{
	struct sk_state *st = bpf_sk_storage_get(&sk_state, ctx->sk, 0, 0);
	__u32 a[4];

	if (!st || !(st->flags & ST_REWRITTEN))
		return 1;
	if (sa_get(ctx, sf, a) == st->family && a[0] == st->to[0] && a[1] == st->to[1] &&
	    a[2] == st->to[2] && a[3] == st->to[3] && ctx->user_port == st->to_port) {
		sa_set(ctx, sf, st->family, st->orig);
		ctx->user_port = st->orig_port;
	}
	return 1;
}

SEC("cgroup/recvmsg4")
int bp_recvmsg4(struct bpf_sock_addr *ctx)
{
	return restore(ctx, 4);
}

SEC("cgroup/getpeername4")
int bp_getpeername4(struct bpf_sock_addr *ctx)
{
	return restore(ctx, 4);
}

SEC("cgroup/recvmsg6")
int bp_recvmsg6(struct bpf_sock_addr *ctx)
{
	return restore(ctx, 6);
}

SEC("cgroup/getpeername6")
int bp_getpeername6(struct bpf_sock_addr *ctx)
{
	return restore(ctx, 6);
}

static __always_inline int bind_any(struct bpf_sock_addr *ctx, __u8 hook, __u8 sf)
{
	struct bp_box_cfg *cfg;
	struct verdict v = {};
	struct flow f = {};

	f.box = sock_box(ctx->sk);
	sa_flow(ctx, sf, BP_DIR_BIND, &f);
	f.port = bpf_ntohs(ctx->user_port);
	cfg = bpf_map_lookup_elem(&box_cfg, &f.box);
	if (!cfg) {
		v.reason = BP_R_NO_CFG;
		v.rule = BP_NO_RULE;
		sa_event(ctx, hook, &f, &v);
		return refuse(f.box, EPERM);
	}
	/* Port 0 asks the kernel for an ephemeral port, which a socket also
	 * gets without any bind call. */
	if (!f.port)
		return 1;
	decide(cfg, &f, &v);
	if (v.action == BP_ALLOW)
		return 1;
	v.action = BP_DENY;
	sa_event(ctx, hook, &f, &v);
	return refuse(f.box, cfg->refuse_errno);
}

SEC("cgroup/bind4")
int bp_bind4(struct bpf_sock_addr *ctx)
{
	return bind_any(ctx, BP_H_BIND4, 4);
}

SEC("cgroup/bind6")
int bp_bind6(struct bpf_sock_addr *ctx)
{
	return bind_any(ctx, BP_H_BIND6, 6);
}

/*
 * Runs for AF_INET and AF_INET6 sockets only. It keeps the socket kinds down
 * to the ones the other hooks understand: TCP, UDP and ping sockets.
 */
SEC("cgroup/sock_create")
int bp_sock_create(struct bpf_sock *sk)
{
	__u64 box = task_box();
	struct bp_box_cfg *cfg = bpf_map_lookup_elem(&box_cfg, &box);
	struct ev_args a = {};
	__u8 pbit = proto_bit(sk->protocol);
	__u16 err = cfg ? cfg->refuse_errno : EPERM;
	__u8 reason = cfg ? BP_R_SOCK_TYPE : BP_R_NO_CFG;

	if (cfg && ((sk->type == SOCK_STREAM && pbit == BP_P_TCP) ||
		    (sk->type == SOCK_DGRAM && (pbit == BP_P_UDP || pbit == BP_P_ICMP)))) {
		__u64 *owner = bpf_sk_storage_get(&sk_box, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);

		if (owner) {
			*owner = box;
			return 1;
		}
		/* A socket nobody can name the box of would be refused at
		 * every later call. */
		err = ENOMEM;
		reason = BP_R_NO_MEMORY;
	}

	a.box = box;
	a.pid = bpf_get_current_pid_tgid() >> 32;
	a.rule = BP_NO_RULE;
	a.l4proto = sk->protocol;
	a.sock_type = sk->type;
	a.hook = BP_H_SOCK_CREATE;
	a.family = sk->family == AF_INET6 ? 6 : 4;
	a.verdict = BP_DENY;
	a.reason = reason;
	emit_net(&a);
	return refuse(box, err);
}

/* The socket's entry in the flows map must not outlive it: the next socket
 * with the same local address and port may belong to anyone. */
SEC("cgroup/sock_release")
int bp_sock_release(struct bpf_sock *sk)
{
	struct sk_state *st = bpf_sk_storage_get(&sk_state, sk, 0, 0);

	if (st && (st->flags & ST_FLOW))
		bpf_map_delete_elem(&flows, &st->flow_key);
	return 1;
}
