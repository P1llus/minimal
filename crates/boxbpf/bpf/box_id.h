/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/*
 * Box identity: the id of the cgroup directly below the attach point.
 *
 * A socket belongs to the box it was created in, at every hook and whoever
 * makes the call. The packet hooks read that from the socket's cgroup. The
 * system-call hooks cannot read a socket's cgroup, so bp_sock_create writes
 * the id into the socket's storage and they read it there.
 *
 * The ancestor helpers take a depth counted from the real cgroup root.
 * Userspace cannot compute that depth when it runs inside a cgroup
 * namespace (WSL2, containers), because its paths start at the namespace
 * root. So the loader passes the id of the attach cgroup, which is the same
 * in every namespace, and the first program to run finds the depth by
 * walking up until it meets that id.
 */
#ifndef BOXBPF_BOX_ID_H
#define BOXBPF_BOX_ID_H

#define BP_MAX_DEPTH 32

const volatile __u64 boxes_id = 0; /* cgroup id of the attach point, set at load */
__u32 box_level = 0;               /* depth of a box cgroup, 0 until found */

/* The box a socket was created in. A socket that accept() returns gets a
 * copy of its listener's entry. */
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
	__type(key, int);
	__type(value, __u64);
} sk_box SEC(".maps");

/* For bp_sock_create only: the calling task's box, which is the box of the
 * socket it is creating. 0 when the task is in none. */
static __always_inline __u64 task_box(void)
{
	__u32 level = box_level;

	if (level)
		return bpf_get_current_ancestor_cgroup_id(level);
	for (int l = 0; l < BP_MAX_DEPTH; l++) {
		if (bpf_get_current_ancestor_cgroup_id(l) == boxes_id) {
			box_level = l + 1;
			return bpf_get_current_ancestor_cgroup_id(l + 1);
		}
	}
	return 0;
}

/* For the other system-call hooks: the box of the socket, whoever calls.
 * 0 for a socket bp_sock_create never saw. */
static __always_inline __u64 sock_box(void *sk)
{
	__u64 *box = bpf_sk_storage_get(&sk_box, sk, 0, 0);

	return box ? *box : 0;
}

/* For the packet hooks: the box of the socket's cgroup. The kernel's own
 * sockets, which bp_sock_create never sees, have one too. */
static __always_inline __u64 skb_box(struct __sk_buff *skb)
{
	__u32 level = box_level;

	if (level)
		return bpf_skb_ancestor_cgroup_id(skb, level);
	for (int l = 0; l < BP_MAX_DEPTH; l++) {
		if (bpf_skb_ancestor_cgroup_id(skb, l) == boxes_id) {
			box_level = l + 1;
			return bpf_skb_ancestor_cgroup_id(skb, l + 1);
		}
	}
	return 0;
}

#endif /* BOXBPF_BOX_ID_H */
