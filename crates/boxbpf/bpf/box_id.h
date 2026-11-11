/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/*
 * Box identity: the id of the cgroup directly below the attach point.
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

/* For the system-call hooks: the calling task's box. 0 when it is in none. */
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

/* For the packet hooks: the box that owns the socket. They also run in
 * softirq context, where the current task has nothing to do with the packet. */
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
