// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * Box network policy: cgroup programs attached once at <root>/boxes.
 * One translation unit, so every hook shares the maps in policy.h.
 */
#include "policy.h"
#include "sockaddr.c"
#include "skb.c"

char LICENSE[] SEC("license") = "Dual MIT/GPL";
