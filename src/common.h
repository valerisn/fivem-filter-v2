/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared ABI between the XDP program (filter.bpf.c) and userspace (fivemctl.c).
 * Anything in here is copied verbatim across the map boundary, so layout must
 * stay stable: 64-bit fields first, then 32, then 16, then bytes.
 */
#ifndef FIVEM_FILTER_COMMON_H
#define FIVEM_FILTER_COMMON_H

#include <linux/types.h>

/* Address family tags stored in ff_addr.a[3] so a v4 address can never alias
 * a v6 /64 prefix inside the same map. */
#define FF_AF_INET  4
#define FF_AF_INET6 6

/*
 * Unified address key. IPv4 lives in a[0] (network byte order) with a[1..2]
 * zeroed. IPv6 is stored as its /64 prefix in a[0..1] - rate limiting a single
 * /128 is pointless when any residential v6 allocation is at least a /64.
 */
struct ff_addr {
	__u32 a[4];
};

/* Longest-prefix-match key for CIDR block/allow lists (IPv4). */
struct ff_lpm4 {
	__u32 prefixlen;
	__u8  addr[4];
};

/* Value type for the exact-match and CIDR lists. expires_ns == 0 is
 * permanent; otherwise it is compared against bpf_ktime_get_ns(). */
struct ff_listent {
	__u64 expires_ns;
	__u64 hits;
};

/* ------------------------------------------------------------------ config */

#define FF_F_ENABLED		(1U << 0)  /* master switch */
#define FF_F_DRY_RUN		(1U << 1)  /* count drops but pass the packet */
#define FF_F_DROP_ICMP		(1U << 2)  /* drop all ICMP, not just non-echo */
#define FF_F_DROP_IPV6		(1U << 3)  /* drop IPv6 outright */
#define FF_F_STRICT_TCP		(1U << 4)  /* non-SYN TCP needs a known flow */
#define FF_F_DROP_IP_OPTS	(1U << 5)  /* drop IPv4 packets carrying options */
#define FF_F_DROP_FRAGS		(1U << 6)  /* drop every fragment, incl. the first */
#define FF_F_LOG		(1U << 7)  /* emit sampled drop events to the ringbuf */
#define FF_F_BOGON		(1U << 8)  /* drop martian / unroutable sources */
#define FF_F_LOCKDOWN		(1U << 9)  /* drop everything not explicitly allowed */
#define FF_F_DROP_OOB		(1U << 10) /* drop all OOB queries (getinfo/getstatus) */

struct ff_config {
	/* 64-bit */
	__u64 tb_refill_ns;		/* one token per this many ns, per source */
	__u64 syn_rate_ns;		/* min gap between SYNs from one source */
	__u64 icmp_rate_ns;		/* min gap between ICMP echoes from one source */
	__u64 oob_rate_ns;		/* min gap between OOB queries from one source */
	__u64 flow_idle_ns;		/* TCP flow idle eviction */
	__u64 conn_window_ns;		/* window for the new-connection quota */
	__u64 tcp_learn_until_ns;	/* adopt unknown TCP flows until this ktime */

	/* 32-bit */
	__u32 flags;
	__u32 v4_addr;			/* network byte order; 0 = match any destination */
	__u32 hash_seed;		/* randomised per load, defeats collision attacks */
	__u32 tb_burst;			/* token bucket depth per source */
	__u32 amp_limit;		/* UDP bytes above which known amp source ports die */
	__u32 udp_min_len;		/* min UDP payload accepted on a game port */
	__u32 udp_max_len;		/* max UDP payload accepted on a game port */
	__u32 conn_per_window;		/* new TCP flows per source per conn_window_ns */
	__u32 global_syn_pps;		/* box-wide SYN ceiling (spoof protection) */
	__u32 global_oob_pps;		/* box-wide OOB query ceiling */
	__u32 log_sample;		/* emit 1 event in N drops; 0 disables */

	/* 16-bit */
	__u16 port_lo;			/* inclusive game port range, host order */
	__u16 port_hi;
	__u16 aux_port;			/* extra TCP port (txAdmin); 0 = unused */

	/* 8-bit */
	__u8 v6_set;			/* v6_addr is meaningful */
	__u8 pad_[1];
	__u8 v6_addr[16];		/* server IPv6, network byte order */
};

/* -------------------------------------------------------------------- stats */

/*
 * Single source of truth for the stats array. Index order is ABI; append only.
 * The string is what `fivemctl stats` prints.
 */
#define FF_STAT_LIST(X)                                                     \
	X(PASS,             "pass")                                         \
	X(DRYRUN_PASS,      "dry-run pass (would have dropped)")            \
	X(DROP_BLOCKLIST,   "blocklist")                                    \
	X(DROP_LOCKDOWN,    "lockdown (not allowlisted)")                   \
	X(DROP_BOGON,       "bogon / martian source")                       \
	X(DROP_LAND,        "land attack (src == dst)")                     \
	X(DROP_IP_OPTS,     "ipv4 options")                                 \
	X(DROP_FRAG,        "fragment")                                     \
	X(DROP_AMP,         "udp amplification source port")                \
	X(DROP_UDP_SIZE,    "udp payload outside accepted size")            \
	X(DROP_RATE,        "per-source token bucket")                      \
	X(DROP_SYN_RATE,    "per-source syn rate")                          \
	X(DROP_CONN_RATE,   "per-source new-connection quota")              \
	X(DROP_GLOBAL_SYN,  "global syn ceiling")                           \
	X(DROP_GLOBAL_OOB,  "global oob query ceiling")                     \
	X(DROP_OOB_RATE,    "per-source oob query rate")                    \
	X(DROP_OOB,         "oob queries disabled")                         \
	X(DROP_ICMP,        "icmp")                                         \
	X(DROP_TCP_NOFLOW,  "tcp without established flow")                 \
	X(DROP_TCP_FLAGS,   "invalid tcp flag combination")                 \
	X(DROP_TCP_SYNDATA, "syn carrying payload")                         \
	X(DROP_IPV6,        "ipv6 disabled")                                \
	X(DROP_MALFORMED,   "malformed / truncated header")

enum ff_stat {
#define FF_STAT_ENUM(name, str) FF_STAT_##name,
	FF_STAT_LIST(FF_STAT_ENUM)
#undef FF_STAT_ENUM
	FF_STAT_MAX
};

#ifndef __BPF__
static const char *const ff_stat_names[FF_STAT_MAX] = {
#define FF_STAT_NAME(name, str) [FF_STAT_##name] = str,
	FF_STAT_LIST(FF_STAT_NAME)
#undef FF_STAT_NAME
};
#endif

/* ------------------------------------------------------------------ events */

struct ff_event {
	__u64 ts_ns;
	__u32 saddr[4];
	__u32 daddr[4];
	__u16 sport;
	__u16 dport;
	__u16 pkt_len;
	__u8  proto;
	__u8  af;
	__u8  reason;	/* enum ff_stat */
	__u8  dry;	/* packet was passed because of FF_F_DRY_RUN */
	__u8  pad_[2];
};

/* Pin path used by the loader; fivemctl finds every map underneath it. */
#define FF_PIN_DIR "/sys/fs/bpf/fivem-filter"

#endif /* FIVEM_FILTER_COMMON_H */
