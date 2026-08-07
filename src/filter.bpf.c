/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fivem-xdp-filter - XDP ingress filter for FiveM / CFX game servers.
 *
 * Everything tunable lives in a config map, so a running filter can be
 * retuned without a recompile or a reattach. See src/common.h for the ABI
 * and fivemctl for the control plane.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

/*
 * Per-source state lives in a fixed, hashed array rather than an LRU hash.
 * Three reasons: the memory footprint is known up front (no allocation under
 * flood), entries can never be evicted at the exact moment they matter, and
 * an array value may carry a bpf_spin_lock - an LRU hash may not, which is
 * why the naive read-modify-write token bucket raced across CPUs.
 *
 * Two sources sharing a slot is resolved by the `tag` fingerprint: a mismatch
 * resets the slot. That means colliding sources do not punish each other, at
 * the cost of a source-rotating attacker resetting slots. Per-source limits
 * are useless against rotating sources anyway; the global ceilings cover that.
 */
#ifndef FF_STATE_SLOTS
#define FF_STATE_SLOTS (1u << 17)	/* 131072 slots * 64B = 8 MiB */
#endif
#define FF_STATE_MASK (FF_STATE_SLOTS - 1)

#define FF_MAP_LIST  131072
#define FF_MAP_FLOWS 524288
#define FF_MAP_CIDR  8192
#define FF_RINGBUF   (1u << 20)

#define FF_V6_MAX_EXT 6		/* extension headers we bother to walk */

/* Global (box-wide) token buckets, indexed by these. */
enum ff_global_slot {
	FF_G_SYN = 0,
	FF_G_OOB,
	FF_G_MAX
};

struct ff_state {
	struct bpf_spin_lock lock;
	__u64 refill_ns;	/* token bucket last refill */
	__u64 syn_ns;		/* last accepted SYN */
	__u64 icmp_ns;		/* last accepted ICMP echo */
	__u64 oob_ns;		/* last accepted OOB query */
	__u64 conn_ns;		/* start of the current new-connection window */
	__u32 tokens;
	__u32 conn_count;
	__u32 tag;
	__u32 pad_;
};

struct ff_bucket {
	struct bpf_spin_lock lock;
	__u64 refill_ns;
	__u64 tokens;
};

struct ff_flow_key {
	struct ff_addr saddr;
	struct ff_addr daddr;
	__u16 sport;		/* network byte order */
	__u16 dport;
	__u8  proto;
	__u8  pad_[3];
};

struct ff_flow_val {
	__u64 last_ns;
	__u8  established;
	__u8  pad_[7];
};

/* Decoded packet, carried through so drop paths can log something useful. */
struct ff_pkt {
	struct ff_addr src;
	struct ff_addr dst;
	__u16 sport;		/* host order */
	__u16 dport;
	__u16 len;
	__u8  proto;
	__u8  af;
};

/* ---------------------------------------------------------------- maps */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ff_config);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FF_STATE_SLOTS);
	__type(key, __u32);
	__type(value, struct ff_state);
} state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FF_G_MAX);
	__type(key, __u32);
	__type(value, struct ff_bucket);
} global SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FF_MAP_LIST);
	__type(key, struct ff_addr);
	__type(value, struct ff_listent);
} allowlist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FF_MAP_LIST);
	__type(key, struct ff_addr);
	__type(value, struct ff_listent);
} blocklist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, FF_MAP_CIDR);
	__type(key, struct ff_lpm4);
	__type(value, struct ff_listent);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allow_cidr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, FF_MAP_CIDR);
	__type(key, struct ff_lpm4);
	__type(value, struct ff_listent);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} block_cidr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FF_MAP_FLOWS);
	__type(key, struct ff_flow_key);
	__type(value, struct ff_flow_val);
} flows SEC(".maps");

/* Per-CPU so the fast path never contends; fivemctl sums across CPUs. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FF_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, FF_RINGBUF);
} events SEC(".maps");

/* ------------------------------------------------------------- helpers */

static __always_inline void ff_count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);

	if (v)
		*v += 1;	/* per-CPU: no atomic needed */
}

static __always_inline void ff_log(struct ff_config *cfg, struct ff_pkt *pkt,
				   __u32 reason, bool dry)
{
	struct ff_event *e;

	if (!(cfg->flags & FF_F_LOG) || !cfg->log_sample)
		return;
	if (cfg->log_sample > 1 && (bpf_get_prandom_u32() % cfg->log_sample))
		return;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->ts_ns = bpf_ktime_get_ns();
	__builtin_memcpy(e->saddr, pkt->src.a, sizeof(e->saddr));
	__builtin_memcpy(e->daddr, pkt->dst.a, sizeof(e->daddr));
	e->sport = pkt->sport;
	e->dport = pkt->dport;
	e->pkt_len = pkt->len;
	e->proto = pkt->proto;
	e->af = pkt->af;
	e->reason = (__u8)reason;
	e->dry = dry;
	e->pad_[0] = 0;
	e->pad_[1] = 0;

	bpf_ringbuf_submit(e, 0);
}

/* Single exit point: counts, logs, and honours dry-run. */
static __always_inline int ff_verdict(struct ff_config *cfg, struct ff_pkt *pkt,
				      __u32 reason)
{
	bool dry;

	ff_count(reason);
	if (reason == FF_STAT_PASS)
		return XDP_PASS;

	dry = cfg->flags & FF_F_DRY_RUN;
	ff_log(cfg, pkt, reason, dry);
	if (dry) {
		ff_count(FF_STAT_DRYRUN_PASS);
		return XDP_PASS;
	}
	return XDP_DROP;
}

static __always_inline __u32 ff_hash(const struct ff_addr *a, __u32 seed)
{
	__u32 h = seed ^ a->a[0];

	h *= 0x9e3779b1u;
	h ^= h >> 15;
	h += a->a[1];
	h *= 0x85ebca6bu;
	h ^= h >> 13;
	h += a->a[2] ^ a->a[3];
	h *= 0xc2b2ae35u;
	h ^= h >> 16;
	return h;
}

static __always_inline bool ff_addr_eq(const struct ff_addr *x,
				       const struct ff_addr *y)
{
	return x->a[0] == y->a[0] && x->a[1] == y->a[1] &&
	       x->a[2] == y->a[2] && x->a[3] == y->a[3];
}

/*
 * Martian / unroutable IPv4 sources. src_h is host byte order.
 * The /24 documentation ranges are compared on a 24-bit shift, which the
 * previous revision got wrong by comparing against the full 32-bit constant.
 */
static __always_inline bool ff_bogon4(__u32 src_h)
{
	if ((src_h >> 24) == 0)			return true;	/* 0.0.0.0/8 */
	if ((src_h >> 24) == 10)		return true;	/* 10.0.0.0/8 */
	if ((src_h >> 22) == 0x00019100)	return true;	/* 100.64.0.0/10 */
	if ((src_h >> 24) == 127)		return true;	/* 127.0.0.0/8 */
	if ((src_h >> 16) == 0x0000a9fe)	return true;	/* 169.254.0.0/16 */
	if ((src_h >> 20) == 0x00000ac1)	return true;	/* 172.16.0.0/12 */
	if ((src_h >> 24) == 192 &&
	    ((src_h >> 8) & 0xffff) == 0x0000)	return true;	/* 192.0.0.0/24 */
	if ((src_h >> 8)  == 0x00c00002)	return true;	/* 192.0.2.0/24 */
	if ((src_h >> 16) == 0x0000c0a8)	return true;	/* 192.168.0.0/16 */
	if ((src_h >> 17) == 0x00063090)	return true;	/* 198.18.0.0/15 */
	if ((src_h >> 8)  == 0x00c63364)	return true;	/* 198.51.100.0/24 */
	if ((src_h >> 8)  == 0x00cb0071)	return true;	/* 203.0.113.0/24 */
	if ((src_h >> 28) == 0xe)		return true;	/* 224.0.0.0/4 */
	if ((src_h >> 28) == 0xf)		return true;	/* 240.0.0.0/4 + bcast */
	return false;
}

/* Operates on the stored /64 prefix, which is all we keep of a v6 source. */
static __always_inline bool ff_bogon6(const struct ff_addr *s)
{
	__u32 w0 = bpf_ntohl(s->a[0]);

	if ((w0 >> 24) == 0xff)			return true;	/* ff00::/8 multicast */
	if ((w0 >> 22) == 0x3fa)		return true;	/* fe80::/10 link-local */
	if (!s->a[0] && !s->a[1])		return true;	/* :: and ::1 */
	if (w0 == 0x20010db8)			return true;	/* 2001:db8::/32 */
	return false;
}

/* UDP source ports that only ever appear on reflected amplification. */
static __always_inline bool ff_amp_port(__u16 sport)
{
	switch (sport) {
	case 19:	/* chargen  */
	case 53:	/* DNS      */
	case 111:	/* portmap  */
	case 123:	/* NTP      */
	case 137:	/* NetBIOS  */
	case 161:	/* SNMP     */
	case 389:	/* CLDAP    */
	case 520:	/* RIPv1    */
	case 1434:	/* MS-SQL   */
	case 1900:	/* SSDP     */
	case 3283:	/* ARD      */
	case 3702:	/* WS-Disc  */
	case 5093:	/* Sentinel */
	case 5353:	/* mDNS     */
	case 10001:	/* Ubiquiti */
	case 11211:	/* memcached */
	case 27015:	/* Source engine */
		return true;
	default:
		return false;
	}
}

static __always_inline bool ff_port_match(struct ff_config *cfg, __u16 dport)
{
	if (dport >= cfg->port_lo && dport <= cfg->port_hi)
		return true;
	return cfg->aux_port && dport == cfg->aux_port;
}

/*
 * Catches null/xmas/SYN-FIN scans and other illegal combinations. Anything
 * a real stack would never emit is cheaper to drop here than to hand to the
 * kernel's connection tracking.
 */
static __always_inline bool ff_tcp_flags_ok(const struct tcphdr *tcp)
{
	if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst &&
	    !tcp->psh && !tcp->urg)
		return false;			/* null scan */
	if (tcp->syn && tcp->fin)		return false;
	if (tcp->syn && tcp->rst)		return false;
	if (tcp->fin && tcp->urg && tcp->psh)	return false;	/* xmas */
	if (tcp->fin && !tcp->ack)		return false;
	if (tcp->rst && (tcp->psh || tcp->urg))	return false;
	if (tcp->urg && !tcp->ack)		return false;
	return true;
}

/* --------------------------------------------------------- rate limiting */

/* Checks requested inside the per-source critical section. */
#define FF_CHK_TOKENS 0x01
#define FF_CHK_SYN    0x02
#define FF_CHK_ICMP   0x04
#define FF_CHK_OOB    0x08
#define FF_CHK_CONN   0x10

/*
 * Every per-source decision happens under one lock, in one pass, so the
 * counters can never be observed half-updated. Returns FF_STAT_PASS when the
 * packet is allowed, otherwise the drop reason.
 *
 * No helper may be called while the lock is held - keep this arithmetic-only.
 */
static __always_inline __u32 ff_source_check(struct ff_config *cfg,
					     const struct ff_addr *src,
					     __u64 now, __u32 checks)
{
	__u32 idx = ff_hash(src, cfg->hash_seed) & FF_STATE_MASK;
	__u32 tag = ff_hash(src, cfg->hash_seed ^ 0x5bf03635u) | 1u;
	__u32 reason = FF_STAT_PASS;
	struct ff_state *s;
	__u64 elapsed;
	__u64 refill;

	s = bpf_map_lookup_elem(&state, &idx);
	if (!s)
		return FF_STAT_PASS;	/* array lookup cannot fail; keep verifier happy */

	bpf_spin_lock(&s->lock);

	if (s->tag != tag) {
		/* Slot belongs to a different source (or is virgin): claim it. */
		s->tag = tag;
		s->tokens = cfg->tb_burst;
		s->refill_ns = now;
		s->syn_ns = 0;
		s->icmp_ns = 0;
		s->oob_ns = 0;
		s->conn_ns = now;
		s->conn_count = 0;
	}

	if (checks & FF_CHK_TOKENS) {
		elapsed = now - s->refill_ns;
		if (cfg->tb_refill_ns) {
			refill = elapsed / cfg->tb_refill_ns;
			/* Clamp before the add - a long-idle source used to
			 * overflow tokens back around to near zero. */
			if (refill > cfg->tb_burst)
				refill = cfg->tb_burst;
			if (refill) {
				s->tokens += (__u32)refill;
				if (s->tokens > cfg->tb_burst)
					s->tokens = cfg->tb_burst;
				s->refill_ns = now;
			}
		}
		if (!s->tokens)
			reason = FF_STAT_DROP_RATE;
		else
			s->tokens--;
	}

	if (reason == FF_STAT_PASS && (checks & FF_CHK_SYN)) {
		if (s->syn_ns && (now - s->syn_ns) < cfg->syn_rate_ns)
			reason = FF_STAT_DROP_SYN_RATE;
		else
			s->syn_ns = now;
	}

	if (reason == FF_STAT_PASS && (checks & FF_CHK_ICMP)) {
		if (s->icmp_ns && (now - s->icmp_ns) < cfg->icmp_rate_ns)
			reason = FF_STAT_DROP_ICMP;
		else
			s->icmp_ns = now;
	}

	if (reason == FF_STAT_PASS && (checks & FF_CHK_OOB)) {
		if (s->oob_ns && (now - s->oob_ns) < cfg->oob_rate_ns)
			reason = FF_STAT_DROP_OOB_RATE;
		else
			s->oob_ns = now;
	}

	/*
	 * New-connection quota. A fixed window rather than a running count:
	 * a running count drifts permanently every time a flow is evicted
	 * without a FIN, which is exactly what happens under attack.
	 */
	if (reason == FF_STAT_PASS && (checks & FF_CHK_CONN)) {
		if ((now - s->conn_ns) >= cfg->conn_window_ns) {
			s->conn_ns = now;
			s->conn_count = 0;
		}
		if (cfg->conn_per_window &&
		    s->conn_count >= cfg->conn_per_window)
			reason = FF_STAT_DROP_CONN_RATE;
		else
			s->conn_count++;
	}

	bpf_spin_unlock(&s->lock);
	return reason;
}

/*
 * Box-wide ceiling. Per-source limits do nothing against spoofed sources, so
 * SYNs and OOB queries also pass through a single shared bucket sized in
 * packets per second.
 */
static __always_inline bool ff_global_allow(__u32 slot, __u32 pps, __u64 now)
{
	struct ff_bucket *b;
	__u64 elapsed, refill, burst;

	if (!pps)
		return true;		/* 0 = unlimited */

	b = bpf_map_lookup_elem(&global, &slot);
	if (!b)
		return true;

	burst = pps;
	bpf_spin_lock(&b->lock);
	elapsed = now - b->refill_ns;
	refill = (elapsed * pps) / 1000000000ULL;
	if (refill) {
		b->tokens += refill;
		if (b->tokens > burst)
			b->tokens = burst;
		b->refill_ns = now;
	}
	if (b->tokens) {
		b->tokens--;
		bpf_spin_unlock(&b->lock);
		return true;
	}
	bpf_spin_unlock(&b->lock);
	return false;
}

/* ----------------------------------------------------------- list lookups */

static __always_inline struct ff_listent *ff_list_hit(void *exact, void *cidr,
						      struct ff_pkt *pkt,
						      __u64 now)
{
	struct ff_listent *e = bpf_map_lookup_elem(exact, &pkt->src);
	struct ff_lpm4 k;

	if (!e && pkt->af == FF_AF_INET) {
		k.prefixlen = 32;
		__builtin_memcpy(k.addr, &pkt->src.a[0], 4);
		e = bpf_map_lookup_elem(cidr, &k);
	}
	if (!e)
		return NULL;
	if (e->expires_ns && now > e->expires_ns)
		return NULL;
	__sync_fetch_and_add(&e->hits, 1);
	return e;
}

/* ------------------------------------------------------------- L3 parsing */

/*
 * Returns 0 on a fully parsed IPv4/IPv6 packet, 1 when the packet is not ours
 * to inspect (ARP, non-IP, unhandled ethertype), -1 when it is malformed.
 * On success *l4 points at the transport header and *frag reports whether the
 * packet is a fragment (and whether it is the first one).
 */
struct ff_l3 {
	void *l4;
	void *end;	/* end of the IP payload per the header's own length field */
	__u32 iplen;	/* total IP length, headers included */
	__u8  proto;
	bool  frag;
	bool  frag_first;
	bool  has_opts;
};

static __always_inline int ff_parse(void *data, void *data_end,
				    struct ff_pkt *pkt, struct ff_l3 *l3)
{
	struct ethhdr *eth = data;
	void *cur = (void *)(eth + 1);
	__u16 proto;

	if (cur > data_end)
		return -1;
	proto = eth->h_proto;

	/* Up to two VLAN tags (802.1Q and QinQ / 802.1ad). */
#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (proto != bpf_htons(ETH_P_8021Q) &&
		    proto != bpf_htons(ETH_P_8021AD))
			break;
		if (cur + 4 > data_end)
			return -1;
		proto = *(__u16 *)(cur + 2);
		cur += 4;
	}

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = cur;
		__u16 fo;
		__u32 hlen, tot;

		if ((void *)(ip + 1) > data_end)
			return -1;
		if (ip->version != 4 || ip->ihl < 5)
			return -1;
		hlen = ip->ihl * 4;
		if (cur + hlen > data_end)
			return -1;
		tot = bpf_ntohs(ip->tot_len);
		if (tot < hlen)
			return -1;

		/* Frames shorter than 60 bytes arrive padded, so data_end is
		 * not the end of the datagram. Trust tot_len, clamped to what
		 * was actually captured. */
		l3->iplen = tot;
		l3->end = cur + tot;
		if (l3->end > data_end)
			l3->end = data_end;

		pkt->af = FF_AF_INET;
		pkt->src.a[0] = ip->saddr;
		pkt->dst.a[0] = ip->daddr;
		pkt->src.a[3] = FF_AF_INET;
		pkt->dst.a[3] = FF_AF_INET;
		pkt->proto = ip->protocol;

		fo = bpf_ntohs(ip->frag_off);
		l3->has_opts = ip->ihl > 5;
		l3->frag = (fo & 0x2000) || (fo & 0x1fff);
		l3->frag_first = (fo & 0x2000) && !(fo & 0x1fff);
		l3->proto = ip->protocol;
		l3->l4 = cur + hlen;
		return 0;
	}

	if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = cur;
		__u8 nexthdr;
		__u32 tot;

		if ((void *)(ip6 + 1) > data_end)
			return -1;

		tot = sizeof(*ip6) + bpf_ntohs(ip6->payload_len);
		l3->iplen = tot;
		l3->end = cur + tot;
		if (l3->end > data_end)
			l3->end = data_end;

		pkt->af = FF_AF_INET6;
		/* /64 prefix only: the host half is attacker-controlled. */
		pkt->src.a[0] = ip6->saddr.in6_u.u6_addr32[0];
		pkt->src.a[1] = ip6->saddr.in6_u.u6_addr32[1];
		pkt->src.a[3] = FF_AF_INET6;
		pkt->dst.a[0] = ip6->daddr.in6_u.u6_addr32[0];
		pkt->dst.a[1] = ip6->daddr.in6_u.u6_addr32[1];
		pkt->dst.a[3] = FF_AF_INET6;

		nexthdr = ip6->nexthdr;
		cur = (void *)(ip6 + 1);
		l3->has_opts = false;
		l3->frag = false;
		l3->frag_first = false;

#pragma unroll
		for (int i = 0; i < FF_V6_MAX_EXT; i++) {
			struct ipv6_opt_hdr *oh;

			if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP ||
			    nexthdr == IPPROTO_ICMPV6)
				break;
			if (nexthdr == IPPROTO_FRAGMENT) {
				struct frag_hdr {
					__u8 nexthdr;
					__u8 reserved;
					__be16 frag_off;
					__be32 identification;
				} *fh = cur;

				if ((void *)(fh + 1) > data_end)
					return -1;
				l3->frag = true;
				l3->frag_first = !(bpf_ntohs(fh->frag_off) & 0xfff8);
				nexthdr = fh->nexthdr;
				cur = (void *)(fh + 1);
				continue;
			}
			if (nexthdr != IPPROTO_HOPOPTS &&
			    nexthdr != IPPROTO_ROUTING &&
			    nexthdr != IPPROTO_DSTOPTS)
				break;	/* ESP/AH/unknown: leave proto as-is */

			oh = cur;
			if ((void *)(oh + 1) > data_end)
				return -1;
			nexthdr = oh->nexthdr;
			cur += (oh->hdrlen + 1) * 8;
			if (cur > data_end)
				return -1;
			l3->has_opts = true;
		}

		pkt->proto = nexthdr;
		l3->proto = nexthdr;
		l3->l4 = cur;
		return 0;
	}

	return 1;	/* not IP - let the stack deal with it */
}

/* ------------------------------------------------------------- L4 helpers */

/*
 * CFX out-of-band queries (getinfo, getstatus, connect, rcon) are prefixed
 * with 0xFFFFFFFF. They are the cheap request / expensive reply asymmetry that
 * FiveM query floods abuse, so they get their own budget separate from
 * gameplay traffic.
 */
static __always_inline bool ff_is_oob(void *payload, void *data_end)
{
	__u32 *magic = payload;

	if ((void *)(magic + 1) > data_end)
		return false;
	return *magic == 0xffffffffu;
}

/* -------------------------------------------------------------- program */

SEC("xdp")
int fivem_filter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ff_pkt pkt = {};
	struct ff_l3 l3 = {};
	struct ff_config *cfg;
	__u32 zero = 0, reason;
	__u64 now;
	int rc;

	cfg = bpf_map_lookup_elem(&config, &zero);
	if (!cfg || !(cfg->flags & FF_F_ENABLED))
		return XDP_PASS;

	rc = ff_parse(data, data_end, &pkt, &l3);
	if (rc > 0)
		return XDP_PASS;
	if (rc < 0)
		return ff_verdict(cfg, &pkt, FF_STAT_DROP_MALFORMED);

	pkt.len = (__u16)l3.iplen;	/* on-the-wire IP length, padding excluded */
	now = bpf_ktime_get_ns();

	if (pkt.af == FF_AF_INET6 && (cfg->flags & FF_F_DROP_IPV6))
		return ff_verdict(cfg, &pkt, FF_STAT_DROP_IPV6);

	/* Allowlist wins over everything, including lockdown. */
	if (ff_list_hit(&allowlist, &allow_cidr, &pkt, now))
		return ff_verdict(cfg, &pkt, FF_STAT_PASS);

	if (ff_list_hit(&blocklist, &block_cidr, &pkt, now))
		return ff_verdict(cfg, &pkt, FF_STAT_DROP_BLOCKLIST);

	if (cfg->flags & FF_F_LOCKDOWN)
		return ff_verdict(cfg, &pkt, FF_STAT_DROP_LOCKDOWN);

	if (cfg->flags & FF_F_BOGON) {
		bool bogus = pkt.af == FF_AF_INET
				? ff_bogon4(bpf_ntohl(pkt.src.a[0]))
				: ff_bogon6(&pkt.src);

		if (bogus)
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_BOGON);
	}

	/* Land attack: a packet claiming to come from the address it targets. */
	if (ff_addr_eq(&pkt.src, &pkt.dst))
		return ff_verdict(cfg, &pkt, FF_STAT_DROP_LAND);

	/* Not addressed to the server we protect: leave it alone. */
	if (pkt.af == FF_AF_INET && cfg->v4_addr && pkt.dst.a[0] != cfg->v4_addr)
		return XDP_PASS;
	if (pkt.af == FF_AF_INET6 && cfg->v6_set) {
		__u32 w0, w1;

		__builtin_memcpy(&w0, &cfg->v6_addr[0], 4);
		__builtin_memcpy(&w1, &cfg->v6_addr[4], 4);
		if (pkt.dst.a[0] != w0 || pkt.dst.a[1] != w1)
			return XDP_PASS;
	}

	if (l3.has_opts && (cfg->flags & FF_F_DROP_IP_OPTS))
		return ff_verdict(cfg, &pkt, FF_STAT_DROP_IP_OPTS);

	/*
	 * Only the first fragment carries L4 headers, so later fragments can
	 * never be port-matched - which is precisely why attackers send them.
	 * The first fragment is rate limited and passed for reassembly.
	 */
	if (l3.frag) {
		if (!l3.frag_first || (cfg->flags & FF_F_DROP_FRAGS))
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_FRAG);
		reason = ff_source_check(cfg, &pkt.src, now, FF_CHK_TOKENS);
		return ff_verdict(cfg, &pkt, reason);
	}

	if (l3.proto == IPPROTO_UDP) {
		struct udphdr *udp = l3.l4;
		void *payload;
		__u32 plen;
		__u32 checks = FF_CHK_TOKENS;
		bool oob;

		if ((void *)(udp + 1) > data_end)
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_MALFORMED);
		if (bpf_ntohs(udp->len) < sizeof(*udp))
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_MALFORMED);

		pkt.sport = bpf_ntohs(udp->source);
		pkt.dport = bpf_ntohs(udp->dest);

		if (!ff_port_match(cfg, pkt.dport))
			return XDP_PASS;

		if (pkt.len > cfg->amp_limit && ff_amp_port(pkt.sport))
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_AMP);

		payload = (void *)(udp + 1);
		/* Measured, not claimed: udp->len is attacker-controlled. */
		plen = payload <= l3.end
			? (__u32)((long)l3.end - (long)payload) : 0;
		if (plen < cfg->udp_min_len ||
		    (cfg->udp_max_len && plen > cfg->udp_max_len))
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_UDP_SIZE);

		oob = plen >= 4 && ff_is_oob(payload, data_end);
		if (oob) {
			if (cfg->flags & FF_F_DROP_OOB)
				return ff_verdict(cfg, &pkt, FF_STAT_DROP_OOB);
			if (!ff_global_allow(FF_G_OOB, cfg->global_oob_pps, now))
				return ff_verdict(cfg, &pkt,
						  FF_STAT_DROP_GLOBAL_OOB);
			checks |= FF_CHK_OOB;
		}

		reason = ff_source_check(cfg, &pkt.src, now, checks);
		if (reason != FF_STAT_PASS)
			return ff_verdict(cfg, &pkt, reason);

		return ff_verdict(cfg, &pkt, FF_STAT_PASS);
	}

	if (l3.proto == IPPROTO_TCP) {
		struct tcphdr *tcp = l3.l4;
		struct ff_flow_key fk = {};
		struct ff_flow_val *fv;
		__u32 hlen;

		if ((void *)(tcp + 1) > data_end)
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_MALFORMED);
		if (tcp->doff < 5)
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_MALFORMED);
		hlen = tcp->doff * 4;
		if ((void *)tcp + hlen > data_end)
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_MALFORMED);

		pkt.sport = bpf_ntohs(tcp->source);
		pkt.dport = bpf_ntohs(tcp->dest);

		if (!ff_port_match(cfg, pkt.dport))
			return XDP_PASS;

		if (!ff_tcp_flags_ok(tcp))
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_TCP_FLAGS);

		fk.saddr = pkt.src;
		fk.daddr = pkt.dst;
		fk.sport = tcp->source;
		fk.dport = tcp->dest;
		fk.proto = IPPROTO_TCP;

		if (tcp->syn && !tcp->ack) {
			struct ff_flow_val nfv = { .last_ns = now };

			/* A bare SYN with payload is not something a normal
			 * client sends; it is a cheap way to burn server work.
			 * Compared against l3.end, not data_end, so runt-frame
			 * Ethernet padding is not mistaken for payload. */
			if ((void *)tcp + hlen < l3.end)
				return ff_verdict(cfg, &pkt,
						  FF_STAT_DROP_TCP_SYNDATA);

			if (!ff_global_allow(FF_G_SYN, cfg->global_syn_pps, now))
				return ff_verdict(cfg, &pkt,
						  FF_STAT_DROP_GLOBAL_SYN);

			reason = ff_source_check(cfg, &pkt.src, now,
						 FF_CHK_TOKENS | FF_CHK_SYN |
						 FF_CHK_CONN);
			if (reason != FF_STAT_PASS)
				return ff_verdict(cfg, &pkt, reason);

			bpf_map_update_elem(&flows, &fk, &nfv, BPF_ANY);
			return ff_verdict(cfg, &pkt, FF_STAT_PASS);
		}

		fv = bpf_map_lookup_elem(&flows, &fk);
		if (!fv) {
			/*
			 * Connections that predate the filter have no flow
			 * entry. During the learning window (set by the loader
			 * at attach time) adopt them instead of tearing every
			 * live session down; after that, strict mode drops.
			 */
			struct ff_flow_val nfv = { .last_ns = now, .established = 1 };

			if (now < cfg->tcp_learn_until_ns ||
			    !(cfg->flags & FF_F_STRICT_TCP)) {
				bpf_map_update_elem(&flows, &fk, &nfv, BPF_ANY);
				reason = ff_source_check(cfg, &pkt.src, now,
							 FF_CHK_TOKENS);
				return ff_verdict(cfg, &pkt, reason);
			}
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_TCP_NOFLOW);
		}

		if ((now - fv->last_ns) > cfg->flow_idle_ns) {
			bpf_map_delete_elem(&flows, &fk);
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_TCP_NOFLOW);
		}

		reason = ff_source_check(cfg, &pkt.src, now, FF_CHK_TOKENS);
		if (reason != FF_STAT_PASS)
			return ff_verdict(cfg, &pkt, reason);

		if (tcp->ack)
			fv->established = 1;

		if (tcp->rst || tcp->fin)
			bpf_map_delete_elem(&flows, &fk);
		else
			fv->last_ns = now;

		return ff_verdict(cfg, &pkt, FF_STAT_PASS);
	}

	if (l3.proto == IPPROTO_ICMP || l3.proto == IPPROTO_ICMPV6) {
		struct icmphdr *icmp = l3.l4;
		bool echo;

		if (cfg->flags & FF_F_DROP_ICMP)
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_ICMP);

		if ((void *)(icmp + 1) > data_end)
			return ff_verdict(cfg, &pkt, FF_STAT_DROP_MALFORMED);

		if (l3.proto == IPPROTO_ICMP)
			echo = icmp->type == ICMP_ECHO ||
			       icmp->type == ICMP_ECHOREPLY;
		else
			echo = icmp->type == ICMPV6_ECHO_REQUEST ||
			       icmp->type == ICMPV6_ECHO_REPLY;

		/*
		 * Non-echo ICMP carries path MTU discovery, which a game server
		 * genuinely needs; rate limit it rather than dropping it.
		 */
		reason = ff_source_check(cfg, &pkt.src, now,
					 echo ? FF_CHK_ICMP : FF_CHK_TOKENS);
		return ff_verdict(cfg, &pkt, reason);
	}

	/* Some other protocol aimed at our address: budget it, then pass. */
	reason = ff_source_check(cfg, &pkt.src, now, FF_CHK_TOKENS);
	return ff_verdict(cfg, &pkt, reason);
}

char LICENSE[] SEC("license") = "GPL";
