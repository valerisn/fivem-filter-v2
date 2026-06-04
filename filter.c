#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// override any of these with -D at compile time
#ifndef SERVER_IP
#define SERVER_IP        0x7F000001UL
#endif

#ifndef SERVER_PORT
#define SERVER_PORT      30120
#endif

// token bucket: BURST tokens per IP, refilled at 1 per REFILL_NS (default ~200pps)
#ifndef TB_BURST
#define TB_BURST         20
#endif
#ifndef TB_REFILL_NS
#define TB_REFILL_NS     5000000ULL
#endif

#ifndef AMP_LIMIT
#define AMP_LIMIT        512
#endif

// SYNs get a separate, tighter limit so a syn flood doesn't eat the whole bucket
#ifndef SYN_RATE_NS
#define SYN_RATE_NS      100000000ULL
#endif

#ifndef ICMP_RATE_NS
#define ICMP_RATE_NS     1000000000ULL
#endif

#ifndef FLOW_IDLE_NS
#define FLOW_IDLE_NS     120000000000ULL
#endif

#define MAP_BLOCKLIST    131072
#define MAP_ALLOWLIST    131072
#define MAP_RATE         524288
#define MAP_FLOWS        524288
#define MAP_STATS        16

static __always_inline bool is_amp_port(__u16 sport)
{
    switch (sport) {
    case 53:    /* DNS    */
    case 123:   /* NTP    */
    case 161:   /* SNMP   */
    case 389:   /* CLDAP  */
    case 520:   /* RIPv1  */
    case 1900:  /* SSDP   */
    case 5353:  /* mDNS   */
    case 11211: /* Memcached */
    case 27015: /* Source engine */
        return true;
    default:
        return false;
    }
}

// drop spoofed/unroutable sources before doing anything else
static __always_inline bool is_bogon(__u32 src_h)
{
    if ((src_h >> 24) == 0)                      return true; // 0.0.0.0/8
    if ((src_h >> 24) == 10)                     return true; // 10/8
    if ((src_h >> 22) == (0x64400000 >> 22))     return true; // 100.64/10 CGNAT
    if ((src_h >> 24) == 127)                    return true; // loopback
    if ((src_h >> 16) == 0xA9FE)                 return true; // 169.254/16
    if ((src_h >> 20) == (0xAC10 >> 4))          return true; // 172.16/12
    if ((src_h >> 16) == 0xC0A8)                 return true; // 192.168/16
    if ((src_h >> 17) == (0xC6120000 >> 17))     return true; // 198.18/15
    if ((src_h >> 8)  == 0xC6336400)             return true; // 198.51.100/24
    if ((src_h >> 8)  == 0xCB007100)             return true; // 203.0.113/24
    if ((src_h >> 28) == 0xE)                    return true; // multicast
    if ((src_h >> 28) == 0xF)                    return true; // reserved
    if (src_h == 0xFFFFFFFF)                     return true; // broadcast
    return false;
}

struct tb_entry {
    __u64 last_ns;
    __u32 tokens;
    __u8  _pad[4];
};

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  _pad[3];
};

struct flow_val {
    __u64 last_ns;
    __u8  established;
    __u8  _pad[7];
};

enum stat_idx {
    STAT_PASS = 0,
    STAT_DROP_BLOCKLIST,
    STAT_DROP_BOGON,
    STAT_DROP_FRAG,
    STAT_DROP_AMP,
    STAT_DROP_RATE,
    STAT_DROP_SYN_RATE,
    STAT_DROP_ICMP,
    STAT_DROP_TCP_NOFLOW,
    STAT_DROP_TCP_BADFLAGS,
    STAT_DROP_MALFORMED,
    STAT_MAX
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAP_ALLOWLIST);
    __type(key,   __u32);
    __type(value, __u8);
} allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAP_BLOCKLIST);
    __type(key,   __u32);
    __type(value, __u8);
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_RATE);
    __type(key,   __u32);
    __type(value, struct tb_entry);
} rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_RATE);
    __type(key,   __u32);
    __type(value, __u64);
} syn_last SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_RATE);
    __type(key,   __u32);
    __type(value, __u64);
} icmp_last SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_FLOWS);
    __type(key,   struct flow_key);
    __type(value, struct flow_val);
} flows SEC(".maps");

// percpu so we don't need atomics, aggregate in userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key,   __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define COUNT(idx) ({                                           \
    __u32 _k = (idx);                                          \
    __u64 *_v = bpf_map_lookup_elem(&stats, &_k);             \
    if (_v) __sync_fetch_and_add(_v, 1);                       \
})

#define DROP(idx)  ({ COUNT(idx); XDP_DROP; })
#define PASS()     ({ COUNT(STAT_PASS); XDP_PASS; })

static __always_inline bool tb_allow(__u32 src, __u64 now)
{
    struct tb_entry *e = bpf_map_lookup_elem(&rate_map, &src);
    if (!e) {
        struct tb_entry fresh = { .last_ns = now, .tokens = TB_BURST - 1 };
        bpf_map_update_elem(&rate_map, &src, &fresh, BPF_ANY);
        return true;
    }

    __u64 elapsed = now - e->last_ns;
    __u32 new_tokens = (__u32)(elapsed / TB_REFILL_NS);
    if (new_tokens > 0) {
        e->tokens = e->tokens + new_tokens;
        if (e->tokens > TB_BURST)
            e->tokens = TB_BURST;
        e->last_ns = now;
    }

    if (e->tokens == 0)
        return false;

    e->tokens--;
    return true;
}

static __always_inline int parse_eth_ip(void *data, void *data_end,
                                        struct iphdr **ip_out)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        __u8 *vlan = (__u8 *)(eth + 1);
        if (vlan + 4 > (__u8 *)data_end)
            return -1;
        __u16 inner_proto = bpf_ntohs(*(__u16 *)(vlan + 2));
        if (inner_proto != ETH_P_IP)
            return -1;
        *ip_out = (struct iphdr *)(vlan + 4);
    } else if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        *ip_out = (struct iphdr *)(eth + 1);
    } else {
        return -1;
    }

    struct iphdr *ip = *ip_out;
    if ((void *)(ip + 1) > data_end)           return -1;
    if (ip->version != 4)                      return -1;
    if (ip->ihl < 5)                           return -1;
    if ((void *)ip + (ip->ihl * 4) > data_end) return -1;
    if (bpf_ntohs(ip->tot_len) < (ip->ihl * 4)) return -1;

    return 0;
}

static __always_inline bool is_first_fragment(struct iphdr *ip)
{
    __u16 fo = bpf_ntohs(ip->frag_off);
    return (fo & 0x2000) && !(fo & 0x1FFF);
}

static __always_inline bool is_fragment(struct iphdr *ip)
{
    __u16 fo = bpf_ntohs(ip->frag_off);
    return (fo & 0x2000) || (fo & 0x1FFF);
}

static __always_inline struct udphdr *get_udp(struct iphdr *ip, void *data_end)
{
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return NULL;
    if (bpf_ntohs(udp->len) < sizeof(struct udphdr))
        return NULL;
    return udp;
}

static __always_inline struct tcphdr *get_tcp(struct iphdr *ip, void *data_end)
{
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return NULL;
    if (tcp->doff < 5)
        return NULL;
    if ((void *)tcp + (tcp->doff * 4) > data_end)
        return NULL;
    return tcp;
}

static __always_inline struct icmphdr *get_icmp(struct iphdr *ip, void *data_end)
{
    struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
    if ((void *)(icmp + 1) > data_end)
        return NULL;
    return icmp;
}

// catches null scans, xmas scans, syn+fin, etc.
static __always_inline bool tcp_flags_valid(struct tcphdr *tcp)
{
    if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst &&
        !tcp->psh && !tcp->urg)
        return false;
    if (tcp->syn && tcp->fin)  return false;
    if (tcp->syn && tcp->rst)  return false;
    if (tcp->fin && !tcp->ack && !tcp->syn) return false;
    return true;
}

SEC("xdp")
int fivem_filter(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *ip;

    if (parse_eth_ip(data, data_end, &ip) < 0)
        return XDP_PASS;

    __u32 src = ip->saddr;
    __u32 dst = ip->daddr;
    __u64 now = bpf_ktime_get_ns();

    {
        __u8 *v = bpf_map_lookup_elem(&allowlist, &src);
        if (v && *v)
            return PASS();
    }

    {
        __u8 *v = bpf_map_lookup_elem(&blocklist, &src);
        if (v && *v)
            return DROP(STAT_DROP_BLOCKLIST);
    }

    if (is_bogon(bpf_ntohl(src)))
        return DROP(STAT_DROP_BOGON);

    if (dst != bpf_htonl(SERVER_IP))
        return PASS();

    if (is_fragment(ip)) {
        // only the first fragment has L4 headers we can check — drop the rest,
        // attackers love sending crafted non-first frags to bypass port filters
        if (!is_first_fragment(ip))
            return DROP(STAT_DROP_FRAG);
        if (!tb_allow(src, now))
            return DROP(STAT_DROP_RATE);
        return PASS();
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = get_udp(ip, data_end);
        if (!udp)
            return DROP(STAT_DROP_MALFORMED);

        __u16 dport = bpf_ntohs(udp->dest);
        __u16 sport = bpf_ntohs(udp->source);

        if (dport != SERVER_PORT)
            return PASS();

        __u32 pkt_size = (__u32)(data_end - data);
        if (pkt_size > AMP_LIMIT && is_amp_port(sport))
            return DROP(STAT_DROP_AMP);

        if (!tb_allow(src, now))
            return DROP(STAT_DROP_RATE);

        struct flow_key fk = {
            .saddr = src,  .daddr = dst,
            .sport = udp->source, .dport = udp->dest,
            .proto = IPPROTO_UDP,
        };
        struct flow_val fv = { .last_ns = now, .established = 1 };
        bpf_map_update_elem(&flows, &fk, &fv, BPF_ANY);

        return PASS();
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = get_tcp(ip, data_end);
        if (!tcp)
            return DROP(STAT_DROP_MALFORMED);

        if (bpf_ntohs(tcp->dest) != SERVER_PORT)
            return PASS();

        if (!tcp_flags_valid(tcp))
            return DROP(STAT_DROP_TCP_BADFLAGS);

        struct flow_key fk = {
            .saddr = src,  .daddr = dst,
            .sport = tcp->source, .dport = tcp->dest,
            .proto = IPPROTO_TCP,
        };

        if (tcp->syn && !tcp->ack) {
            __u64 *last = bpf_map_lookup_elem(&syn_last, &src);
            if (last && (now - *last) < SYN_RATE_NS)
                return DROP(STAT_DROP_SYN_RATE);
            bpf_map_update_elem(&syn_last, &src, &now, BPF_ANY);

            if (!tb_allow(src, now))
                return DROP(STAT_DROP_RATE);

            struct flow_val fv = { .last_ns = now, .established = 0 };
            bpf_map_update_elem(&flows, &fk, &fv, BPF_ANY);
            return PASS();
        }

        struct flow_val *fv = bpf_map_lookup_elem(&flows, &fk);
        if (!fv)
            return DROP(STAT_DROP_TCP_NOFLOW);

        if ((now - fv->last_ns) > FLOW_IDLE_NS) {
            bpf_map_delete_elem(&flows, &fk);
            return DROP(STAT_DROP_TCP_NOFLOW);
        }

        if (tcp->syn && tcp->ack)
            fv->established = 1;

        if (tcp->rst || tcp->fin)
            bpf_map_delete_elem(&flows, &fk);
        else
            fv->last_ns = now;

        return PASS();
    }

    if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = get_icmp(ip, data_end);
        if (!icmp)
            return DROP(STAT_DROP_MALFORMED);

        if (icmp->type != ICMP_ECHO && icmp->type != ICMP_ECHOREPLY)
            return DROP(STAT_DROP_ICMP);

        __u64 *last = bpf_map_lookup_elem(&icmp_last, &src);
        if (last && (now - *last) < ICMP_RATE_NS)
            return DROP(STAT_DROP_ICMP);
        bpf_map_update_elem(&icmp_last, &src, &now, BPF_ANY);

        return PASS();
    }

    return PASS();
}

char LICENSE[] SEC("license") = "GPL";
