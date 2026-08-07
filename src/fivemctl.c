// SPDX-License-Identifier: GPL-2.0
/*
 * fivemctl - load, tune and observe the fivem-xdp-filter.
 *
 * Maps are pinned under FF_PIN_DIR, so every subcommand other than `load`
 * simply reopens the pins. Nothing here needs the BPF object file except
 * `load` itself.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"

/* Searched in order when --obj is not given, so the tool works the same from
 * a build tree and from an install prefix. */
static const char *const obj_search[] = {
	"build/filter.bpf.o",
	"./filter.bpf.o",
	"/usr/local/lib/fivem-xdp-filter/filter.bpf.o",
	"/usr/lib/fivem-xdp-filter/filter.bpf.o",
};

static const char *find_obj(void)
{
	for (size_t i = 0; i < sizeof(obj_search) / sizeof(obj_search[0]); i++)
		if (!access(obj_search[i], R_OK))
			return obj_search[i];
	return NULL;
}

static const char *const pinned_maps[] = {
	"config", "state", "global", "allowlist", "blocklist",
	"allow_cidr", "block_cidr", "flows", "stats", "events",
};

/* ------------------------------------------------------------------ util */

static void die(const char *fmt, ...)
	__attribute__((format(printf, 1, 2), noreturn));

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("fivemctl: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	exit(1);
}

static __u64 now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* /dev/urandom rather than getrandom(2) so old glibc still builds. */
static int seed_from_urandom(__u32 *out)
{
	FILE *f = fopen("/dev/urandom", "rb");
	size_t n;

	if (!f)
		return -1;
	n = fread(out, sizeof(*out), 1, f);
	fclose(f);
	return n == 1 ? 0 : -1;
}

static int quiet_libbpf(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (lvl == LIBBPF_PRINT_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

static int open_pin(const char *name)
{
	char path[256];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", FF_PIN_DIR, name);
	fd = bpf_obj_get(path);
	if (fd < 0)
		die("cannot open %s (%s). Is the filter loaded?",
		    path, strerror(errno));
	return fd;
}

/* Parse "1.2.3.4", "2001:db8::1", "1.2.3.0/24". Returns prefix length, and
 * fills either an exact key or a CIDR key. */
struct target {
	bool		is_cidr;
	struct ff_addr	exact;
	struct ff_lpm4	cidr;
	char		text[64];
};

static void parse_target(const char *s, struct target *t)
{
	char buf[64], *slash;
	int prefix = -1;

	memset(t, 0, sizeof(*t));
	snprintf(t->text, sizeof(t->text), "%s", s);
	snprintf(buf, sizeof(buf), "%s", s);

	slash = strchr(buf, '/');
	if (slash) {
		*slash++ = '\0';
		prefix = atoi(slash);
	}

	if (strchr(buf, ':')) {
		struct in6_addr a6;

		if (inet_pton(AF_INET6, buf, &a6) != 1)
			die("invalid IPv6 address: %s", s);
		if (prefix >= 0 && prefix < 64)
			die("IPv6 entries are keyed on the /64 prefix; "
			    "a shorter prefix than /64 is not supported");
		memcpy(&t->exact.a[0], &a6.s6_addr[0], 8);
		t->exact.a[3] = FF_AF_INET6;
		return;
	}

	struct in_addr a4;

	if (inet_pton(AF_INET, buf, &a4) != 1)
		die("invalid IPv4 address: %s", s);

	if (prefix >= 0 && prefix < 32) {
		if (prefix < 0 || prefix > 32)
			die("invalid prefix length in %s", s);
		t->is_cidr = true;
		t->cidr.prefixlen = prefix;
		memcpy(t->cidr.addr, &a4.s_addr, 4);
		return;
	}
	t->exact.a[0] = a4.s_addr;
	t->exact.a[3] = FF_AF_INET;
}

static void fmt_addr(const __u32 a[4], __u8 af, char *out, size_t n)
{
	if (af == FF_AF_INET6) {
		struct in6_addr a6;
		char tmp[INET6_ADDRSTRLEN];

		memset(&a6, 0, sizeof(a6));
		memcpy(&a6.s6_addr[0], a, 8);
		inet_ntop(AF_INET6, &a6, tmp, sizeof(tmp));
		snprintf(out, n, "%s/64", tmp);
	} else {
		struct in_addr a4 = { .s_addr = a[0] };

		snprintf(out, n, "%s", inet_ntoa(a4));
	}
}

/* ---------------------------------------------------------------- config */

static void config_defaults(struct ff_config *c)
{
	memset(c, 0, sizeof(*c));
	c->flags = FF_F_ENABLED | FF_F_BOGON | FF_F_STRICT_TCP | FF_F_LOG;
	c->tb_refill_ns		= 5000000ULL;		/* 200 pps sustained */
	c->tb_burst		= 40;
	c->syn_rate_ns		= 100000000ULL;		/* 10 SYN/s per source */
	c->icmp_rate_ns		= 1000000000ULL;	/* 1 echo/s per source */
	c->oob_rate_ns		= 1000000000ULL;	/* 1 query/s per source */
	c->flow_idle_ns		= 120000000000ULL;	/* 120 s */
	c->conn_window_ns	= 60000000000ULL;	/* 60 s */
	c->conn_per_window	= 60;
	c->global_syn_pps	= 20000;
	c->global_oob_pps	= 2000;
	c->amp_limit		= 512;
	c->udp_min_len		= 1;
	c->udp_max_len		= 1400;
	c->log_sample		= 256;
	c->port_lo		= 30120;
	c->port_hi		= 30120;
}

/* Shared between `load` and `config`. Every field is optional; only the ones
 * the user names are touched, so `config` is a true partial update. */
enum {
	OPT_IP = 1000, OPT_IP6, OPT_PORT, OPT_PORT_HI, OPT_AUX_PORT,
	OPT_BURST, OPT_PPS, OPT_SYN_RATE, OPT_ICMP_RATE, OPT_OOB_RATE,
	OPT_CONN_PER_MIN, OPT_GSYN, OPT_GOOB, OPT_AMP, OPT_UDP_MIN,
	OPT_UDP_MAX, OPT_FLOW_IDLE, OPT_LOG_SAMPLE, OPT_GRACE, OPT_MODE,
	OPT_OBJ, OPT_ON, OPT_OFF,
};

static const struct option tune_opts[] = {
	{ "ip",		required_argument, NULL, OPT_IP },
	{ "ip6",	required_argument, NULL, OPT_IP6 },
	{ "port",	required_argument, NULL, OPT_PORT },
	{ "port-hi",	required_argument, NULL, OPT_PORT_HI },
	{ "aux-port",	required_argument, NULL, OPT_AUX_PORT },
	{ "burst",	required_argument, NULL, OPT_BURST },
	{ "pps",	required_argument, NULL, OPT_PPS },
	{ "syn-rate",	required_argument, NULL, OPT_SYN_RATE },
	{ "icmp-rate",	required_argument, NULL, OPT_ICMP_RATE },
	{ "oob-rate",	required_argument, NULL, OPT_OOB_RATE },
	{ "conn-per-min", required_argument, NULL, OPT_CONN_PER_MIN },
	{ "global-syn-pps", required_argument, NULL, OPT_GSYN },
	{ "global-oob-pps", required_argument, NULL, OPT_GOOB },
	{ "amp-limit",	required_argument, NULL, OPT_AMP },
	{ "udp-min",	required_argument, NULL, OPT_UDP_MIN },
	{ "udp-max",	required_argument, NULL, OPT_UDP_MAX },
	{ "flow-idle",	required_argument, NULL, OPT_FLOW_IDLE },
	{ "log-sample",	required_argument, NULL, OPT_LOG_SAMPLE },
	{ "grace",	required_argument, NULL, OPT_GRACE },
	{ "mode",	required_argument, NULL, OPT_MODE },
	{ "obj",	required_argument, NULL, OPT_OBJ },
	{ "on",		required_argument, NULL, OPT_ON },
	{ "off",	required_argument, NULL, OPT_OFF },
	{ "iface",	required_argument, NULL, 'i' },
	{ "help",	no_argument,	   NULL, 'h' },
	{ NULL, 0, NULL, 0 },
};

static const struct {
	const char *name;
	__u32 bit;
} flag_names[] = {
	{ "enabled",	FF_F_ENABLED },
	{ "dry-run",	FF_F_DRY_RUN },
	{ "drop-icmp",	FF_F_DROP_ICMP },
	{ "drop-ipv6",	FF_F_DROP_IPV6 },
	{ "strict-tcp",	FF_F_STRICT_TCP },
	{ "drop-ip-opts", FF_F_DROP_IP_OPTS },
	{ "drop-frags",	FF_F_DROP_FRAGS },
	{ "log",	FF_F_LOG },
	{ "bogon",	FF_F_BOGON },
	{ "lockdown",	FF_F_LOCKDOWN },
	{ "drop-oob",	FF_F_DROP_OOB },
};

static __u32 flag_bit(const char *name)
{
	for (size_t i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); i++)
		if (!strcmp(flag_names[i].name, name))
			return flag_names[i].bit;
	die("unknown flag '%s'", name);
	return 0;
}

struct tune_state {
	const char *iface;
	const char *obj;
	__u32 xdp_mode;
	__u64 grace_sec;
	bool grace_set;
};

/* Applies one parsed option to cfg. Returns false if the option is unknown. */
static bool apply_tune(int opt, const char *arg, struct ff_config *cfg,
		       struct tune_state *ts)
{
	unsigned long long v = arg ? strtoull(arg, NULL, 0) : 0;

	switch (opt) {
	case OPT_IP: {
		struct in_addr a;

		if (inet_pton(AF_INET, arg, &a) != 1)
			die("invalid --ip: %s", arg);
		cfg->v4_addr = a.s_addr;
		break;
	}
	case OPT_IP6: {
		struct in6_addr a;

		if (inet_pton(AF_INET6, arg, &a) != 1)
			die("invalid --ip6: %s", arg);
		memcpy(cfg->v6_addr, a.s6_addr, 16);
		cfg->v6_set = 1;
		break;
	}
	case OPT_PORT:
		cfg->port_lo = (__u16)v;
		if (cfg->port_hi < cfg->port_lo)
			cfg->port_hi = (__u16)v;
		break;
	case OPT_PORT_HI:	cfg->port_hi = (__u16)v; break;
	case OPT_AUX_PORT:	cfg->aux_port = (__u16)v; break;
	case OPT_BURST:		cfg->tb_burst = (__u32)v; break;
	case OPT_PPS:
		if (!v)
			die("--pps must be greater than zero");
		cfg->tb_refill_ns = 1000000000ULL / v;
		break;
	case OPT_SYN_RATE:
		if (!v)
			die("--syn-rate must be greater than zero");
		cfg->syn_rate_ns = 1000000000ULL / v;
		break;
	case OPT_ICMP_RATE:
		if (!v)
			die("--icmp-rate must be greater than zero");
		cfg->icmp_rate_ns = 1000000000ULL / v;
		break;
	case OPT_OOB_RATE:
		if (!v)
			die("--oob-rate must be greater than zero");
		cfg->oob_rate_ns = 1000000000ULL / v;
		break;
	case OPT_CONN_PER_MIN:
		cfg->conn_per_window = (__u32)v;
		cfg->conn_window_ns = 60000000000ULL;
		break;
	case OPT_GSYN:		cfg->global_syn_pps = (__u32)v; break;
	case OPT_GOOB:		cfg->global_oob_pps = (__u32)v; break;
	case OPT_AMP:		cfg->amp_limit = (__u32)v; break;
	case OPT_UDP_MIN:	cfg->udp_min_len = (__u32)v; break;
	case OPT_UDP_MAX:	cfg->udp_max_len = (__u32)v; break;
	case OPT_FLOW_IDLE:	cfg->flow_idle_ns = v * 1000000000ULL; break;
	case OPT_LOG_SAMPLE:	cfg->log_sample = (__u32)v; break;
	case OPT_ON:		cfg->flags |= flag_bit(arg); break;
	case OPT_OFF:		cfg->flags &= ~flag_bit(arg); break;
	case OPT_GRACE:
		ts->grace_sec = v;
		ts->grace_set = true;
		break;
	case OPT_MODE:
		if (!strcmp(arg, "native"))
			ts->xdp_mode = XDP_FLAGS_DRV_MODE;
		else if (!strcmp(arg, "skb") || !strcmp(arg, "generic"))
			ts->xdp_mode = XDP_FLAGS_SKB_MODE;
		else if (!strcmp(arg, "hw") || !strcmp(arg, "offload"))
			ts->xdp_mode = XDP_FLAGS_HW_MODE;
		else if (!strcmp(arg, "auto"))
			ts->xdp_mode = 0;
		else
			die("--mode must be one of: auto, native, skb, hw");
		break;
	case OPT_OBJ:		ts->obj = arg; break;
	case 'i':		ts->iface = arg; break;
	default:
		return false;
	}
	return true;
}

static void config_read(struct ff_config *cfg)
{
	int fd = open_pin("config");
	__u32 zero = 0;

	if (bpf_map_lookup_elem(fd, &zero, cfg))
		die("reading config map: %s", strerror(errno));
	close(fd);
}

static void config_write(const struct ff_config *cfg)
{
	int fd = open_pin("config");
	__u32 zero = 0;

	if (bpf_map_update_elem(fd, &zero, cfg, BPF_ANY))
		die("writing config map: %s", strerror(errno));
	close(fd);
}

static void config_print(const struct ff_config *cfg)
{
	char v6[INET6_ADDRSTRLEN] = "unset";
	struct in_addr a4 = { .s_addr = cfg->v4_addr };
	__u64 now = now_ns();

	if (cfg->v6_set)
		inet_ntop(AF_INET6, cfg->v6_addr, v6, sizeof(v6));

	printf("protecting      %s", cfg->v4_addr ? inet_ntoa(a4) : "any IPv4");
	printf(" / %s\n", v6);
	printf("ports           %u-%u", cfg->port_lo, cfg->port_hi);
	if (cfg->aux_port)
		printf(" (+ tcp %u)", cfg->aux_port);
	printf("\n");
	printf("per-source      %llu pps sustained, burst %u\n",
	       cfg->tb_refill_ns ? 1000000000ULL / cfg->tb_refill_ns : 0,
	       cfg->tb_burst);
	printf("syn / icmp / oob  %llu / %llu / %llu per second per source\n",
	       cfg->syn_rate_ns ? 1000000000ULL / cfg->syn_rate_ns : 0,
	       cfg->icmp_rate_ns ? 1000000000ULL / cfg->icmp_rate_ns : 0,
	       cfg->oob_rate_ns ? 1000000000ULL / cfg->oob_rate_ns : 0);
	printf("global ceilings %u syn/s, %u oob/s\n",
	       cfg->global_syn_pps, cfg->global_oob_pps);
	printf("new conns       %u per %llus per source\n",
	       cfg->conn_per_window, cfg->conn_window_ns / 1000000000ULL);
	printf("udp payload     %u-%u bytes, amp limit %u\n",
	       cfg->udp_min_len, cfg->udp_max_len, cfg->amp_limit);
	printf("flow idle       %llus\n", cfg->flow_idle_ns / 1000000000ULL);
	printf("log sample      1 in %u\n", cfg->log_sample);

	if (cfg->tcp_learn_until_ns > now)
		printf("tcp learning    %llus remaining\n",
		       (cfg->tcp_learn_until_ns - now) / 1000000000ULL);

	printf("flags           ");
	for (size_t i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); i++)
		if (cfg->flags & flag_names[i].bit)
			printf("%s ", flag_names[i].name);
	printf("\n");
}

/* ------------------------------------------------------------------ load */

/* Kernels before 5.11 charge map memory against RLIMIT_MEMLOCK, and the state
 * table alone is 8 MiB. libbpf raises this itself on new enough versions;
 * doing it unconditionally costs nothing. */
static void raise_memlock(void)
{
	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };

	setrlimit(RLIMIT_MEMLOCK, &r);
}

static void ensure_pin_dir(void)
{
	if (mkdir(FF_PIN_DIR, 0700) && errno != EEXIST)
		die("cannot create %s: %s. Is bpffs mounted at /sys/fs/bpf?",
		    FF_PIN_DIR, strerror(errno));
}

static int cmd_load(int argc, char **argv)
{
	struct ff_config cfg;
	struct tune_state ts = { .grace_sec = 30 };
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;
	int ifindex, prog_fd, opt, err;

	config_defaults(&cfg);
	optind = 1;
	while ((opt = getopt_long(argc, argv, "i:h", tune_opts, NULL)) != -1) {
		if (opt == 'h')
			return 1;
		if (!apply_tune(opt, optarg, &cfg, &ts))
			die("unknown option; try `fivemctl help`");
	}

	if (!ts.iface)
		die("load needs -i <interface>");
	ifindex = if_nametoindex(ts.iface);
	if (!ifindex)
		die("no such interface: %s", ts.iface);
	if (!cfg.v4_addr && !cfg.v6_set)
		fprintf(stderr,
			"fivemctl: warning: no --ip given, filtering traffic to "
			"every destination on %s\n", ts.iface);

	/* Randomised per load so nobody can precompute state-table collisions. */
	if (seed_from_urandom(&cfg.hash_seed) < 0)
		cfg.hash_seed = (__u32)now_ns();

	cfg.tcp_learn_until_ns = ts.grace_sec
		? now_ns() + ts.grace_sec * 1000000000ULL : 0;

	if (!ts.obj) {
		ts.obj = find_obj();
		if (!ts.obj)
			die("cannot find filter.bpf.o; build it with `make` or "
			    "point at it with --obj");
	}

	raise_memlock();
	ensure_pin_dir();

	obj = bpf_object__open_file(ts.obj, NULL);
	if (!obj)
		die("cannot open %s: %s", ts.obj, strerror(errno));

	for (size_t i = 0; i < sizeof(pinned_maps) / sizeof(pinned_maps[0]); i++) {
		char path[256];

		map = bpf_object__find_map_by_name(obj, pinned_maps[i]);
		if (!map)
			die("object is missing map '%s'", pinned_maps[i]);
		snprintf(path, sizeof(path), "%s/%s", FF_PIN_DIR, pinned_maps[i]);
		unlink(path);	/* stale pin from a previous load */
		if (bpf_map__set_pin_path(map, path))
			die("cannot set pin path for %s", pinned_maps[i]);
	}

	if (bpf_object__load(obj))
		die("verifier rejected the program (run with LIBBPF_LOG_LEVEL=debug "
		    "for the full log): %s", strerror(errno));

	prog = bpf_object__find_program_by_name(obj, "fivem_filter");
	if (!prog)
		die("object is missing the fivem_filter program");
	prog_fd = bpf_program__fd(prog);

	/* Seed config before attaching so the first packet sees real values. */
	{
		int cfd = bpf_map__fd(bpf_object__find_map_by_name(obj, "config"));
		__u32 zero = 0;

		if (bpf_map_update_elem(cfd, &zero, &cfg, BPF_ANY))
			die("seeding config: %s", strerror(errno));
	}

	err = bpf_xdp_attach(ifindex, prog_fd, ts.xdp_mode, NULL);
	if (err && !ts.xdp_mode) {
		fprintf(stderr,
			"fivemctl: native XDP unavailable, falling back to skb mode\n");
		err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	}
	if (err)
		die("attaching to %s: %s", ts.iface, strerror(-err));

	/* Pinning the program keeps it alive independently of the link. */
	{
		char path[256];

		snprintf(path, sizeof(path), "%s/prog", FF_PIN_DIR);
		unlink(path);
		bpf_obj_pin(prog_fd, path);
	}

	printf("attached to %s\n\n", ts.iface);
	config_print(&cfg);
	if (cfg.flags & FF_F_DRY_RUN)
		printf("\nDRY RUN: nothing will actually be dropped.\n");
	if (ts.grace_sec)
		printf("\nAdopting pre-existing TCP connections for %llus.\n",
		       ts.grace_sec);

	bpf_object__close(obj);
	return 0;
}

static int cmd_unload(int argc, char **argv)
{
	const char *iface = NULL;
	int opt, ifindex;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "i:", tune_opts, NULL)) != -1)
		if (opt == 'i')
			iface = optarg;

	if (!iface)
		die("unload needs -i <interface>");
	ifindex = if_nametoindex(iface);
	if (!ifindex)
		die("no such interface: %s", iface);

	if (bpf_xdp_detach(ifindex, 0, NULL))
		die("detaching from %s: %s", iface, strerror(errno));

	for (size_t i = 0; i < sizeof(pinned_maps) / sizeof(pinned_maps[0]); i++) {
		char path[256];

		snprintf(path, sizeof(path), "%s/%s", FF_PIN_DIR, pinned_maps[i]);
		unlink(path);
	}
	{
		char path[256];

		snprintf(path, sizeof(path), "%s/prog", FF_PIN_DIR);
		unlink(path);
	}
	rmdir(FF_PIN_DIR);

	printf("detached from %s\n", iface);
	return 0;
}

/* ----------------------------------------------------------------- stats */

static void stats_read(__u64 *out)
{
	int fd = open_pin("stats");
	int ncpu = libbpf_num_possible_cpus();
	__u64 *per_cpu;

	if (ncpu < 0)
		die("cannot determine CPU count");
	per_cpu = calloc(ncpu, sizeof(__u64));
	if (!per_cpu)
		die("out of memory");

	for (__u32 i = 0; i < FF_STAT_MAX; i++) {
		__u64 sum = 0;

		if (bpf_map_lookup_elem(fd, &i, per_cpu))
			continue;
		for (int c = 0; c < ncpu; c++)
			sum += per_cpu[c];
		out[i] = sum;
	}
	free(per_cpu);
	close(fd);
}

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static int cmd_stats(int argc, char **argv)
{
	__u64 cur[FF_STAT_MAX] = {}, prev[FF_STAT_MAX] = {};
	bool watch = false, first = true;
	unsigned interval = 1;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--watch") || !strcmp(argv[i], "-w")) {
			watch = true;
			if (i + 1 < argc && argv[i + 1][0] != '-')
				interval = (unsigned)atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--reset")) {
			int fd = open_pin("stats");
			int ncpu = libbpf_num_possible_cpus();
			__u64 *zeros = calloc(ncpu > 0 ? ncpu : 1, sizeof(__u64));

			for (__u32 k = 0; k < FF_STAT_MAX; k++)
				bpf_map_update_elem(fd, &k, zeros, BPF_ANY);
			free(zeros);
			close(fd);
			printf("counters reset\n");
			return 0;
		}
	}

	if (!interval)
		interval = 1;
	signal(SIGINT, on_signal);

	do {
		stats_read(cur);
		if (watch && !first)
			printf("\033[H\033[J");
		printf("%-42s %16s %12s\n", "counter", "total", "per second");
		for (__u32 i = 0; i < FF_STAT_MAX; i++) {
			double rate = watch && !first
				? (double)(cur[i] - prev[i]) / interval : 0.0;

			if (!cur[i] && i != FF_STAT_PASS)
				continue;	/* hide idle counters */
			printf("%-42s %16llu %12.1f\n",
			       ff_stat_names[i], cur[i], rate);
		}
		memcpy(prev, cur, sizeof(prev));
		memset(cur, 0, sizeof(cur));
		first = false;
		if (watch && !stop)
			sleep(interval);
	} while (watch && !stop);

	return 0;
}

/* ------------------------------------------------------------------ list */

static int cmd_list_entry(const char *which, const char *addr,
			  __u64 ttl_sec, bool remove)
{
	bool allow = !strncmp(which, "allow", 5);
	struct ff_listent val = {};
	struct target t;
	int fd;

	parse_target(addr, &t);
	fd = open_pin(t.is_cidr ? (allow ? "allow_cidr" : "block_cidr")
				: (allow ? "allowlist" : "blocklist"));

	if (remove) {
		int err = t.is_cidr ? bpf_map_delete_elem(fd, &t.cidr)
				    : bpf_map_delete_elem(fd, &t.exact);

		if (err)
			die("%s is not in the %s list", addr,
			    allow ? "allow" : "block");
		printf("removed %s from the %s list\n", addr,
		       allow ? "allow" : "block");
	} else {
		int err;

		val.expires_ns = ttl_sec ? now_ns() + ttl_sec * 1000000000ULL : 0;
		err = t.is_cidr
			? bpf_map_update_elem(fd, &t.cidr, &val, BPF_ANY)
			: bpf_map_update_elem(fd, &t.exact, &val, BPF_ANY);
		if (err)
			die("updating map: %s", strerror(errno));
		if (ttl_sec)
			printf("%s %s for %llus\n",
			       allow ? "allowed" : "blocked", addr, ttl_sec);
		else
			printf("%s %s permanently\n",
			       allow ? "allowed" : "blocked", addr);
	}
	close(fd);
	return 0;
}

static void dump_exact(const char *name)
{
	struct ff_addr key = {}, next;
	struct ff_listent val;
	__u64 now = now_ns();
	int fd = open_pin(name);
	bool any = false;

	while (!bpf_map_get_next_key(fd, &key, &next)) {
		char buf[80], ttl[32];

		key = next;
		if (bpf_map_lookup_elem(fd, &key, &val))
			continue;
		fmt_addr(key.a, (__u8)key.a[3], buf, sizeof(buf));
		if (!val.expires_ns)
			snprintf(ttl, sizeof(ttl), "permanent");
		else if (val.expires_ns <= now)
			snprintf(ttl, sizeof(ttl), "expired");
		else
			snprintf(ttl, sizeof(ttl), "%llus left",
				 (val.expires_ns - now) / 1000000000ULL);
		printf("  %-46s %-14s %llu hits\n", buf, ttl, val.hits);
		any = true;
	}
	if (!any)
		printf("  (empty)\n");
	close(fd);
}

static void dump_cidr(const char *name)
{
	struct ff_lpm4 key = {}, next;
	struct ff_listent val;
	__u64 now = now_ns();
	int fd = open_pin(name);
	bool any = false;

	while (!bpf_map_get_next_key(fd, &key, &next)) {
		struct in_addr a;
		char buf[80], ttl[32];

		key = next;
		if (bpf_map_lookup_elem(fd, &key, &val))
			continue;
		memcpy(&a.s_addr, key.addr, 4);
		snprintf(buf, sizeof(buf), "%s/%u", inet_ntoa(a), key.prefixlen);
		if (!val.expires_ns)
			snprintf(ttl, sizeof(ttl), "permanent");
		else if (val.expires_ns <= now)
			snprintf(ttl, sizeof(ttl), "expired");
		else
			snprintf(ttl, sizeof(ttl), "%llus left",
				 (val.expires_ns - now) / 1000000000ULL);
		printf("  %-46s %-14s %llu hits\n", buf, ttl, val.hits);
		any = true;
	}
	if (!any)
		printf("  (empty)\n");
	close(fd);
}

static int cmd_list(int argc, char **argv)
{
	bool want_allow = argc < 2 || !strcmp(argv[1], "allow");
	bool want_block = argc < 2 || !strcmp(argv[1], "block");

	if (want_block) {
		printf("blocklist:\n");
		dump_exact("blocklist");
		dump_cidr("block_cidr");
	}
	if (want_allow) {
		printf("allowlist:\n");
		dump_exact("allowlist");
		dump_cidr("allow_cidr");
	}
	return 0;
}

/* ------------------------------------------------------------------- log */

static int on_event(void *ctx, void *data, size_t len)
{
	const struct ff_event *e = data;
	char src[80], dst[80];
	time_t wall = time(NULL);
	struct tm tm;

	(void)ctx;
	if (len < sizeof(*e))
		return 0;

	fmt_addr(e->saddr, e->af, src, sizeof(src));
	fmt_addr(e->daddr, e->af, dst, sizeof(dst));
	localtime_r(&wall, &tm);

	printf("%02d:%02d:%02d %-10s %s:%u -> %s:%u proto %u len %u %s\n",
	       tm.tm_hour, tm.tm_min, tm.tm_sec,
	       e->dry ? "WOULD-DROP" : "DROP",
	       src, e->sport, dst, e->dport, e->proto, e->pkt_len,
	       e->reason < FF_STAT_MAX ? ff_stat_names[e->reason] : "?");
	fflush(stdout);
	return 0;
}

static int cmd_log(int argc, char **argv)
{
	struct ring_buffer *rb;
	int fd = open_pin("events");

	(void)argc; (void)argv;
	rb = ring_buffer__new(fd, on_event, NULL, NULL);
	if (!rb)
		die("cannot open the event ring buffer");

	signal(SIGINT, on_signal);
	fprintf(stderr, "streaming sampled drops (ctrl-c to stop)\n");
	while (!stop) {
		int err = ring_buffer__poll(rb, 200);

		if (err < 0 && err != -EINTR)
			break;
	}
	ring_buffer__free(rb);
	close(fd);
	return 0;
}

/* ---------------------------------------------------------------- config */

static int cmd_config(int argc, char **argv)
{
	struct ff_config cfg;
	struct tune_state ts = {};
	bool changed = false;
	int opt;

	config_read(&cfg);

	optind = 1;
	while ((opt = getopt_long(argc, argv, "i:h", tune_opts, NULL)) != -1) {
		if (!apply_tune(opt, optarg, &cfg, &ts))
			die("unknown option; try `fivemctl help`");
		changed = true;
	}

	if (ts.grace_set)
		cfg.tcp_learn_until_ns = ts.grace_sec
			? now_ns() + ts.grace_sec * 1000000000ULL : 0;

	if (changed) {
		config_write(&cfg);
		printf("config updated\n\n");
	}
	config_print(&cfg);
	return 0;
}

static int cmd_status(int argc, char **argv)
{
	struct ff_config cfg;
	__u64 s[FF_STAT_MAX] = {};

	(void)argc; (void)argv;
	config_read(&cfg);
	config_print(&cfg);
	stats_read(s);

	__u64 dropped = 0;

	for (__u32 i = 0; i < FF_STAT_MAX; i++)
		if (i != FF_STAT_PASS && i != FF_STAT_DRYRUN_PASS)
			dropped += s[i];

	printf("\npassed %llu, %s %llu\n", s[FF_STAT_PASS],
	       (cfg.flags & FF_F_DRY_RUN) ? "would have dropped" : "dropped",
	       dropped);
	return 0;
}

/* ------------------------------------------------------------------ main */

static void usage(void)
{
	printf(
"fivemctl - control the fivem XDP filter\n"
"\n"
"  load -i IFACE --ip A.B.C.D [--port 30120] [tunables]\n"
"  unload -i IFACE\n"
"  status\n"
"  stats [--watch [SEC]] [--reset]\n"
"  config [tunables]              show or partially update the live config\n"
"  block  <ip|cidr> [--ttl SEC]\n"
"  unblock <ip|cidr>\n"
"  allow  <ip|cidr> [--ttl SEC]\n"
"  unallow <ip|cidr>\n"
"  list [block|allow]\n"
"  log                            stream sampled drops\n"
"\n"
"Tunables (accepted by both load and config):\n"
"  --ip A.B.C.D --ip6 ADDR --port N --port-hi N --aux-port N\n"
"  --pps N            sustained packets/sec per source\n"
"  --burst N          per-source burst allowance\n"
"  --syn-rate N       SYN/sec per source\n"
"  --icmp-rate N      ICMP echo/sec per source\n"
"  --oob-rate N       getinfo/getstatus queries per sec per source\n"
"  --conn-per-min N   new TCP connections per minute per source\n"
"  --global-syn-pps N --global-oob-pps N    box-wide ceilings (0 = off)\n"
"  --amp-limit N --udp-min N --udp-max N --flow-idle SEC --log-sample N\n"
"  --grace SEC        adopt pre-existing TCP connections for this long\n"
"  --mode auto|native|skb|hw    --obj PATH\n"
"  --on FLAG / --off FLAG       flags: enabled dry-run drop-icmp drop-ipv6\n"
"                               strict-tcp drop-ip-opts drop-frags log bogon\n"
"                               lockdown drop-oob\n"
"\n"
"Examples:\n"
"  fivemctl load -i eth0 --ip 203.0.113.10 --port 30120 --aux-port 40120\n"
"  fivemctl load -i eth0 --ip 203.0.113.10 --on dry-run   # observe first\n"
"  fivemctl config --pps 400 --off dry-run\n"
"  fivemctl block 198.51.100.0/24 --ttl 3600\n"
"  fivemctl stats --watch 2\n");
}

int main(int argc, char **argv)
{
	const char *cmd;

	libbpf_set_print(quiet_libbpf);

	if (argc < 2) {
		usage();
		return 1;
	}
	cmd = argv[1];

	if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
		usage();
		return 0;
	}
	if (!strcmp(cmd, "load"))
		return cmd_load(argc - 1, argv + 1);
	if (!strcmp(cmd, "unload"))
		return cmd_unload(argc - 1, argv + 1);
	if (!strcmp(cmd, "status"))
		return cmd_status(argc - 1, argv + 1);
	if (!strcmp(cmd, "stats"))
		return cmd_stats(argc - 1, argv + 1);
	if (!strcmp(cmd, "config"))
		return cmd_config(argc - 1, argv + 1);
	if (!strcmp(cmd, "log"))
		return cmd_log(argc - 1, argv + 1);
	if (!strcmp(cmd, "list"))
		return cmd_list(argc - 1, argv + 1);

	if (!strcmp(cmd, "block") || !strcmp(cmd, "allow") ||
	    !strcmp(cmd, "unblock") || !strcmp(cmd, "unallow")) {
		bool remove = cmd[0] == 'u';
		const char *which = remove ? cmd + 2 : cmd;
		__u64 ttl = 0;

		if (argc < 3)
			die("%s needs an address or CIDR", cmd);
		for (int i = 3; i < argc; i++)
			if (!strcmp(argv[i], "--ttl") && i + 1 < argc)
				ttl = strtoull(argv[++i], NULL, 0);
		return cmd_list_entry(which, argv[2], ttl, remove);
	}

	fprintf(stderr, "fivemctl: unknown command '%s'\n\n", cmd);
	usage();
	return 1;
}
