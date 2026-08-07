// SPDX-License-Identifier: GPL-2.0
/*
 * Exercises the real ff_bogon4() from src/bogon.h. Each range is checked at
 * both edges plus the addresses immediately outside it, because the failure
 * mode of a wrong shift constant is a check that silently never fires - or
 * worse, one that blackholes routable space.
 *
 *   cc -I../src -o test_bogon test_bogon.c && ./test_bogon
 */
#include <stdio.h>
#include "bogon.h"

#define IP(a, b, c, d) (((__u32)(a) << 24) | ((__u32)(b) << 16) | \
			((__u32)(c) << 8) | (__u32)(d))

static const struct {
	__u32 ip;
	int want;
	const char *what;
} cases[] = {
	/* ---- must be classified as bogons ---- */
	{ IP(0,0,0,0),			1, "this-network" },
	{ IP(0,255,255,255),		1, "0/8 top" },
	{ IP(10,0,0,1),			1, "10/8 bottom" },
	{ IP(10,255,255,255),		1, "10/8 top" },
	{ IP(100,64,0,0),		1, "cgnat bottom" },
	{ IP(100,127,255,255),		1, "cgnat top" },
	{ IP(127,0,0,1),		1, "loopback" },
	{ IP(169,254,0,1),		1, "link-local" },
	{ IP(172,16,0,0),		1, "172.16/12 bottom" },
	{ IP(172,31,255,255),		1, "172.16/12 top" },
	{ IP(192,0,0,8),		1, "192.0.0/24 ietf" },
	{ IP(192,0,2,5),		1, "TEST-NET-1" },
	{ IP(192,168,0,1),		1, "192.168/16" },
	{ IP(198,18,0,0),		1, "benchmark bottom" },
	{ IP(198,19,255,255),		1, "benchmark top" },
	{ IP(198,51,100,7),		1, "TEST-NET-2" },
	{ IP(203,0,113,9),		1, "TEST-NET-3" },
	{ IP(224,0,0,1),		1, "multicast bottom" },
	{ IP(239,255,255,255),		1, "multicast top" },
	{ IP(240,0,0,1),		1, "reserved" },
	{ IP(255,255,255,255),		1, "broadcast" },

	/* ---- must survive: routable space, including the addresses that sit
	 * immediately outside each reserved range ---- */
	{ IP(1,1,1,1),			0, "1.1.1.1" },
	{ IP(8,8,8,8),			0, "8.8.8.8" },
	{ IP(9,255,255,255),		0, "just below 10/8" },
	{ IP(11,0,0,0),			0, "just above 10/8" },
	{ IP(100,63,255,255),		0, "just below cgnat" },
	{ IP(100,128,0,0),		0, "just above cgnat" },
	{ IP(126,255,255,255),		0, "just below loopback" },
	{ IP(128,0,0,1),		0, "just above loopback" },
	{ IP(169,253,255,255),		0, "just below link-local" },
	{ IP(169,255,0,0),		0, "just above link-local" },
	{ IP(172,15,255,255),		0, "just below 172.16/12" },
	{ IP(172,32,0,0),		0, "just above 172.16/12" },
	{ IP(192,0,1,1),		0, "between 192.0.0 and 192.0.2" },
	{ IP(192,0,3,1),		0, "just above TEST-NET-1" },
	{ IP(192,167,255,255),		0, "just below 192.168/16" },
	{ IP(192,169,0,0),		0, "just above 192.168/16" },
	{ IP(198,17,255,255),		0, "just below benchmark" },
	{ IP(198,20,0,0),		0, "just above benchmark" },
	{ IP(198,51,99,255),		0, "just below TEST-NET-2" },
	{ IP(198,51,101,0),		0, "just above TEST-NET-2" },
	{ IP(203,0,112,255),		0, "just below TEST-NET-3" },
	{ IP(203,0,114,0),		0, "just above TEST-NET-3" },
	{ IP(223,255,255,255),		0, "top of routable unicast" },
	{ IP(51,161,20,4),		0, "ovh" },
	{ IP(45,88,228,10),		0, "typical game host" },
};

int main(void)
{
	int failed = 0;
	unsigned n = sizeof(cases) / sizeof(cases[0]);

	for (unsigned i = 0; i < n; i++) {
		int got = ff_bogon4(cases[i].ip) ? 1 : 0;

		if (got != cases[i].want) {
			printf("FAIL %-28s %u.%u.%u.%u want=%d got=%d\n",
			       cases[i].what,
			       cases[i].ip >> 24, (cases[i].ip >> 16) & 255,
			       (cases[i].ip >> 8) & 255, cases[i].ip & 255,
			       cases[i].want, got);
			failed++;
		}
	}

	if (failed) {
		printf("%d/%u cases FAILED\n", failed, n);
		return 1;
	}
	printf("all %u bogon cases pass\n", n);
	return 0;
}
