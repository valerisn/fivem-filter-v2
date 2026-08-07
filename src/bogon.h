/* SPDX-License-Identifier: GPL-2.0 */
/*
 * IPv4 martian classification. Pure arithmetic with no BPF dependencies, so
 * tests/test_bogon.c can compile and exercise the exact code the filter runs.
 * Getting a shift/constant pair wrong here silently disables a check, which is
 * how the /24 documentation ranges went unenforced for a while.
 */
#ifndef FIVEM_FILTER_BOGON_H
#define FIVEM_FILTER_BOGON_H

#include <linux/types.h>
#include <stdbool.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* src_h is host byte order. */
static __always_inline bool ff_bogon4(__u32 src_h)
{
	if ((src_h >> 24) == 0)			return true;	/* 0.0.0.0/8 */
	if ((src_h >> 24) == 10)		return true;	/* 10.0.0.0/8 */
	if ((src_h >> 22) == 0x00000191)	return true;	/* 100.64.0.0/10 CGNAT */
	if ((src_h >> 24) == 127)		return true;	/* 127.0.0.0/8 */
	if ((src_h >> 16) == 0x0000a9fe)	return true;	/* 169.254.0.0/16 */
	if ((src_h >> 20) == 0x00000ac1)	return true;	/* 172.16.0.0/12 */
	if ((src_h >> 24) == 192 &&
	    ((src_h >> 8) & 0xffff) == 0x0000)	return true;	/* 192.0.0.0/24 */
	if ((src_h >> 8)  == 0x00c00002)	return true;	/* 192.0.2.0/24 */
	if ((src_h >> 16) == 0x0000c0a8)	return true;	/* 192.168.0.0/16 */
	if ((src_h >> 17) == 0x00006309)	return true;	/* 198.18.0.0/15 */
	if ((src_h >> 8)  == 0x00c63364)	return true;	/* 198.51.100.0/24 */
	if ((src_h >> 8)  == 0x00cb0071)	return true;	/* 203.0.113.0/24 */
	if ((src_h >> 28) == 0xe)		return true;	/* 224.0.0.0/4 */
	if ((src_h >> 28) == 0xf)		return true;	/* 240.0.0.0/4 + bcast */
	return false;
}

#endif /* FIVEM_FILTER_BOGON_H */
