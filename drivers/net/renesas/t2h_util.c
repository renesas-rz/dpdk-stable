/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2024 Renesas Electronics Corporation
 */

#include "t2h_util.h"
#include "t2h_pmd_logs.h"

/* VLAN Identifier */
#define VLAN_VID_MASK 0x0fff

inline uint32_t
t2h_eqos_get_lastbit_set(uint32_t x)
{
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xffff0000)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000)) {
		x <<= 1;
		r -= 1;
	}

	return r;
}

uint32_t
t2h_eqos_vid_crc32_le(uint16_t vid_le)
{
	/* CRCPOLY_LE */
	uint32_t poly	  = 0xedb88320;
	uint32_t crc	  = ~0;
	uint32_t temp	  = 0;
	uint8_t *data	  = (uint8_t *)&vid_le;
	uint8_t data_byte = 0;
	int i, bits;

	bits = t2h_eqos_get_lastbit_set(VLAN_VID_MASK);
	for (i = 0; i < bits; i++) {
		if ((i % 8) == 0)
			data_byte = data[i / 8];

		temp = ((crc & 1) ^ data_byte) & 1;
		crc >>= 1;
		data_byte >>= 1;

		if (temp)
			crc ^= poly;
	}

	return crc;
}

uint32_t
t2h_eqos_bitrev32(uint32_t x)
{
	x = (x >> 16) | (x << 16);
	x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));
	x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
	x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
	x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));

	return x;
}

int
t2h_eqos_fls64(uint32_t word)
{
	return (64 - __builtin_clzl(word)) - 1;
}
