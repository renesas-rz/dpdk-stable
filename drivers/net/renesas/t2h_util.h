/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2024 Renesas Electronics Corporation
 */
#ifndef __T2H_UTIL_H__
#define __T2H_UTIL_H__

#include <stdint.h>

#define BITS_PER_BYTE                   8
#define BITS_PER_TYPE(type)             (sizeof(type) * BITS_PER_BYTE)
#define DIV_ROUND_UP(n, d)              (((n) + (d)-1) / (d))
#define BITS_TO_LONGS(nr)               DIV_ROUND_UP(nr, BITS_PER_TYPE(long))

uint32_t t2h_eqos_get_lastbit_set(uint32_t x);
uint32_t t2h_eqos_vid_crc32_le(uint16_t vid_le);
uint32_t t2h_eqos_bitrev32(uint32_t x);
int t2h_eqos_fls64(uint32_t word);

#endif /* __T2H_UTIL_H__*/
