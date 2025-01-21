/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2024 Renesas Electronics Corporation
 */
#ifndef __T2H_ETHDEV_H__
#define __T2H_ETHDEV_H__

#include <rte_ethdev.h>
#include <rte_io.h>

#include "t2h_regs.h"
#include "t2h_util.h"

#define BITS_PER_LONG                           (__SIZEOF_LONG__ * 8)
#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

#endif /*__T2H_ETHDEV_H__*/
