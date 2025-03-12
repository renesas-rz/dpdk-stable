# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation
# Copyright(C) 2024 Renesas Electronics Corporation

extra_flags = []

foreach flag: extra_flags
    if cc.has_argument(flag)
        cflags += flag
    endif
endforeach

sources = files(
        'rte_mempool.c',
        'rte_mempool_ops.c',
        'rte_mempool_ops_default.c',
        'mempool_trace_points.c',
        't2h_mem.c',
)
headers = files(
        'rte_mempool.h',
        'rte_mempool_trace_fp.h',
)
deps += ['ring', 'telemetry']
