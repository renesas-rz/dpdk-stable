# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024 Renesas Electronics Corporation

if not is_linux
    build = false
    reason = 'only supported on linux'
endif

cflags_options = [
        '-DT2H_DEBUG=0'
]

foreach option:cflags_options
        if cc.has_argument(option)
                cflags += option
        endif
endforeach

deps += ['timer']

sources = files(
        't2h_uio.c',
        't2h_ethdev.c',
        't2h_rxtx.c',
        't2h_util.c'
)
