/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2024 Renesas Electronics Corporation
 */
#ifndef __T2H_UIO_H__
#define __T2H_UIO_H__

#include "t2h_ethdev.h"

/*
 * Name of UIO device. User space t2h will have a corresponding
 * UIO device.
 * Maximum length is #T2H_EQOS_MAX_DEVICE_NAME_LENGTH.
 *
 * @note  Must be kept in sync with t2h kernel driver
 * define #T2H_EQOS_DEVICE_NAME !
 */
#define T2H_EQOS_DEVICE_NAME                    "renesas_rzt2h-eqos-uio"

/*
 * Maximum length for the name of an UIO device file.
 * Device file name format is: /dev/uioX.
 */
#define T2H_EQOS_MAX_DEVICE_FILE_NAME_LENGTH    30

/*
 * Maximum length for the name of an attribute file for an UIO device.
 * Attribute files are exported in sysfs and have the name formatted as:
 * /sys/class/uio/uioX/<attribute_file_name>
 */
#define T2H_EQOS_MAX_ATTR_FILE_NAME             100

/*
 * The id for the mapping used to export t2h registers and BD memory to
 * user space through UIO device.
 */
#define T2H_EQOS_REG_MAP_ID                     0
#define T2H_EQOS_BD_MAP_ID                      1

#define T2H_EQOS_MAP_PAGE_SIZE                  4096

#define T2H_EQOS_MAX_NAME_LENGTH                32
#define T2H_EQOS_DEVICE_HEX                     16
#define T2H_EQOS_DNAME_FIRST                    1
#define T2H_EQOS_DNAME_SEC                      2

struct t2h_uio_job {
	int uio_fd;
	int map_size;
	uint64_t map_addr;
	int uio_minor_number;
};

int t2h_eqos_uio_configure(void);
int config_t2h_eqos_uio(struct renesas_t2h_private *priv);
void t2h_eqos_uio_init(void);
void t2h_eqos_uio_cleanup(struct renesas_t2h_private *priv);

#endif
