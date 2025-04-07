/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2024 Renesas Electronics Corporation
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include "t2h_pmd_logs.h"
#include "t2h_uio.h"
#include "t2h_regs.h"

/*
 * Prefix path to sysfs directory where UIO device attributes are exported.
 * Path for UIO device X is /sys/class/uio/uioX
 */
#define T2H_UIO_DEVICE_SYS_ATTR_PATH            "/sys/class/uio"

/*
 * Subfolder in sysfs where mapping attributes are exported
 * for each UIO device. Path for mapping Y for device X is:
 * /sys/class/uio/uioX/maps/mapY
 */
#define T2H_UIO_DEVICE_SYS_MAP_ATTR             "maps/map"

/*
 * Name of UIO device file prefix. Each UIO device will have a device file
 * /dev/uioX, where X is the minor device number.
 */
#define T2H_UIO_DEVICE_FILE_NAME                "/dev/uio"

static struct t2h_uio_job renesas_t2h_uio_job;
static int renesas_t2h_count;

static bool
file_name_match_extract(const char filename[], const char match[])
{
	if (strncmp(filename, match, strlen(match)) == 0)
		return true;

	return false;
}

static int
file_read_first_line(const char root[], const char subdir[], const char filename[], char *line)
{
	char absolute_file_name[T2H_EQOS_MAX_ATTR_FILE_NAME];
	int fd = 0, ret = 0;

	/* compose the file name: root/subdir/filename */
	snprintf(absolute_file_name, T2H_EQOS_MAX_ATTR_FILE_NAME, "%s/%s/%s", root, subdir,
		 filename);

	fd = open(absolute_file_name, O_RDONLY);
	if (fd <= 0) {
		T2H_EQOS_PMD_ERR("Error opening file %s", absolute_file_name);
		return -1;
	}

	/* read UIO device name from first line in file */
	ret = read(fd, line, T2H_EQOS_MAX_DEVICE_FILE_NAME_LENGTH);
	if (ret <= 0) {
		T2H_EQOS_PMD_ERR("Error reading file %s", absolute_file_name);
		return ret;
	}
	close(fd);

	/* NULL-ify string */
	line[ret] = '\0';

	return 0;
}

static void *
uio_map_mem(int uio_device_fd, int uio_device_id, int uio_map_id, int *map_size, uint64_t *map_addr)
{
	void *mapped_address	= NULL;
	uint32_t uio_map_size	= 0;
	uint64_t uio_map_p_addr = 0;
	char uio_sys_root[T2H_EQOS_MAX_ATTR_FILE_NAME];
	char uio_sys_map_subdir[T2H_EQOS_MAX_ATTR_FILE_NAME];
	char uio_map_size_str[T2H_EQOS_MAX_DEVICE_FILE_NAME_LENGTH + 1];
	char uio_map_p_addr_str[T2H_EQOS_MAX_DEVICE_FILE_NAME_LENGTH + 1];
	int ret = 0;

	/* Compose string: /sys/class/uio/uioX */
	snprintf(uio_sys_root, sizeof(uio_sys_root), "%s/%s%d", T2H_UIO_DEVICE_SYS_ATTR_PATH, "uio",
		 uio_device_id);
	/* Compose string: maps/mapY */
	snprintf(uio_sys_map_subdir, sizeof(uio_sys_map_subdir), "%s%d",
		 T2H_UIO_DEVICE_SYS_MAP_ATTR, uio_map_id);

	/* Read first (and only) line from file  /sys/class/uio/uioX/maps/mapY/size */
	ret = file_read_first_line(uio_sys_root, uio_sys_map_subdir, "size", uio_map_size_str);
	if (ret < 0) {
		T2H_EQOS_PMD_ERR("file_read_first_line() failed");
		return NULL;
	}
	ret = file_read_first_line(uio_sys_root, uio_sys_map_subdir, "addr", uio_map_p_addr_str);
	if (ret < 0) {
		T2H_EQOS_PMD_ERR("file_read_first_line() failed");
		return NULL;
	}
	/* Read mapping size and physical address expressed in hexa(base 16) */
	uio_map_size   = strtoull(uio_map_size_str, NULL, T2H_EQOS_DEVICE_HEX);
	uio_map_p_addr = strtoull(uio_map_p_addr_str, NULL, T2H_EQOS_DEVICE_HEX);

	if (uio_map_id == 0) {
		/* Map the register address in user space when map_id is 0 */
		mapped_address = mmap(0 , uio_map_size,
				      PROT_READ | PROT_WRITE, MAP_SHARED, uio_device_fd, 0);
	} else {
		/* Map the BD memory in user space */
		mapped_address = mmap(NULL, uio_map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
				      uio_device_fd, (1 * T2H_EQOS_MAP_PAGE_SIZE));
	}

	if (mapped_address == MAP_FAILED) {
		T2H_EQOS_PMD_ERR("Failed to map! errno = %d uio job fd = %d,"
				 "uio device id = %d, uio map id = %d",
				 errno, uio_device_fd, uio_device_id, uio_map_id);
		return NULL;
	}

	/* Save the map size to use it later on for munmap-ing */
	*map_size = uio_map_size;
	*map_addr = uio_map_p_addr;
	T2H_EQOS_PMD_INFO("UIO dev[%d] mapped region [id =%d] size 0x%x at %p", uio_device_id,
			  uio_map_id, uio_map_size, mapped_address);

	return mapped_address;
}

int
config_t2h_eqos_uio(struct renesas_t2h_private *priv)
{
	char uio_device_file_name[T2H_EQOS_MAX_NAME_LENGTH];
	struct t2h_uio_job *uio_job = NULL;

	uio_job = &renesas_t2h_uio_job;

	/* Find UIO device created by T2H-UIO kernel driver */
	snprintf(uio_device_file_name, sizeof(uio_device_file_name), "%s%d",
		 T2H_UIO_DEVICE_FILE_NAME, uio_job->uio_minor_number);

	/* Open device file */
	uio_job->uio_fd = open(uio_device_file_name, O_RDWR);
	if (uio_job->uio_fd < 0) {
		T2H_EQOS_PMD_ERR("Unable to open %s file", uio_device_file_name);
		return -1;
	}
	T2H_EQOS_PMD_INFO("UIO: Open device(%s) file with uio_fd = %d", uio_device_file_name,
			  uio_job->uio_fd);

	priv->uio_fd = uio_job->uio_fd;

	priv->hw_baseaddr_v =
		uio_map_mem(uio_job->uio_fd, uio_job->uio_minor_number, T2H_EQOS_REG_MAP_ID,
			    &uio_job->map_size, &uio_job->map_addr);
	if (priv->hw_baseaddr_v == NULL) {
		T2H_EQOS_PMD_ERR("Memeory map failed");
		return -ENOMEM;
	}

	T2H_EQOS_PMD_INFO("US_UIO: map_addr (0x%lx) , map_size = 0x%x", uio_job->map_addr,
			  uio_job->map_size);

	priv->reg_size = uio_job->map_size;

	priv->bd_addr_v = uio_map_mem(uio_job->uio_fd, uio_job->uio_minor_number,
				      T2H_EQOS_BD_MAP_ID, &uio_job->map_size, &uio_job->map_addr);
	if (priv->bd_addr_v == NULL) {
		T2H_EQOS_PMD_ERR("Memeory map failed");
		return -ENOMEM;
	}

	T2H_EQOS_PMD_INFO("UIO: map_addr (0x%x - %x) , map_size = 0x%x",
			  T2H_EQOS_UPPER_32_BITS(uio_job->map_addr),
			  T2H_EQOS_LOWER_32_BITS(uio_job->map_addr), uio_job->map_size);

	priv->bd_addr_p = (uint32_t)(uio_job->map_addr);
	priv->bd_size	= uio_job->map_size;

	renesas_t2h_count++;
	return 0;
}

int
t2h_eqos_uio_configure(uint32_t reg_id)
{
	char uio_name[T2H_EQOS_MAX_DEVICE_FILE_NAME_LENGTH + 1];
	int uio_minor_number = -1;
	int ret;
	DIR *d = NULL;
	struct dirent *dir;
	char port_name[T2H_EQOS_MAX_DEVICE_FILE_NAME_LENGTH + 1];
	int len;

	snprintf(port_name, sizeof(port_name) - 1, "%s-%d", T2H_EQOS_DEVICE_NAME,
			reg_id);

	T2H_EQOS_PMD_DEBUG("port_name = %s", port_name);

	d = opendir(T2H_UIO_DEVICE_SYS_ATTR_PATH);
	if (d == NULL) {
		T2H_EQOS_PMD_ERR("Error opening directory '%s': %d", T2H_UIO_DEVICE_SYS_ATTR_PATH,
				 errno);
		return -1;
	}

	/* Iterate through all subdirs */
	while ((dir = readdir(d)) != NULL) {
		if (!strncmp(dir->d_name, ".", T2H_EQOS_DNAME_FIRST) ||
		    !strncmp(dir->d_name, "..", T2H_EQOS_DNAME_SEC))
			continue;

		T2H_EQOS_PMD_DEBUG("US_UIO: (%s) file ", dir->d_name);
		if (file_name_match_extract(dir->d_name, "uio")) {
			ret = sscanf(dir->d_name + strlen("uio"), "%d", &uio_minor_number);
			if (ret < 0) {
				T2H_EQOS_PMD_WARN("not find minor number");
			}
			/*
			 * Open file uioX/name and read first line which contains the name for the
			 * device. Based on the name check if this UIO device is for t2h.
			 */
			ret = file_read_first_line(T2H_UIO_DEVICE_SYS_ATTR_PATH, dir->d_name,
						   "name", uio_name);
			if (ret < 0) {
				T2H_EQOS_PMD_INFO("file_read_first_line failed");
				closedir(d);
				return -1;
			}
			len = strlen(uio_name);
			if (uio_name[len - 1] == '\n' || uio_name[len - 1] == '\r')
				uio_name[len - 1] = '\0';

			if (file_name_match_extract(uio_name, port_name)) {
				renesas_t2h_uio_job.uio_minor_number = uio_minor_number;
				return 0;
			}
		}
	}

	closedir(d);
	return -ENOENT;
}

void
t2h_eqos_uio_cleanup(struct renesas_t2h_private *priv)
{
	munmap(priv->hw_baseaddr_v, priv->reg_size);
	munmap(priv->bd_addr_v, priv->bd_size);

	close(priv->uio_fd);
	T2H_EQOS_PMD_DEBUG("munmap success");
}
