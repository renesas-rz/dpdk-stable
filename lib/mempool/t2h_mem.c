/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Renesas Electronics Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

#include <rte_mempool.h>

#define T2H_MEMPOOL_OPS_NAME	"t2h_mempool"

#define DEVICE_PATH "/dev/t2h_cma_mmap"				/* device name */
#define CMA_MMAP_SET_SIZE _IOW('c', 1, size_t)		/* ioctl command */
#define CMA_MMAP_GET_HANDLE _IOR('c', 2, unsigned long long)	/* ioctl command */

/* ------------------------------------------------------------------------------
   Prototype
------------------------------------------------------------------------------ */
char *t2h_malloc(size_t noOfBytes, unsigned long long *p_addr);
void t2h_mempool_free(struct rte_mempool *mp);


/* ------------------------------------------------------------------------------
   Local Variable
------------------------------------------------------------------------------ */
static int mirror_fd = -1;					// Mirror area descriptor
static void *mapped_mem =  ((void *) -1);	// Mirror area map address
static size_t cur_map_size = 0;


/* ------------------------------------------------------------------------------
   Allocate mempool form CMA
     map_size : The size of the memory to be allocated (in bytes)
------------------------------------------------------------------------------ */
char *t2h_malloc(size_t map_size, unsigned long long *p_addr)
{
	unsigned long long phys_addr;

	/* Open dev file */
	mirror_fd = open(DEVICE_PATH, O_RDWR);
	if (mirror_fd == -1)
	{
		perror("Failed to open device file");
		return NULL;
	}

	/* Specify the map size using ioctl */
	if (ioctl(mirror_fd, CMA_MMAP_SET_SIZE, &map_size) < 0)
	{
		perror("Failed to set mmap size with ioctl");
		close(mirror_fd);
		return NULL;
	}
	printf("Requested mmap size: %zu bytes\n", map_size);

	/* Map memory from the device using mmap */
	mapped_mem = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, mirror_fd, 0);
	if (mapped_mem == MAP_FAILED) {
		perror("Failed to mmap");
		close(mirror_fd);
		return NULL;
	}

	if (ioctl(mirror_fd, CMA_MMAP_GET_HANDLE, &phys_addr) < 0)
	{
		perror("Failed to set mmap size with ioctl");
		close(mirror_fd);
		return NULL;
	}

	*p_addr = phys_addr;
	printf("mmaped cma_handle: 0x%llx, p_addr: 0x%llx\n", phys_addr, *p_addr);

	cur_map_size = map_size;
	return (char *)mapped_mem;

}


/* ------------------------------------------------------------------------------
   Release heap block
     mpFThe address of the mempool to be freed
------------------------------------------------------------------------------ */
void t2h_mempool_free(struct rte_mempool *mp)
{
	(void)mp;

	/* Termination process */
	if (munmap(mapped_mem, cur_map_size) < 0)
	{
		perror("Failed to unmap memory");
	}
	close(mirror_fd);

	printf("Memory unmapped and device closed\n");

	cur_map_size = 0;
	return;
}
