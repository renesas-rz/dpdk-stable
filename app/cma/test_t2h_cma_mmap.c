#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

#define DEVICE_PATH "/dev/t2h_cma_mmap"
#define CMA_MMAP_SET_SIZE _IOW('c', 1, size_t)	/* ioctl command */

int main(int argc, char *argv[])
{
	int fd;
	size_t map_size;
	void *mapped_mem;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <map_size>\n", argv[0]);
		return EXIT_FAILURE;
	}

	map_size = strtoul(argv[1], NULL, 0);

	/* Open device file */
	fd = open(DEVICE_PATH, O_RDWR);
	if (fd < 0)
	{
		perror("Failed to open device file");
		return EXIT_FAILURE;
	}

	/* Specify the map size using ioctl */
	if (ioctl(fd, CMA_MMAP_SET_SIZE, &map_size) < 0)
	{
		perror("Failed to set mmap size with ioctl");
		close(fd);
		return EXIT_FAILURE;
	}
	printf("Requested mmap size: %zu bytes\n", map_size);

	/* Map memory from the device using mmap */
	mapped_mem = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mapped_mem == MAP_FAILED) {
		perror("Failed to mmap");
		close(fd);
		return EXIT_FAILURE;
	}

	/* Access the mapped memory and verify data writing and reading */
	snprintf((char *)mapped_mem, map_size, "Accessed from userspace!");
	printf("Written to mapped memory: %s\n", (char *)mapped_mem);

	/* Termination process */
	if (munmap(mapped_mem, map_size) < 0)
	{
		perror("Failed to unmap memory");
	}
	close(fd);

	printf("Memory unmapped and device closed\n");
	return EXIT_SUCCESS;
}
