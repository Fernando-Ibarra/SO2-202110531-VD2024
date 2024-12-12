#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>


struct syscall_counters {
    int open_count;
    int write_count;
    int read_count;
    int fork_count;
};

struct memory_info {
	unsigned long active_pages;
	unsigned long cache_pages;
	unsigned long swap_pages;
	unsigned long free_pages;
	unsigned long total_pages;
};

int main() {
    int fd;
    struct syscall_counters counters;
    struct memory_info info;

    fd = open("/etc/passwd", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    printf("File opened successfully\n");

    close(fd);

    fd = open("/etc/hostname", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    printf("File opened successfully\n");

    close(fd);

    int ret = syscall(548, &counters);
    if (ret == -1) {
        perror("syscall");
        return 1;
    }

    printf("open() was called %d times\n", counters.open_count);
    printf("write() was called %d times\n", counters.write_count);
    printf("read() was called %d times\n", counters.read_count);
    printf("fork() was called %d times\n", counters.fork_count);

    int ret2 = syscall(549, &info);
    if (ret2 == -1) {
        perror("syscall");
        return 1;
    }

    printf("Active pages: %lu\n", info.active_pages);
    printf("Cache pages: %lu\n", info.cache_pages);
    printf("Swap pages: %lu\n", info.swap_pages);
    printf("Free pages: %lu\n", info.free_pages);
    printf("Total pages: %lu\n", info.total_pages);

    return 0;
}