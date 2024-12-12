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

int main() {
    int fd;
    struct syscall_counters counters;

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

    return 0;
}