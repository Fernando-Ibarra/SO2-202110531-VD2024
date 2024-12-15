#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/sched.h>


struct syscall_counters {
    int open_count;
    int write_count;
    int read_count;
    int fork_count;
};

struct memory_info {
	unsigned long active_pages;
	unsigned long cache_pages;
	unsigned long total_swap;
	unsigned long free_swap;
	unsigned long cache_swap;
	unsigned long free_pages;
	unsigned long total_pages;
};

#define MAX_PROCESSES 15
#define TASK_COMM_LEN 1024

struct process_io_stats {
	pid_t pid;
	char comm[TASK_COMM_LEN];
	unsigned long read_bytes;
	unsigned long write_bytes;
	unsigned long read_bytes_from_disk;
	unsigned long write_bytes_to_disk;
};


struct process_io_stats_response {
	int total_processes;
	struct process_io_stats processes[MAX_PROCESSES];
};


int main() {
    // Structs
    struct syscall_counters counters;
    struct memory_info info;
    struct process_io_stats_response stats;  

    const char *filename = "result.txt";

    FILE *file = fopen(filename, "w");

    if (file == NULL) {
        perror("fopen");
        return 1;
    }
    
    // Syscalls
    int ret = syscall(548, &counters);
    if (ret == -1) {
        perror("syscall");
        return 1;
    }

    printf("******************** Memory Snapshot ********************\n");
    printf("open() was called %d times\n", counters.open_count);
    printf("write() was called %d times\n", counters.write_count);
    printf("read() was called %d times\n", counters.read_count);
    printf("fork() was called %d times\n", counters.fork_count);

    fprintf(file, "******************** Memory Snapshot ********************\n");
    fprintf(file, "open() was called %d times\n", counters.open_count);
    fprintf(file, "write() was called %d times\n", counters.write_count);
    fprintf(file, "read() was called %d times\n", counters.read_count);
    fprintf(file, "fork() was called %d times\n", counters.fork_count);

    int ret2 = syscall(549, &info);
    if (ret2 == -1) {
        perror("syscall");
        return 1;
    }

    printf("******************** Track Syscall Usage ********************\n");
    printf("Active pages: %lu\n", info.active_pages);
    printf("Cache pages: %lu\n", info.cache_pages);
    printf("Free pages: %lu\n", info.free_pages);
    printf("Total pages: %lu\n", info.total_pages);
    printf("Total swap: %lu\n", info.total_swap);
    printf("Free swap: %lu\n", info.free_swap);
    printf("Cache swap: %lu\n", info.cache_swap);
    
    fprintf(file, "******************** Track Syscall Usage ********************\n");
    fprintf(file, "Active pages: %lu\n", info.active_pages);
    fprintf(file, "Cache pages: %lu\n", info.cache_pages);
    fprintf(file, "Free pages: %lu\n", info.free_pages);
    fprintf(file, "Total pages: %lu\n", info.total_pages);
    fprintf(file, "Total swap: %lu\n", info.total_swap);
    fprintf(file, "Free swap: %lu\n", info.free_swap);
    fprintf(file, "Cache swap: %lu\n", info.cache_swap);

    int ret3 = syscall(550, &stats);
    if (ret3 == -1) {
        perror("syscall");
        return 1;
    }

    printf("******************** I/O Throttle ********************\n");
    printf("Total processes: %d\n", stats.total_processes);
    for (int i = 0; i < stats.total_processes; i++) {
        printf("PID: %d\n", stats.processes[i].pid);
        printf("Comm: %s\n", stats.processes[i].comm);
        printf("Read bytes: %lu\n", stats.processes[i].read_bytes);
        printf("Write bytes: %lu\n", stats.processes[i].write_bytes);
        printf("Read bytes from disk: %lu\n", stats.processes[i].read_bytes_from_disk);
        printf("Write bytes to disk: %lu\n", stats.processes[i].write_bytes_to_disk);
    }

    fprintf(file, "******************** I/O Throttle ********************\n");
    fprintf(file, "Total processes: %d\n", stats.total_processes);
    for (int i = 0; i < stats.total_processes; i++) {
        fprintf(file, "PID: %d\n", stats.processes[i].pid);
        fprintf(file, "Comm: %s\n", stats.processes[i].comm);
        fprintf(file, "Read bytes: %lu\n", stats.processes[i].read_bytes);
        fprintf(file, "Write bytes: %lu\n", stats.processes[i].write_bytes);
        fprintf(file, "Read bytes from disk: %lu\n", stats.processes[i].read_bytes_from_disk);
        fprintf(file, "Write bytes to disk: %lu\n\n", stats.processes[i].write_bytes_to_disk);
    }

    return 0;
}