#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

// Números de syscall (modificar según configuración)
#define SYS_GET_ALL_PROCESS_MEMORY_INFO 552
#define SYS_GET_SINGLE_PROCESS_MEMORY_INFO 554

// Estructura para recibir la información de procesos
struct process_mem_info {
    unsigned long reserved_memory; // KB
    unsigned long committed_memory; // KB
    unsigned int committed_percent; // %
    int oom_score; // OOM Score
};

void print_table_border(int column_widths[], int num_columns) {
    for (int i = 0; i < num_columns; i++) {
        printf("+");
        for (int j = 0; j < column_widths[i]; j++) {
            printf("-");
        }
    }
    printf("+\n");
}

void print_table_header() {
    int column_widths[] = {10, 25, 25, 20, 10};
    print_table_border(column_widths, 5);
    printf("| %-8s | %-23s | %-23s | %-18s | %-8s |\n", "PID", "Memoria Reservada (KB)", "Memoria Comprometida (KB)", "% Comprometido", "OOM Score");
    print_table_border(column_widths, 5);
}

void print_table_row(int pid, struct process_mem_info *info) {
    printf("| %-8d | %-23lu | %-23lu | %-18u | %-8d |\n", pid, info->reserved_memory, info->committed_memory, info->committed_percent, info->oom_score);
}

void test_all_processes() {
    printf("\nProbando syscall: get_all_process_memory_info\n");

    // Buffer para almacenar información de múltiples procesos
    struct process_mem_info processes[1024];
    long result = syscall(SYS_GET_ALL_PROCESS_MEMORY_INFO, processes);

    if (result == 0) {
        printf("Listado de procesos:\n");
        print_table_header();
        for (int i = 0; i < 1024; i++) {
            if (processes[i].reserved_memory == 0) // Fin de lista
                break;

            print_table_row(i, &processes[i]);
        }
        int column_widths[] = {10, 25, 25, 20, 10};
        print_table_border(column_widths, 5);
    } else {
        perror("Error en syscall get_all_process_memory_info");
    }
}

void test_single_process(pid_t pid) {
    printf("\nProbando syscall: get_single_process_memory_info para PID %d\n", pid);

    struct process_mem_info info;
    long result = syscall(SYS_GET_SINGLE_PROCESS_MEMORY_INFO, pid, &info);

    if (result == 0) {
        print_table_header();
        print_table_row(pid, &info);
        int column_widths[] = {10, 25, 25, 20, 10};
        print_table_border(column_widths, 5);
    } else {
        if (errno == ESRCH) {
            printf("Error: Proceso con PID %d no encontrado.\n", pid);
        } else if (errno == EINVAL) {
            printf("Error: Memoria no disponible para el proceso con PID %d.\n", pid);
        } else {
            perror("Error en syscall get_single_process_memory_info");
        }
    }
}

int main() {
    pid_t pid;

    printf("Ingrese un PID para probar get_single_process_memory_info: ");
    scanf("%d", &pid);

    test_single_process(pid);
    test_all_processes();

    return 0;
}
