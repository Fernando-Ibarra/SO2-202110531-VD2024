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
    char process_name[16]; // Nombre del proceso
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
    int column_widths[] = {10, 25, 25, 15, 10, 20};
    print_table_border(column_widths, 6);
    printf("| %-8s | %-23s | %-23s | %-13s | %-8s | %-18s |\n", 
           "PID", "Memoria Reservada (KB)", "Memoria Comprometida (KB)", 
           "% Comprometido", "OOM Score", "Nombre del Proceso");
    print_table_border(column_widths, 6);
}

void print_table_row(int pid, struct process_mem_info *info) {
    printf("| %-8d | %-23lu | %-23lu | %-13u | %-8d | %-18s |\n", 
           pid, info->reserved_memory, info->committed_memory, 
           info->committed_percent, info->oom_score, info->process_name);
}

void test_all_processes() {
    printf("\nProbando syscall: get_all_process_memory_info\n");

    struct process_mem_info processes[1024]; // Buffer para almacenar la información de procesos
    long result = syscall(SYS_GET_ALL_PROCESS_MEMORY_INFO, processes);

    if (result == 0) {
        printf("Listado de procesos:\n");
        print_table_header();
        for (int i = 0; i < 1024; i++) {
            if (processes[i].reserved_memory == 0) // Fin de lista
                break;

            print_table_row(i, &processes[i]);
        }
        int column_widths[] = {10, 25, 25, 15, 10, 20};
        print_table_border(column_widths, 6);
    } else {
        perror("Error en syscall get_all_process_memory_info");
    }
}

// Función para probar la syscall de un proceso específico
void test_single_process(pid_t pid) {
    printf("\nProbando syscall para PID %d\n", pid);

    struct process_mem_info processes[1024]; // Buffer para almacenar la información de procesos
    long result = syscall(SYS_GET_ALL_PROCESS_MEMORY_INFO, processes);

    if (result == 0) {
        for (int i = 0; i < 1024; i++) {
            if (processes[i].reserved_memory == 0) // Fin de lista
                break;

            if (i == pid) {
                print_table_header();
                printf("PID:\n");
                print_table_row(i, &processes[i]);
                int column_widths[] = {10, 25, 25, 15, 10, 20};
                print_table_border(column_widths, 6);
                return;
            }
        }
        printf("Error: PID no encontrado.\n");
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

    // Probar syscall de un proceso específico
    printf("Ingrese un PID para probar get_single_process_memory_info: ");
    if (scanf("%d", &pid) != 1) {
        printf("Error: Entrada no válida.\n");
        return EXIT_FAILURE;
    }
    test_single_process(pid);

    // Probar syscall de todos los procesos
    test_all_processes();

    return 0;
}