#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

// Número de syscall para obtener el resumen global de memoria
#define SYS_GET_SYSTEM_MEMORY_SUMMARY 553

// Estructura para almacenar el resumen global de memoria
struct system_mem_summary {
    unsigned long total_reserved_memory; // MB
    unsigned long total_committed_memory; // MB
};

int main() {
    struct system_mem_summary summary;

    printf("Llamando a la syscall get_system_memory_summary...\n");

    // Llamar a la syscall
    long result = syscall(SYS_GET_SYSTEM_MEMORY_SUMMARY, &summary);

    if (result == 0) {
        printf("Resumen global de memoria:\n");
        printf("  Memoria total reservada: %lu MB\n", summary.total_reserved_memory);
        printf("  Memoria total utilizada: %lu MB\n", summary.total_committed_memory);
    } else {
        perror("Error al llamar a la syscall");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
