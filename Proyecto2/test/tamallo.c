#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <time.h>

#define TAMALLOC_SYSCALL_NUM 551 // Número de syscall asignado

void *tamalloc(size_t size) {
    return (void *)syscall(TAMALLOC_SYSCALL_NUM, size);
}

void print_memory_usage(pid_t pid, size_t offset) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *file = fopen(path, "r");
    if (!file) {
        perror("Error al abrir /proc/[pid]/status");
        return;
    }

    char line[256];
    size_t vmrss = 0, vmsize = 0;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "VmSize:", 7) == 0) {
            sscanf(line, "VmSize: %zu", &vmsize);
        } else if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %zu", &vmrss);
        }
    }
    fclose(file);

    printf("Offset: %zu MB | VmSize: %zu kB | VmRSS: %zu kB\n", offset / (1024 * 1024), vmsize, vmrss);
}

int main() {
    size_t size = 10 * 1024 * 1024; // Solicitar 4 MB
    pid_t pid = getpid();
    srand(time(NULL));

    printf("PID del proceso: %d\n", pid);
    printf("\nAntes de tamalloc:\n");
    print_memory_usage(pid, 0);

    printf("Llamando a tamalloc para asignar %zu bytes...\n", size);

    void *addr = tamalloc(size);
    if (addr == (void *)-1) {
        perror("Error en tamalloc");
        return 1;
    }

    printf("Memoria asignada en: %p\n", addr);

    printf("Presione enter: ");
    scanf("%*c");

    // Acceder a la memoria y forzar page faults
    printf("\nAccediendo a la memoria asignada...\n");
    char *data = (char *)addr;
    for (size_t i = 0; i < size; i++) { // Accede a cada página (1 MB)
        if (data[i] == 0) { // Verifica si el valor inicial es cero
            data[i] = 'A' + (rand() % 26); // Escribe una letra aleatoria
        }
        print_memory_usage(pid, i); // Mostrar estado de memoria después de cada acceso
    }

    // Liberar memoria
    if (munmap(addr, size) == -1) {
        perror("Error al liberar memoria con munmap");
        return EXIT_FAILURE;
    }

    // Mostrar uso de memoria después de acceder a toda la memoria
    printf("\nDespués de acceder a toda la memoria:\n");
    print_memory_usage(pid, size);

    return 0;
}
