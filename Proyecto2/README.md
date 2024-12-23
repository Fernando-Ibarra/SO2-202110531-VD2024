# Proyecto 2

Enrique Fernando Gaitán Ibarra
202110531

## Tamalloc con lazy-zeroing
```c
SYSCALL_DEFINE1(get_addr_tamalloc, size_t, size) {
    unsigned long addr;
    size_t aligned_size;

    if (size == 0 || size > TASK_SIZE)
        return -EINVAL;

    aligned_size = PAGE_ALIGN(size);

    addr = vm_mmap(NULL, 0, aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
    if (IS_ERR_VALUE(addr))
        return addr;

    return addr;
}
```
Explicación:
1. **Validación del Tamaño de Memoria**:
    - Si el tamaño solicitado ```(size)``` es igual a 0 o mayor que el límite permitido para el proceso ```(TASK_SIZE)```, devuelve el error -EINVAL
2. **Alineación del Tamaño de Memoria**:
    - Se ajusta el tamaño solicitado al siguiente múltiplo del tamaño de página del sistema utilizando la macro PAGE_ALIGN.
3. **Asignación de Memoria**:
    - Llama a ```vm_mmap``` para asignar memoria virtual. Los parámetros clave son:
        - ```NULL```: El kernel decide la dirección base.
        - ```0```: El offset inicial.
        - ```aligned_size```: Tamaño alineado.
        - ```PROT_READ | PROT_WRITE```: Permisos de lectura y escritura..
        - ```MAP_PRIVATE | MAP_ANONYMOUS```: Crea un mapeo privado sin archivo asociado.
        - ```0```: Sin descriptor de archivo.
4. **Manejo de Errores**:
    - Si ```vm_mmap``` devuelve un valor de error (IS_ERR_VALUE), se retorna directamente.
5. **Retorno Exitoso**:
    - Si la asignación es exitosa, retorna la dirección virtual asignada al espacio de usuario.

## Recolección de estadísticas de asignación de memoria
```c
SYSCALL_DEFINE1(get_all_pid_stats, struct process_mem_info __user *, user_info) {
    struct task_struct *iter_task;
    struct process_mem_info temp_info;
    struct process_mem_info __user *user_ptr = user_info;

    rcu_read_lock();
    for_each_process(iter_task) {
        struct mm_struct *mm = get_task_mm(iter_task);
        if (!mm)
            continue;

        temp_info.reserved_memory = mm->total_vm << (PAGE_SHIFT - 10);
        temp_info.committed_memory = mm->hiwater_rss << (PAGE_SHIFT - 10);
        temp_info.committed_percent = temp_info.reserved_memory ?
            (temp_info.committed_memory * 100) / temp_info.reserved_memory : 0;
        temp_info.oom_score = iter_task->signal->oom_score_adj;
        strncpy(temp_info.process_name, iter_task->comm, TASK_COMM_LEN);

        if (copy_to_user(user_ptr, &temp_info, sizeof(temp_info))) {
            mmput(mm);
            rcu_read_unlock();
            return -EFAULT;
        }

        user_ptr++;
        mmput(mm);
    }
    rcu_read_unlock();

    return 0;
}
```
Explicación:
1. **Inicialización de Variables**:
    - ```iter_task```: Puntero para iterar sobre todos los procesos.
    - ```temp_info```: Estructura temporal para almacenar información de cada proceso.
    - ```user_ptr```: Puntero para copiar datos al espacio de usuario
2. **Iteración sobre Procesos**:
    - Utiliza ```for_each_process``` para iterar sobre cada proceso en el sistema
3. **Acceso a la Información de Memoria**:
    - Obtiene la estructura ```mm_struct``` de cada proceso con get_task_mm.
    - Si el proceso no tiene memoria asignada ```(!mm)```, se omite.
4. **Cálculo de Estadísticas:**:
    - **Memoria Reservada**: total_vm convertido de páginas a KB (<< (PAGE_SHIFT - 10))
    - **Memoria Comprometida**: hiwater_rss cconvertido de páginas a KB
    - **Porcentaje de Memoria Comprometida**: Calcula el porcentaje de memoria comprometida respecto a la reservada.
    - **Puntuación OOM**: Ajuste del puntaje de out-of-memory (oom_score_adj)
    - **Nombre del Proceso**: Copiado del nombre corto (comm)
5. **Copia al Espacio de Usuario**:
    - Usa copy_to_user para copiar la información al buffer de usuario.
    - Si falla, se libera mm con mmput y se devuelve -EFAULT.


```c
SYSCALL_DEFINE1(get_all_mem_stats, struct system_mem_summary __user *, user_summary) {
    struct task_struct *task;
    struct system_mem_summary summary = {0};

    rcu_read_lock();
    for_each_process(task) {
        struct mm_struct *mm = get_task_mm(task);
        if (!mm)
            continue;

        summary.total_reserved_memory += mm->total_vm << (PAGE_SHIFT - 10); // Reservado en KB
        summary.total_committed_memory += mm->hiwater_rss << (PAGE_SHIFT - 10); // Committed en KB
        mmput(mm);
    }
    rcu_read_unlock();

    // Convertir a MB
    summary.total_reserved_memory >>= 10;
    summary.total_committed_memory >>= 10;

    if (copy_to_user(user_summary, &summary, sizeof(summary)))
        return -EFAULT;

    return 0;
}
```
Explicación:
1. **Inicialización**:
    - ```summary```: Estructura para almacenar las estadísticas globales de memoria.
    - Los valores iniciales de memoria están en cero
2. **Iteración sobre Procesos**:
    - ```for_each_process``` para recorrer cada proceso en el sistema
3. **Acceso a la Información de Memoria**:
    - Para cada proceso, se obtiene la estructura mm_struct mediante get_task_mm.
    - Si un proceso no tiene memoria asignada (!mm), se omite.
4. **Cálculo de Estadísticas Globales**:
    - **Memoria Reservada**: Se suma el total de memoria virtual ```(total_vm)``` en KB.
    - **Memoria Comprometida**: Se suma el máximo de memoria residente ```(hiwater_rss)``` en KB.
5. **Conversión a MB**:
    - Se convierten los valores acumulados de memoria reservada y comprometida de KB a MB mediante un desplazamiento a la derecha (>>= 10).


## Cronograma
| Fecha | Actividad |
| --- | --- |
| 2024-12-19 | Inicio del Proyecto |
| 2024-12-20 | Tamalloc Beta 1 |
| 2024-12-21 | Tamalloc Beta 2 y Syscalls |
| 2024-12-22 | Finalizacion |

## Errores
1. **Copia incompleta del nombre del proceso**
    - Problema: Al copiar el nombre del proceso (comm), los datos eran incompletos o corruptos debido a un manejo incorrecto de la memoria.
    - Solución: Se utilizó strncpy con el tamaño adecuado (TASK_COMM_LEN) para garantizar la copia segura del nombre.Copia incompleta del nombre del proceso

2. **user_info**:
    - Problema: Al implementar la syscall para obtener información de procesos, apareció un error indicando que user_info no estaba declarado.
    - Solución: Se habia declara mal la syscall y no se habia definido como SYSCALL_DEFINE2 para que recibiera argumentos.