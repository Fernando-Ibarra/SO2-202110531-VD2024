# Proyecto 3

### INSERT
```c
SYSCALL_DEFINE2(so2_add_fernando_memory_limit, pid_t, pid, size_t, memory_limit) {
    struct task_struct *task;
    struct memory_list *entry;
    struct rlimit new_rlim;
    int ret;

    // Validar PID
    if (pid <= 0) {
        pr_err("add_memory_limit: PID inválido.\n");
        return -EINVAL;
    }

    // Validar límite de memoria
    if (memory_limit <= 0) {
        pr_err("add_memory_limit: límite de memoria inválido.\n");
        return -EINVAL;
    }

    // Verificar privilegios de superusuario
    if (!capable(CAP_SYS_ADMIN)) {
        pr_err("add_memory_limit: falta de privilegios de superusuario.\n");
        return -EPERM;
    }

    // Obtener task_struct del proceso
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        pr_err("add_memory_limit: el proceso con PID=%d no existe.\n", pid);
        return -ESRCH;
    }

    // Configurar nuevo límite de memoria
    new_rlim.rlim_cur = memory_limit; // Límite actual
    new_rlim.rlim_max = memory_limit; // Límite máximo
    ret = do_prlimit(task, RLIMIT_AS, &new_rlim, NULL);
    if (ret) {
        rcu_read_unlock();
        pr_err("add_memory_limit: error al establecer el límite de memoria (PID=%d, error=%d).\n", pid, ret);
        return ret;
    }
    rcu_read_unlock();

    // Actualizar o agregar a la lista global
    mutex_lock(&memory_list_mutex);

    // Buscar si el proceso ya está en la lista
    list_for_each_entry(entry, &memory_limitation_list, list) {
        if (entry->node.pid == pid) {
            return -101;
        }
    }

    // Agregar un nuevo nodo si no está en la lista
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        mutex_unlock(&memory_list_mutex);
        pr_err("add_memory_limit: no hay memoria suficiente.\n");
        return -ENOMEM;
    }

    // Inicializar y agregar el nodo
    entry->node.pid = pid;
    entry->node.memory_limit = memory_limit;
    INIT_LIST_HEAD(&entry->list);
    list_add_tail(&entry->list, &memory_limitation_list);

    mutex_unlock(&memory_list_mutex);

    pr_info("add_memory_limit: agregado PID=%d con memory_limit=%zu.\n", pid, memory_limit);
    return 0;
}
```

#### Explicación del código
**Validaciones iniciales**
- PID negativo (-EINVAL): Se valida que pid sea mayor que 0.
- Cantidad de memoria negativa (-EINVAL): Se valida que memory_limit sea mayor que 0.
- Privilegios de superusuario (-EPERM): Se verifica que el usuario tenga permisos administrativos (CAP_SYS_ADMIN).

**Verificación de existencia del proceso**
- Se usa find_vpid y pid_task para verificar si el proceso con el PID especificado existe.
- Si no existe, se retorna -ESRCH.

**Configuración del nuevo límite de memoria**
- Se crea una estructura rlimit con el límite actual y máximo igual a memory_limit.
- Se utiliza do_prlimit para establecer el límite de memoria (RLIMIT_AS) del proceso.

**Actualización o inserción en la lista global**
- Se bloquea la lista global con mutex_lock para buscar si el proceso ya está en la lista memory_limitation_list.
- Si ya está en la lista, se retorna -101.

**Agregación de un nuevo nodo**
- Si el proceso no está en la lista, se crea un nuevo nodo memory_list con kmalloc.
- Se inicializa el nodo con el PID y el límite de memoria.

**Inserción en la lista**
- Se inicializa la lista del nodo con INIT_LIST_HEAD.
- Se agrega el nodo a la lista global memory_limitation_list con list_add_tail.

**Retorno de la syscall**
- Devuelve 0 en caso de éxito.

### GET
```c
SYSCALL_DEFINE3(so2_get_fernando_memory_limits, struct memory_limitation __user *, u_processes_buffer, size_t, max_entries, int __user *, processes_returned) {
    struct memory_list *entry;
    size_t count = 0;
    int ret;

    // Validar punteros de espacio de usuario
    if (!u_processes_buffer || !processes_returned) {
        pr_err("get_memory_limits: punteros inválidos.\n");
        return -EINVAL;
    }

    // Validar max_entries
    if (max_entries <= 0) {
        pr_err("get_memory_limits: max_entries debe ser mayor a 0.\n");
        return -EINVAL;
    }

    // Bloquear la lista global para accederla de manera segura
    mutex_lock(&memory_list_mutex);

    // Recorrer la lista global y copiar los datos al buffer del usuario
    list_for_each_entry(entry, &memory_limitation_list, list) {
        if (count >= max_entries) {
            break; // Si alcanzamos el límite del buffer, salimos
        }

        // Copiar un elemento al buffer de espacio de usuario
        ret = copy_to_user(&u_processes_buffer[count], &entry->node, sizeof(struct memory_limitation));
        if (ret != 0) {
            mutex_unlock(&memory_list_mutex);
            pr_err("get_memory_limits: error al copiar al espacio de usuario.\n");
            return -EFAULT;
        }

        count++;
    }

    mutex_unlock(&memory_list_mutex);

    // Establecer el número de procesos devueltos
    if (put_user(count, processes_returned) != 0) {
        pr_err("get_memory_limits: error al escribir el número de procesos retornados.\n");
        return -EFAULT;
    }

    pr_info("get_memory_limits: devueltos %zu procesos limitados.\n", count);
    return 0; // Éxito
}
```

#### Explicación del código
**Validaciones iniciales**
- Punteros inválidos (-EINVAL)
- Se verifica si los punteros u_processes_buffer y processes_returned son nulos.
max_entries inválido (-EINVAL)
- Si max_entries es menor o igual a 0, se devuelve un error.
**Bloqueo de la lista global**
- Se usa mutex_lock para proteger el acceso a la lista global memory_limitation_list.
**Recorrido de la lista**
- Se recorren los elementos de la lista usando list_for_each_entry.
- Si el número de elementos copiados alcanza max_entries, se detiene el recorrido.
**Copia de datos al espacio de usuario**
- Para cada entrada, se copia la información al buffer proporcionado por el usuario mediante copy_to_user.
- Si ocurre un error al copiar, se devuelve -EFAULT.
**Escribir el número de procesos retornados**
- Se usa put_user para escribir en el puntero processes_returned la cantidad de entradas realmente copiadas.
**Retorno de la syscall**
- Devuelve 0 en caso de éxito.

### UPDATE
```c
SYSCALL_DEFINE2(so2_update_fernando_memory_limit, pid_t, process_pid, size_t, memory_limit) {
    struct task_struct *task;
    struct memory_list *entry;
    int process_found = 0;

    // Validar si el PID es negativo
    if (process_pid <= 0) {
        pr_err("update_memory_limit: PID inválido.\n");
        return -EINVAL;
    }

    // Validar si la cantidad de memoria es negativa
    if (memory_limit <= 0) {
        pr_err("update_memory_limit: límite de memoria inválido.\n");
        return -EINVAL;
    }

    // Verificar si el usuario tiene privilegios de superusuario
    if (!capable(CAP_SYS_ADMIN)) {
        pr_err("update_memory_limit: falta de privilegios de superusuario.\n");
        return -EPERM;
    }

    // Verificar si el proceso existe
    rcu_read_lock();
    task = pid_task(find_vpid(process_pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        pr_err("update_memory_limit: el proceso con PID=%d no existe.\n", process_pid);
        return -ESRCH;
    }
    rcu_read_unlock();

    // Bloquear la lista global para buscar y actualizar el proceso
    mutex_lock(&memory_list_mutex);

    // Buscar si el proceso está en la lista
    list_for_each_entry(entry, &memory_limitation_list, list) {
        if (entry->node.pid == process_pid) {
            process_found = 1;

            // Validar si el proceso ya excede el nuevo límite
            if (task->mm && (task->mm->total_vm << PAGE_SHIFT) > memory_limit) {
                mutex_unlock(&memory_list_mutex);
                pr_err("update_memory_limit: el proceso con PID=%d ya excede el nuevo límite.\n", process_pid);
                return -100; // Error personalizado
            }

            // Actualizar el límite en la lista
            entry->node.memory_limit = memory_limit;

            // Actualizar RLIMIT_AS del proceso
            struct rlimit new_rlim = {
                .rlim_cur = memory_limit,
                .rlim_max = memory_limit
            };
            if (do_prlimit(task, RLIMIT_AS, &new_rlim, NULL)) {
                mutex_unlock(&memory_list_mutex);
                pr_err("update_memory_limit: fallo al actualizar RLIMIT_AS para PID=%d.\n", process_pid);
                return -EFAULT;
            }

            pr_info("update_memory_limit: actualizado PID=%d con memory_limit=%zu.\n", process_pid, memory_limit);
            mutex_unlock(&memory_list_mutex);
            return 0; // Éxito
        }
    }

    mutex_unlock(&memory_list_mutex);

    // Si el proceso no está en la lista
    pr_err("update_memory_limit: el proceso con PID=%d no está en la lista.\n", process_pid);
    return -102; // Error personalizado
}
```

#### Explicación del código

**Validaciones iniciales**
- PID negativo (-EINVAL): Se valida que process_pid sea mayor que 0.
- Cantidad de memoria negativa (-EINVAL): Se valida que memory_limit sea mayor que 0.
- Privilegios de superusuario (-EPERM): Se verifica que el usuario tenga permisos administrativos (CAP_SYS_ADMIN).

**Verificación de existencia del proceso**
- Se usa find_vpid y pid_task para verificar si el proceso con el PID especificado existe.
Si no existe, se retorna -ESRCH.

**Acceso a la lista global**
- Se bloquea la lista global con mutex_lock para buscar si el proceso está en la lista memory_limitation_list.
- Si el proceso no está en la lista, se retorna -102.

**Validación de límite excedido**
- Se compara el uso actual de memoria del proceso (total_vm en páginas convertido a bytes) con el nuevo límite solicitado.
Si ya excede el límite, se retorna -100.

**Actualización del límite**
- El límite en la lista se actualiza directamente.
- También se actualiza el límite del proceso (RLIMIT_AS) utilizando do_prlimit.

### DELETE
```c
SYSCALL_DEFINE1(so2_remove_fernando_memory_limit, pid_t, process_pid) {
    struct task_struct *task;
    struct memory_list *entry, *tmp;

    // Validar si el PID es negativo
    if (process_pid <= 0) {
        pr_err("remove_memory_limit: PID inválido.\n");
        return -EINVAL;
    }

    // Verificar si el usuario tiene privilegios de superusuario
    if (!capable(CAP_SYS_ADMIN)) {
        pr_err("remove_memory_limit: falta de privilegios de superusuario.\n");
        return -EPERM;
    }

    // Verificar si el proceso existe
    rcu_read_lock();
    task = pid_task(find_vpid(process_pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        pr_err("remove_memory_limit: el proceso con PID=%d no existe.\n", process_pid);
        return -ESRCH;
    }
    rcu_read_unlock();

    // Bloquear la lista global para buscar y eliminar el proceso
    mutex_lock(&memory_list_mutex);

    // Buscar si el proceso está en la lista
    list_for_each_entry_safe(entry, tmp, &memory_limitation_list, list) {
        if (entry->node.pid == process_pid) {
            // Eliminar el límite de memoria del proceso
            struct rlimit new_rlim = {
                .rlim_cur = RLIM_INFINITY, // Sin límite
                .rlim_max = RLIM_INFINITY  // Sin límite
            };

            if (do_prlimit(task, RLIMIT_AS, &new_rlim, NULL)) {
                mutex_unlock(&memory_list_mutex);
                pr_err("remove_memory_limit: fallo al eliminar RLIMIT_AS para PID=%d.\n", process_pid);
                return -EFAULT;
            }

            // Eliminar la entrada de la lista
            list_del(&entry->list);
            kfree(entry);

            pr_info("remove_memory_limit: eliminado PID=%d de la lista y límites de memoria.\n", process_pid);
            mutex_unlock(&memory_list_mutex);
            return 0; // Éxito
        }
    }

    mutex_unlock(&memory_list_mutex);

    // Si el proceso no está en la lista
    pr_err("remove_memory_limit: el proceso con PID=%d no está en la lista.\n", process_pid);
    return -102; // Error personalizado
}
```

#### Explicación del código
**Validaciones iniciales**
- PID negativo (-EINVAL): Se valida que process_pid sea mayor que 0.
- Privilegios de superusuario (-EPERM): Se verifica que el usuario tenga permisos administrativos (CAP_SYS_ADMIN).

**Verificación de existencia del proceso**
- Se usa find_vpid y pid_task para verificar si el proceso con el PID especificado existe.
- Si no existe, se retorna -ESRCH.

**Acceso a la lista global**
- Se bloquea la lista global con mutex_lock para buscar si el proceso está en la lista memory_limitation_list.
- Si no está, se retorna -102.

**Eliminación del límite de memoria**
- Se usa do_prlimit para restablecer el límite de memoria (RLIMIT_AS) del proceso a RLIM_INFINITY, lo que significa sin límites.

**Eliminación de la entrada de la lista**
- Si el proceso se encuentra en la lista, se elimina con list_del y se libera la memoria asociada con kfree.


## Cronograma
| Dia | Descripción | 
| --- | --- |
| 1 | Inicio del proyecto |
| 2 | Syscall 1 |
| 3 | Syscall 2, 3 y 4 |
| 4 | Documentacion y test |


## Errores
| Error | Descripción | Solucion |
| --- | --- | --- |
| Compilacion | Durante la compilación se mostraba un warning acerca sobre que no se encontrab ala carpeta include en la carpeta del proyecto. | Se solucionó agregando la carpeta include en la carpeta del proyecto. |
| do_prlimit | Al intentar compilar el código, se mostraba un error en la función do_prlimit. | Se solucionó agregando la librería <linux/prlimit.h> en el archivo fuente y la funcion |


## Comentario