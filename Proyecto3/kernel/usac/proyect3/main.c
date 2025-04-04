#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/resource.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/utsname.h>
#include <linux/mman.h>
#include <linux/reboot.h>
#include <linux/prctl.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/ksm.h>
#include <linux/perf_event.h>
#include <linux/resource.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/capability.h>
#include <linux/device.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/posix-timers.h>
#include <linux/security.h>
#include <linux/random.h>
#include <linux/suspend.h>
#include <linux/tty.h>
#include <linux/signal.h>
#include <linux/cn_proc.h>
#include <linux/getcpu.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/seccomp.h>
#include <linux/cpu.h>
#include <linux/personality.h>
#include <linux/ptrace.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/gfp.h>
#include <linux/syscore_ops.h>
#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/syscall_user_dispatch.h>

#include <linux/compat.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/user_namespace.h>
#include <linux/time_namespace.h>
#include <linux/binfmts.h>

#include <linux/sched.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/stat.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/task.h>
#include <linux/sched/cputime.h>
#include <linux/rcupdate.h>
#include <linux/uidgid.h>
#include <linux/cred.h>

#include <linux/nospec.h>

// MY IMPORTS
#include <linux/vmstat.h>
#include <linux/mmzone.h>
#include <linux/sysinfo.h>
#include <linux/swap.h>
#include <linux/slab.h>

#include <linux/kmsg_dump.h>
/* Move somewhere else to avoid recompiling? */
#include <generated/utsrelease.h>

#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>


struct memory_limitation {
    pid_t pid;
    size_t memory_limit;
};

struct memory_list {
    struct list_head list;
    struct memory_limitation node;
};

static LIST_HEAD(memory_limitation_list);
static DEFINE_MUTEX(memory_list_mutex);

static int do_prlimit(struct task_struct *tsk, unsigned int resource, struct rlimit *new_rlim, struct rlimit *old_rlim) {
	struct rlimit *rlim;
	int retval = 0;

	if (resource >= RLIM_NLIMITS)
		return -EINVAL;
	resource = array_index_nospec(resource, RLIM_NLIMITS);

	if (new_rlim) {
		if (new_rlim->rlim_cur > new_rlim->rlim_max)
			return -EINVAL;
		if (resource == RLIMIT_NOFILE &&
				new_rlim->rlim_max > sysctl_nr_open)
			return -EPERM;
	}

	/* Holding a refcount on tsk protects tsk->signal from disappearing. */
	rlim = tsk->signal->rlim + resource;
	task_lock(tsk->group_leader);
	if (new_rlim) {
		/*
		 * Keep the capable check against init_user_ns until cgroups can
		 * contain all limits.
		 */
		if (new_rlim->rlim_max > rlim->rlim_max &&
				!capable(CAP_SYS_RESOURCE))
			retval = -EPERM;
		if (!retval)
			retval = security_task_setrlimit(tsk, resource, new_rlim);
	}
	if (!retval) {
		if (old_rlim)
			*old_rlim = *rlim;
		if (new_rlim)
			*rlim = *new_rlim;
	}
	task_unlock(tsk->group_leader);

	/*
	 * RLIMIT_CPU handling. Arm the posix CPU timer if the limit is not
	 * infinite. In case of RLIM_INFINITY the posix CPU timer code
	 * ignores the rlimit.
	 */
	if (!retval && new_rlim && resource == RLIMIT_CPU &&
	    new_rlim->rlim_cur != RLIM_INFINITY &&
	    IS_ENABLED(CONFIG_POSIX_TIMERS)) {
		/*
		 * update_rlimit_cpu can fail if the task is exiting, but there
		 * may be other tasks in the thread group that are not exiting,
		 * and they need their cpu timers adjusted.
		 *
		 * The group_leader is the last task to be released, so if we
		 * cannot update_rlimit_cpu on it, then the entire process is
		 * exiting and we do not need to update at all.
		 */
		update_rlimit_cpu(tsk->group_leader, new_rlim->rlim_cur);
	}

	return retval;
}


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