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
            entry->node.memory_limit = memory_limit; // Actualizar límite
            mutex_unlock(&memory_list_mutex);
            pr_info("add_memory_limit: actualizado PID=%d con memory_limit=%zu.\n", pid, memory_limit);
            return 0;
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