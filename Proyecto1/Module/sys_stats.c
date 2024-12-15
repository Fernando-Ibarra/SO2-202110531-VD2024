#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/statfs.h>
#include <linux/path.h>
#include <linux/namei.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fernando Ibarra");
MODULE_DESCRIPTION("Module to show system statistics");

// CPU Stats
static void get_cpu_stats(struct seq_file *m) {
    u64 idle_time, total_time;
    
    idle_time = kcpustat_cpu(0).cpustat[CPUTIME_IDLE];
    total_time = idle_time;
    for(int i = 0; i < CPUTIME_SOFTIRQ; i++) {
        total_time += kcpustat_cpu(0).cpustat[i];
    }

    if (total_time > 0) {
        u64 usage = 100 * (total_time - idle_time) / total_time;
        seq_printf(m, "CPU Usage: %llu%%\n", usage);
    } else {
        seq_printf(m, "CPU Usage: Unable to fetch\n");
    }
    
}

// Mem Stats
static void get_memory_stats(struct seq_file *m) {
    struct sysinfo si;
    si_meminfo(&si);

    unsigned long total_memory = si.totalram << (PAGE_SHIFT - 10); // Convertir a KB
    unsigned long free_memory = si.freeram << (PAGE_SHIFT - 10);   // Convertir a KB

    seq_printf(m, "Total Memory: %lu KB\n", total_memory);
    seq_printf(m, "Free Memory: %lu KB\n", free_memory);
}

// Disk Stats
static void get_storage_stats(struct seq_file *m) {
    struct kstatfs stat;
    struct path path;

    // Resolver la ruta "/"
    if (kern_path("/", LOOKUP_FOLLOW, &path) == 0) {
        if (vfs_statfs(&path, &stat) == 0) {
            unsigned long total_blocks = stat.f_blocks;
            unsigned long free_blocks = stat.f_bfree;
            unsigned long block_size = stat.f_bsize;

            unsigned long total_space = total_blocks * block_size >> 10; // Convertir a KB
            unsigned long free_space = free_blocks * block_size >> 10;   // Convertir a KB

            seq_printf(m, "Total Disk Space: %lu KB\n", total_space);
            seq_printf(m, "Free Disk Space: %lu KB\n", free_space);
        } else {
            seq_printf(m, "Error al obtener estadísticas del disco.\n");
        }
        path_put(&path); // Liberar el recurso de la ruta
    } else {
        seq_printf(m, "Error al resolver la ruta para estadísticas del disco.\n");
    }
    
}

// Función principal para mostrar estadísticas
static int stats_show(struct seq_file *m, void *v) {
    seq_printf(m, "Kernel Module Statistics:\n");
    seq_printf(m, "--------------------------\n");
    get_cpu_stats(m);
    get_memory_stats(m);
    get_storage_stats(m);
    return 0;
}

static int stats_open(struct inode *inode, struct file *file) {
    return single_open(file, stats_show, NULL);
}

static const struct proc_ops stats_fops = {
    .proc_open = stats_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

// Inicialización del módulo
static int __init stats_init(void) {
    struct proc_dir_entry *entry;

    entry = proc_create("system_stats", 0, NULL, &stats_fops);
    if (!entry) {
        return -ENOMEM;
    }
    pr_info("Modulo 'system_stats' cargado.\n");
    return 0;
}

// Salida del módulo
static void __exit stats_exit(void) {
    remove_proc_entry("system_stats", NULL);
    pr_info("Modulo 'system_stats' descargado.\n");
}
module_init(stats_init);
module_exit(stats_exit);