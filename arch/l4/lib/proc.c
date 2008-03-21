/*
 * /proc/l4
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/list.h>

#include <asm/api/macros.h>
#include <asm/l4lxapi/thread.h>

#include <asm/generic/hybrid.h>
#include <asm/generic/stats.h>
#include <asm/generic/task.h>

#define DIRNAME "l4"

struct proc_dir_entry *l4_proc_dir;

EXPORT_SYMBOL(l4_proc_dir);

int kthreads_seq_show(struct seq_file *m, void *v)
{
	int i = *(int *)v;

	if (!l4lx_thread_equal(l4lx_thread_names[i].id, L4_NIL_ID))
		seq_printf(m, PRINTF_L4TASK_FORM ": %s\n",
		           PRINTF_L4TASK_ARG(l4lx_thread_names[i].id),
		           l4lx_thread_names[i].name);
	return 0;
}

static void *kthreads_seq_start(struct seq_file *m, loff_t *pos)
{
	return (*pos <= L4LX_THREAD_NO_THREADS) ? pos : NULL;
}

static void *kthreads_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos > L4LX_THREAD_NO_THREADS)
		return NULL;
	return pos;
}

static void kthreads_seq_stop(struct seq_file *m, void *v)
{
	/* Nothing to do */
}

static struct seq_operations kthreads_seq_ops = {
	.start = kthreads_seq_start,
	.next  = kthreads_seq_next,
	.stop  = kthreads_seq_stop,
	.show  = kthreads_seq_show,
};

static int l4x_kthreads_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &kthreads_seq_ops);
}

static struct file_operations l4x_kthreads_fops = {
	.open    = l4x_kthreads_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

/* ------------------------------------------- */

static void *hybrid_seq_start(struct seq_file *m, loff_t *pos)
{
	return (*pos == 0) ? pos : NULL;
}

static void *hybrid_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

static void hybrid_seq_stop(struct seq_file *m, void *v)
{
	/* Nothing to do */
}

static struct seq_operations hybrid_seq_ops = {
	.start = hybrid_seq_start,
	.next  = hybrid_seq_next,
	.stop  = hybrid_seq_stop,
	.show  = l4x_hybrid_list_seq_show,
};

static int l4x_hybrid_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &hybrid_seq_ops);
}

static struct file_operations l4x_hybrid_fops = {
	.open    = l4x_hybrid_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

/* ------------------------------------------- */

static void *stats_seq_start(struct seq_file *m, loff_t *pos)
{
	return (*pos == 0) ? pos : NULL;
}

static void *stats_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

static void stats_seq_stop(struct seq_file *m, void *v)
{
	/* Nothing to do */
}

static int stats_seq_show(struct seq_file *m, void *v)
{
	seq_printf(m, "user suspends:   %ld\n"
	              "user pagefaults: %ld\n"
	              "user exceptions: %ld\n"
	              "page fault but in PT: %ld\n"
	              "write page faults: %ld\n",
	          l4x_debug_stats_suspend_get(),
	          l4x_debug_stats_pagefault_get(),
	          l4x_debug_stats_exceptions_get(),
	          l4x_debug_stats_pagefault_but_in_PTs_get(),
	          l4x_debug_stats_pagefault_write_get());

	return 0;
}

static struct seq_operations stats_seq_ops = {
	.start = stats_seq_start,
	.next  = stats_seq_next,
	.stop  = stats_seq_stop,
	.show  = stats_seq_show,
};

static int l4x_stats_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &stats_seq_ops);
}

static struct file_operations l4x_stats_fops = {
	.open    = l4x_stats_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static void l4x_create_seq_entry(char *name, mode_t mode, struct file_operations *f)
{
	struct proc_dir_entry *entry;
	entry = create_proc_entry(name, mode, l4_proc_dir);
	if (entry)
		entry->proc_fops = f;
}

static int __init l4x_proc_init(void)
{
	int r = 0;

	/* create directory */
	if ((l4_proc_dir = proc_mkdir(DIRNAME, NULL)) == NULL)
		return -ENOMEM;

	/* seq file ones */
	l4x_create_seq_entry("kthreads", 0, &l4x_kthreads_fops);
	l4x_create_seq_entry("hybrids",  0, &l4x_hybrid_fops);
	l4x_create_seq_entry("stats",    0, &l4x_stats_fops);

	return r;
}

/* automatically start this */
subsys_initcall(l4x_proc_init);
