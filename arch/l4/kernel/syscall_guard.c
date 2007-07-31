/*
 * System call guard.
 */

#include <linux/kernel.h>
#include <linux/sched.h>

#include <l4/sys/utcb.h>
#include <l4/log/l4log.h>

#include <asm/generic/dispatch.h>
#include <asm/generic/syscall_guard.h>

typedef int (*sc_check_func_t)(struct task_struct *p);

static int check_ipc(struct task_struct *p)
{
	if (!strcmp(p->comm, "fiasco"))
		return 0;

	return 1;
}

static int check_id_nearest(struct task_struct *p)
{
	if (!strcmp(p->comm, "fiasco"))
		return 0;

	/* Querying information is ok. */
	return 1;
}

static int check_fpage_unmap(struct task_struct *p)
{
	/* Allow */
	return 1;
}

static int check_thread_switch(struct task_struct *p)
{
	/* Not allowed. */
	return 0;
}

static int check_thread_schedule(struct task_struct *p)
{
	/* Not allowed. */
	return 0;
}

static int check_lthread_ex_regs(struct task_struct *p)
{
	/* Not allowed. */
	return 0;
}

static int check_task_new(struct task_struct *p)
{
	/* Not allowed. */
	return 0;
}

static int check_privctrl(struct task_struct *p)
{
	/* Not allowed. */
	return 0;
}


sc_check_func_t sc_check_funcs[] = {
	check_ipc,
	check_id_nearest,
	check_fpage_unmap,
	check_thread_switch,
	check_thread_schedule,
	check_lthread_ex_regs,
	check_task_new,
	check_privctrl,
};



/*
 * Check if a system call is allow or not.
 *
 * \param p		task structure of the process to check
 * \param utcb		exception utcb state of the process to check
 * \return 0		syscall not allowed
 * \return 1		syscall ok
 */
int l4x_syscall_guard(struct task_struct *p, int sysnr)
{
	if (sysnr >= 0
	    && sc_check_funcs[sysnr]
	    && sc_check_funcs[sysnr](p))
		return 1; /* This syscall is allowed */

	LOG_printf("%s: Syscall%d was forbidden for %s(%d) at %p\n",
	           __func__, sysnr, p->comm, p->pid,
#ifdef ARCH_arm
		   (void *)p->thread.regs.ARM_pc
#else
	           (void *)p->thread.regs.eip
#endif
		   );

	return 0; /* Not allowed */
}
