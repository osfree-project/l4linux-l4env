
#include <linux/errno.h>

#include <asm/generic/dispatch.h>
#include <asm/generic/upage.h>
#include <asm/generic/task.h>
#include <asm/generic/assert.h>
#include <asm/generic/hybrid.h>

#include <asm/api/macros.h>

#include <asm/l4lxapi/task.h>
#include <asm/l4lxapi/thread.h>
#include <asm/l4x/iodb.h>

#include <l4/sys/kdebug.h>

/*
 * Create an L4 user mode task for the new task_struct; copy_thread() will
 * invoke this routine in the Linux server's root task
 */
int thread_create_user(struct task_struct *p, int fork)
{
	struct thread_struct *t = &p->thread;
#ifdef DEBUG
	printk("%s: current=%s(%d) (" PRINTF_L4TASK_FORM ") -> "
	       PRINTF_L4TASK_FORM " (fork: %s)\n", __func__, current->comm, current->pid,
	       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
	       PRINTF_L4TASK_ARG(t->user_thread_id),
	       fork ? "yes" : "no");
#endif
#ifdef MY_ASSERTIONS
	if (fork &&
	    current->thread.user_thread_id.id.task == t->user_thread_id.id.task &&
	    current->thread.user_thread_id.id.lthread == t->user_thread_id.id.lthread) {
		printk("%s: Fork and same thread IDs ("
		       PRINTF_L4TASK_FORM ")\n", __func__,
		       PRINTF_L4TASK_ARG(t->user_thread_id));
		enter_kdebug("BUG?");
	}
#endif
	t->initial_state_set = 0;

	t->task_start_fork = !!fork;
	if (!l4lx_task_create(t->user_thread_id)) {
		printk("%s: Failed to create user task\n", __func__);
		return -EBUSY;
	}
	t->started = 1;
	return 0;
}


/* called by l4x_idle when activating a freshly-started thread, and
 * by the (kernel-internal) execve() when we want to convert a
 * kernel-internal thread to a user process.
 */
void l4x_start_thread_really(void)
{
	struct thread_struct *t = &current->thread;

	/* create the task */
	if (thread_create_user(current, 0) < 0) {
		l4lx_task_number_free(t->user_thread_id);

		/* XXX what should we do here? */
		enter_kdebug("start thread failed");

		l4x_sig_current_kill();
	}
}

/* called by do_exit(); kills the Linux user thread */
void exit_thread(void)
{
	l4_threadid_t id = current->thread.user_thread_id;
	int ret;

	/* check if we were a kernel-internal thread (i.e., have no
	   user-space partner) */
	if (unlikely(l4_is_nil_id(id)))
		return;

#ifdef DEBUG
	printk("exit_thread: trying to delete %s(%d, " PRINTF_L4TASK_FORM ")\n",
	       current->comm, current->pid, PRINTF_L4TASK_ARG(id));
#endif

	/* If task_delete fails we don't free the task number so that it
	 * won't be used again. */
	if (likely(ret = l4lx_task_delete(id, l4x_hybrid_list_task_exists(id)))) {
		if (ret == L4LX_TASK_DELETE_THREAD) {
			l4x_hybrid_list_thread_remove(id);
#ifdef CONFIG_L4_DEBUG_REGISTER_NAMES
			fiasco_register_thread_name(id, "(deleted)");
#endif
		} else {
			l4lx_task_number_free(id);
			l4x_hybrid_list_task_remove(id);
		}
		current->thread.started = 0;
	} else
		printk("%s: failed to delete task " PRINTF_L4TASK_FORM "\n",
		       __func__, PRINTF_L4TASK_ARG(id));

	l4x_iodb_free(current);
}
