
#include <linux/errno.h>

#include <asm/generic/task.h>
#include <asm/generic/hybrid.h>

#include <asm/api/macros.h>

#include <asm/l4lxapi/task.h>
#include <asm/l4lxapi/thread.h>
#include <asm/l4x/iodb.h>

#include <l4/sys/kdebug.h>

#include <l4/sys/ipc.h>

void l4x_exit_thread(void)
{
	int ret;
	int i;

	for (i = 0; i < NR_CPUS; i++) {
		l4_threadid_t id = current->thread.user_thread_ids[i];
		/* check if we were a non-user thread (i.e., have no
		   user-space partner) */
		if (unlikely(l4_is_nil_id(id)))
			continue;

#ifdef DEBUG
		LOG_printf("exit_thread: trying to delete %s(%d, " PRINTF_L4TASK_FORM ")\n",
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

	}

	//enter_kdebug("exit thread");

	l4x_iodb_free(current);

#ifdef CONFIG_X86_DS
	ds_exit_thread(current);
#endif
}
