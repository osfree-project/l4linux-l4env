#ifndef __ASM_L4__GENERIC__SCHED_H__
#define __ASM_L4__GENERIC__SCHED_H__

#include <linux/thread_info.h>

#include <asm/generic/kthreads.h>
#include <asm/generic/dispatch.h>

#include <l4/sys/kdebug.h>
#include <l4/sys/ipc.h>

// clone flag to differentiate between kernel and user threads
#define CLONE_L4_KERNEL 0x10000000

static inline int l4x_in_kernel(void)
{
	return !l4x_current_proc_run
	       || l4x_current_proc_run == &init_thread_info;
}

/*
 * IRQ threads use this routine to check if they
 * need to wake up a sleeping kernel
 */
static inline void l4x_wakeup_idle_if_needed(void)
{
	/* when in an irq service routine, we must make sure the
	 * wakeup request will really wake up the process.  so if the
	 * kernel server is idling, wake it up. */

	if (l4x_current_proc_run
	    && test_bit(TIF_NEED_RESCHED, &l4x_current_proc_run->flags)) {

		if (l4x_current_proc_run == &init_thread_info) {
			/*
			 * No user process is currently running, i.e.
			 * idle is only waiting for interrupts to go on.
			 */
			l4x_wakeup_idler();
		} else {
			/*
			 * A user process is currently running, go interrupt
			 * it so that it comes in and triggers any
			 * possible interrupt work to do.
			 */
			l4x_suspend_user(l4x_current_proc_run->task);
		}
	}
}

#endif /* ! __ASM_L4__GENERIC__SCHED_H__ */
