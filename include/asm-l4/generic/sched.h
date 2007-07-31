#ifndef __ASM_L4__GENERIC__SCHED_H__
#define __ASM_L4__GENERIC__SCHED_H__

#include <linux/thread_info.h>

#include <asm/generic/kthreads.h>
#include <asm/generic/dispatch.h>

#include <l4/sys/kdebug.h>
#include <l4/sys/ktrace.h> // remove
#include <l4/sys/ipc.h>

static inline int l4x_in_kernel(void)
{
	return !per_cpu(l4x_current_proc_run, smp_processor_id())
	       || per_cpu(l4x_current_proc_run, smp_processor_id())
	          == &init_thread_info;
}

/*
 * IRQ threads use this routine to check if they
 * need to wake up a sleeping kernel
 */
static inline void l4x_wakeup_idle_if_needed(void)
{
	int cpu;

	/* when in an irq service routine, we must make sure the
	 * wakeup request will really wake up the process.  so if the
	 * kernel server is idling, wake it up. */

	for_each_online_cpu(cpu) {
		if (per_cpu(l4x_current_proc_run, cpu)
#ifdef ARCH_x86
		    && (_TIF_ALLWORK_MASK
		        & per_cpu(l4x_current_proc_run, cpu)->flags)
#elif defined(ARCH_arm)
		    && (_TIF_WORK_MASK
		        & per_cpu(l4x_current_proc_run, cpu)->flags)
#else
#error Unknown arch
#endif
		    ) {

			if (per_cpu(l4x_current_proc_run, cpu)
			    == &init_thread_info) {
				/*
				 * No user process is currently running,
				 * i.e.  idle is only waiting for interrupts
				 * to go on.
				 */
				l4x_wakeup_idler(cpu);
			} else {
				/*
				 * A user process is currently running, go
				 * interrupt it so that it comes in and
				 * triggers any possible interrupt work to
				 * do.
				 */
				l4x_suspend_user(per_cpu(l4x_current_proc_run,
				                         cpu)->task, cpu);
			}
		}
	}
}

#endif /* ! __ASM_L4__GENERIC__SCHED_H__ */
