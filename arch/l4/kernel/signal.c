#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/spinlock.h>

#include <asm/api/macros.h>
#include <asm/generic/signal.h>
#include <l4/sys/kdebug.h>

#if defined(ARCH_x86)
int l4x_deliver_signal(int exception_nr, int errcode)
{
	// look at arm example??
	printk("nr = %d  errcode = %d\n", exception_nr, errcode);
	enter_kdebug("l4x_deliver_signal");
	return 0;
}
#elif defined(ARCH_arm)
int l4x_deliver_signal(int exception_nr, int errcode)
{
	siginfo_t info;

	printk("%s with exception %d for " PRINTF_L4TASK_FORM " (code: %x)\n",
		__func__, exception_nr,
		PRINTF_L4TASK_ARG(current->thread.user_thread_id), errcode);

	info.si_signo = SIGSEGV;
	info.si_errno = 0;
	info.si_code  = SEGV_MAPERR;
	info.si_addr  = (void __user *)current->thread.regs.ARM_pc;

	force_sig_info(SIGSEGV, &info, current);

	if (signal_pending(current)) {
		do_signal(&current->blocked, &current->thread.regs, 0);
		return 1;
	}

	return 0;
}
#else
#error Unknown arch
#endif

void l4x_sig_current_kill(void)
{
	/*
	 * We're a user process which just got a SIGKILL/SEGV and we're now
	 * preparing to die...
	 */

	/*
	 * empty queue and only put SIGKILL/SEGV into it so that the process
	 * gets killed ASAP
	 */
	spin_lock_irq(&current->sighand->siglock);
	flush_signals(current);
	force_sig(SIGKILL, current);
	spin_unlock_irq(&current->sighand->siglock);

	/*
	 * invoke do_signal which will dequeue the signal from the queue
	 * and feed us further to do_exit
	 */
#if defined(ARCH_x86)
	do_signal(&current->thread.regs);
#elif defined(ARCH_arm)
	do_signal(&current->blocked, &current->thread.regs, 0);
#else
#error Wrong arch
#endif
	panic("The zombie walks after SIGKILL!");
}

