/*
 * This file implements the timer interrupt in a generic
 * manner. The interface is defined in asm-l4/l4lxapi/irq.h.
 */

#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#include <asm/generic/dispatch.h>
#include <asm/generic/irq.h>
#include <asm/generic/sched.h>
#include <asm/generic/setup.h>
#include <asm/generic/task.h>
#include <asm/generic/do_irq.h>
#include <asm/generic/suspres.h>
#include <asm/generic/smp.h>

#include <asm/l4lxapi/irq.h>
#include <asm/l4lxapi/thread.h>
#include <asm/l4lxapi/misc.h>

#include <l4/sys/syscalls.h>

/*
 * Show the current (directly into vidmem)
 */
static inline void show_current(int cpu)
{
#ifdef CONFIG_L4_DBG_SHOW_CURRENT
	//struct task_struct *c = cpu_curr(cpu);
	struct task_struct *c = current->comm;
#ifdef CONFIG_L4_VX2
	const unsigned xstart = 62;
	const unsigned xend   = 74;
#else
	const unsigned xstart = 66;
	const unsigned xend   = 78;
#endif
	unsigned i = 0, xd = 0;
	char *scrp = (void *)(0xb8000 + 160*cpu + xstart*2);
	unsigned textstart = xend - strlen(c->comm);

	while (xstart + xd < xend) {
		if (xstart + xd >= textstart) {
			*scrp       = c->comm[i++];
			*(scrp + 1) = 2;
		} else
			*scrp = ' ';
		scrp += 2;
		xd++;
	}
#endif /* CONFIG_L4_DBG_SHOW_CURRENT */
}

/*
 * Timer interrupt thread.
 */
void timer_irq_thread(void *data)
{
	int irq = TIMER_IRQ;
	l4_timeout_t to;
	l4_threadid_t me = l4_myself();
	l4_kernel_clock_t pint;
	struct thread_info *ctx = current_thread_info();

	l4x_prepare_irq_thread(ctx, 0);

	printk("%s: Starting timer IRQ thread.\n", __func__);

	pint = l4lx_kinfo->clock;
	for (;;) {
		l4_msgdope_t result;
		l4_umword_t d1, d2;

		pint += 10000;

		if (pint > l4lx_kinfo->clock) {
			l4_rcv_timeout(l4_timeout_abs(pint,
			                              L4_TIMEOUT_ABS_V64_ms),
			               &to);
			l4_ipc_receive(me, L4_IPC_SHORT_MSG, &d1, &d2,
				       to, &result);
		} else {
			//printk("I'm too slow (%lld vs. %lld [%lld])!\n", l4lx_kinfo->clock, pint, l4lx_kinfo->clock - pint);
		}

		l4x_do_IRQ(irq, ctx);
		l4x_smp_broadcast_timer();
	}
} /* timer_irq_thread */

static void deep_sleep(void)
{
	l4_sleep_forever();
}

static void suspend_resume_func(enum l4x_suspend_resume_state state)
{
	switch (state) {
		case L4X_SUSPEND:
			l4x_thread_set_pc(irq_id[TIMER_IRQ], deep_sleep);
			break;

		case L4X_RESUME:
			l4x_thread_set_pc(irq_id[TIMER_IRQ], timer_irq_thread);
			break;
	};
}

/*
 * public functions.
 */
unsigned int l4lx_irq_timer_startup(unsigned int irq)
{
	char thread_name[15];
	int cpu = 0;
	static struct l4x_suspend_resume_struct susp_res;

	printk("%s(%d)\n", __func__, irq);

	if (test_and_set_bit(irq, &irq_threads_started))
		return 1;

	BUG_ON(TIMER_IRQ != irq);

	l4x_suspend_resume_register(suspend_resume_func, &susp_res);

	sprintf(thread_name, "timer.i%d", irq);
	irq_id[irq] = l4lx_thread_create
			(timer_irq_thread,	/* thread function */
	                 0,                     /* cpu */
			 NULL,			/* stack */
			 &cpu, sizeof(cpu),	/* data */
			 l4lx_irq_prio_get(irq),/* prio */
			 thread_name);		/* ID */

	if (l4lx_thread_equal(irq_id[irq], L4_NIL_ID))
		enter_kdebug("Error creating timer thread!");

	return 1;
}

void l4lx_irq_timer_shutdown(unsigned int irq)
{}

void l4lx_irq_timer_enable(unsigned int irq)
{}

void l4lx_irq_timer_disable(unsigned int irq)
{}

void l4lx_irq_timer_ack(unsigned int irq)
{
	l4lx_irq_dbg_spin_wheel(irq);
}

void l4lx_irq_timer_end(unsigned int irq)
{}

void l4lx_irq_timer_mask(unsigned int irq)
{}

void l4lx_irq_timer_unmask(unsigned int irq)
{}
