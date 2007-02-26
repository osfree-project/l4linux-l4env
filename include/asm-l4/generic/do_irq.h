#ifndef __ASM_L4__GENERIC__DO_IRQ_H__
#define __ASM_L4__GENERIC__DO_IRQ_H__

#include <linux/spinlock.h>
#include <linux/thread_info.h>

#include <asm/generic/sched.h>
#include <asm/generic/task.h>
#include <asm/l4lxapi/irq.h>
#include <asm/l4x/exception.h>

static inline void l4x_do_IRQ(int irq, struct thread_info *ctx)
{
	unsigned long flags, old_cpu_state;
	struct pt_regs *r;

	local_irq_save(flags);
	ctx->task = l4x_current_process;
	ctx->preempt_count = l4x_current_process->thread_info->preempt_count;
	r = &l4x_current_process->thread.regs;
	old_cpu_state = l4x_get_cpu_mode(r);
	l4x_set_cpu_mode(r, l4x_in_kernel() ? L4X_MODE_KERNEL : L4X_MODE_USER);
	do_IRQ(irq, &l4x_current_process->thread.regs);
	l4x_set_cpu_mode(r, old_cpu_state);
	local_irq_restore(flags);

	l4x_wakeup_idle_if_needed();
}

#endif /* ! __ASM_L4__GENERIC__DO_IRQ_H__ */
