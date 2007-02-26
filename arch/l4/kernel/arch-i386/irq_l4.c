/*
 * linux/arch/l4/irq_l4.c
 *
 * $Id: irq_l4.c,v 1.16 2003/01/09 18:39:21 uhlig Exp $
 *
 */

#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/module.h>

#include <asm/uaccess.h>
#include <asm/system.h>

#include <asm/l4lxapi/irq.h>

#include <asm/generic/task.h>
#include <asm/generic/stack_id.h>


struct hw_interrupt_type l4_timer_irq_type = {
	.typename	= "L4 Timer IRQ",
	.startup	= l4lx_irq_timer_startup,
	.shutdown	= l4lx_irq_timer_shutdown,
	.enable		= l4lx_irq_timer_enable,
	.disable	= l4lx_irq_timer_disable,
	.ack		= l4lx_irq_timer_ack,
	.mask		= l4lx_irq_timer_mask,
	.unmask		= l4lx_irq_timer_unmask,
	.end		= l4lx_irq_timer_end,
	.set_affinity	= NULL
};

struct hw_interrupt_type l4_hw_irq_type = {
	.typename	= "L4 HW IRQ",
	.startup	= l4lx_irq_dev_startup_hw,
	.shutdown	= l4lx_irq_dev_shutdown_hw,
	.enable		= l4lx_irq_dev_enable_hw,
	.disable	= l4lx_irq_dev_disable_hw,
	.ack		= l4lx_irq_dev_ack_hw,
	.mask		= l4lx_irq_dev_mask_hw,
	.unmask		= l4lx_irq_dev_unmask_hw,
	.end		= l4lx_irq_dev_end_hw,
	.set_affinity	= NULL
};

struct hw_interrupt_type l4_virt_irq_type = {
	.typename	= "L4 virt IRQ",
	.startup	= l4lx_irq_dev_startup_virt,
	.shutdown	= l4lx_irq_dev_shutdown_virt,
	.enable		= l4lx_irq_dev_enable_virt,
	.disable	= l4lx_irq_dev_disable_virt,
	.ack		= l4lx_irq_dev_ack_virt,
	.mask		= l4lx_irq_dev_mask_virt,
	.unmask		= l4lx_irq_dev_unmask_virt,
	.end		= l4lx_irq_dev_end_virt,
	.set_affinity	= NULL
};


union irq_ctx {
	struct thread_info	tinfo;
	u32			stack[THREAD_SIZE/sizeof(u32)];
};

static union irq_ctx *softirq_ctx;

static char softirq_stack[THREAD_SIZE]
		__attribute__((__aligned__(THREAD_SIZE)));

static void l4x_init_softirq_stack(void)
{
	softirq_ctx = (union irq_ctx *)softirq_stack;
	softirq_ctx->tinfo.task			= NULL;
	softirq_ctx->tinfo.exec_domain		= NULL;
	softirq_ctx->tinfo.cpu			= 0;
	softirq_ctx->tinfo.preempt_count	= SOFTIRQ_OFFSET;
	softirq_ctx->tinfo.addr_limit		= MAKE_MM_SEG(0);
}

void __init init_IRQ(void)
{
	int i;

	l4lx_irq_init();
	l4x_init_softirq_stack();

	set_irq_chip_and_handler(0, &l4_timer_irq_type, handle_edge_irq);

	for (i = 1; i < NR_IRQS; i++) {
		if (i < l4lx_irq_max) {
			if (i < NR_IRQS_HW)
				set_irq_chip_and_handler(i, &l4_hw_irq_type, handle_edge_irq);
			else
				set_irq_chip_and_handler(i, &l4_virt_irq_type, handle_edge_irq);
		} else
			set_irq_chip_and_handler(i, &no_irq_type, handle_edge_irq);
	}
}

extern asmlinkage void __do_softirq(void);

#include <l4/sys/ktrace.h>

asmlinkage void do_softirq(void)
{
	unsigned long flags;

	if (in_interrupt())
		return;

	local_irq_save(flags);

	if (local_softirq_pending()) {
		__do_softirq();
	}

	local_irq_restore(flags);
}

EXPORT_SYMBOL(do_softirq);
