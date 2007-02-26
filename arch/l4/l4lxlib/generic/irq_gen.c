/*
 * This file implements some generic code for the interrupt handling.
 * This code can be used in the µk specific implementations as well as in
 * irq_omega0, irq_timer etc.
 *
 * $Id: irq_gen.c,v 1.4 2003/07/14 13:23:37 jork Exp $
 */

#include <asm/io.h>

#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#include <asm/l4lxapi/generic/irq_gen.h>

/* PIC lock */
DEFINE_SPINLOCK(l4lx_irq_pic_lock);

/* Bitmap which IRQ is running */
unsigned long irq_threads_started;

/* TID for every IRQ thread */
l4_threadid_t irq_id[NR_IRQS];

unsigned int l4lx_irq_max; ///< highest IRQ no + 1 available in the system

#ifdef CONFIG_L4_DEBUG_IRQ_WHEELS
static char irq_wheel_counter[NR_IRQS];

void l4lx_irq_dbg_spin_wheel(unsigned int irq) {
	char *screenp;
#ifdef CONFIG_L4_DEBUG_IRQ_WHEELS_PIC
	unsigned pic_mask = inb(0x21) | (inb(0xA1) << 8);
#endif
	if (irq > 22)
		return;

	irq_wheel_counter[irq]++;
#ifdef CONFIG_L4_DEBUG_IRQ_WHEELS_FULL_REDRAW
	for (irq = 0; irq < NR_IRQS && irq < 23; irq++) {
#endif
	screenp = (void *)(0xb809e + irq*160);
	*(screenp - 2) = irq + ((irq < 10)?48:55);
#ifdef CONFIG_L4_DEBUG_IRQ_WHEELS_PIC
	*(screenp - 1) = ((1 << irq) & pic_mask)?4:1;
#else
	*(screenp - 1) = 1;
#endif
	*screenp = irq_wheel_counter[irq];
	*(screenp + 1) = 2;
#ifdef CONFIG_L4_DEBUG_IRQ_WHEELS_FULL_REDRAW
	}
#endif
}
#endif /* CONFIG_L4_DEBUG_IRQ_SPINWHEELS */
