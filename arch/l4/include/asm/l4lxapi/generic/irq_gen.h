/*
 * This file defines some generic function for the interrupt handling.
 * The code can be used in the µk specific implementations as well as in
 * irq_omega0, irq_timer etc.
 *
 * $Id$
 */

#ifndef __ASM_L4__L4LXAPI__GENERIC__IRQ_GEN_H__
#define __ASM_L4__L4LXAPI__GENERIC__IRQ_GEN_H__

#include <l4/sys/types.h>

#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#ifdef CONFIG_L4_DEBUG_IRQ_WHEELS
void l4lx_irq_dbg_spin_wheel(unsigned int irq);
#else /* ! CONFIG_L4_IRQ_WHEELS */
/* define function empty */
#define l4lx_irq_dbg_spin_wheel(irq) do { } while (0)
#endif /* ! CONFIG_L4_IRQ_WHEELS */

extern spinlock_t l4lx_irq_pic_lock;
extern unsigned long irq_threads_started;
extern l4_threadid_t irq_id[NR_IRQS];
extern unsigned int l4lx_irq_max;

#endif /* ! __ASM_L4__L4LXAPI__GENERIC__IRQ_GEN_H__ */
