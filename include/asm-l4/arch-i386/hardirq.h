#ifndef __ASM_L4__ARCH_I386__HARDIRQ_H__
#define __ASM_L4__ARCH_I386__HARDIRQ_H__

#include <linux/threads.h>
#include <linux/irq.h>

typedef struct {
	unsigned int __softirq_pending;
	unsigned long idle_timestamp;
	unsigned int __nmi_count;	/* arch dependent */
	unsigned int __l4x_irq_flag;	/* L4-specific IRQ flag emulation */
	unsigned int apic_timer_irqs;	/* arch dependent */
} ____cacheline_aligned irq_cpustat_t;

DECLARE_PER_CPU(irq_cpustat_t, irq_stat);
extern irq_cpustat_t irq_stat[];

#define __ARCH_IRQ_STAT
#define __IRQ_STAT(cpu, member) (per_cpu(irq_stat, cpu).member)

void ack_bad_irq(unsigned int irq);
#include <linux/irq_cpustat.h>

#endif /* __ASM_L4__ARCH_I386__HARDIRQ_H__ */
