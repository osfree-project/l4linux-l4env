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
	unsigned int irq0_irqs;
	unsigned int irq_resched_count;
	unsigned int irq_call_count;
	unsigned int irq_tlb_count;
	unsigned int irq_thermal_count;
	unsigned int irq_spurious_count;
} ____cacheline_aligned irq_cpustat_t;

DECLARE_PER_CPU(irq_cpustat_t, irq_stat);

#define __ARCH_IRQ_STAT
#define __IRQ_STAT(cpu, member) (per_cpu(irq_stat, cpu).member)

void ack_bad_irq(unsigned int irq);
#include <linux/irq_cpustat.h>

// from hardirq.h
extern u64 arch_irq_stat_cpu(unsigned int cpu);
#define arch_irq_stat_cpu	arch_irq_stat_cpu

extern u64 arch_irq_stat(void);
#define arch_irq_stat		arch_irq_stat

#endif /* __ASM_L4__ARCH_I386__HARDIRQ_H__ */
