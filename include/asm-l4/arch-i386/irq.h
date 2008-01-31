#ifndef __ASM_L4__ARCH_I386__IRQ_H__
#define __ASM_L4__ARCH_I386__IRQ_H__

#include <linux/sched.h>
#include <asm/thread_info.h>

/* the defines are from irq_vectors out of the mach-default directory */
#define NR_IRQS			25
#define NR_IRQS_HW		16
#define NR_IRQ_VECTORS		NR_IRQS
#define SYSCALL_VECTOR		0x80
#define FIRST_DEVICE_VECTOR	0x31
#define FIRST_SYSTEM_VECTOR	0xef
#define NR_VECTORS		256

#define L4X_IRQ_CONS            20

static __inline__ int irq_canonicalize(int irq)
{
	return ((irq == 2) ? 9 : irq);
}

#ifdef CONFIG_X86_LOCAL_APIC
# define ARCH_HAS_NMI_WATCHDOG		/* See include/linux/nmi.h */
#endif

# define __ARCH_HAS_DO_SOFTIRQ

#ifdef CONFIG_4KSTACKS_ALWAYS_DISABLED_FOR_L4LX
  extern void irq_ctx_init(int cpu);
  extern void irq_ctx_exit(int cpu);
# define __ARCH_HAS_DO_SOFTIRQ
#else
# define irq_ctx_init(cpu) do { } while (0)
# define irq_ctx_exit(cpu) do { } while (0)
#endif

#ifdef CONFIG_IRQBALANCE
extern int irqbalance_disable(char *str);
#endif

#ifdef CONFIG_HOTPLUG_CPU
extern void fixup_irqs(cpumask_t map);
#endif

unsigned int do_IRQ(int irq, struct pt_regs *regs);
void init_IRQ(void);
void __init native_init_IRQ(void);

/* Interrupt vector management */
extern DECLARE_BITMAP(used_vectors, NR_VECTORS);


#endif /* __ASM_L4__ARCH_I386__IRQ_H__ */
