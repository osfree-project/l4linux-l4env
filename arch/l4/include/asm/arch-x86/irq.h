#ifndef __ASM_L4__ARCH_I386__IRQ_H__
#define __ASM_L4__ARCH_I386__IRQ_H__

#include <asm/apicdef.h>
#include <asm/irq_vectors.h>

/* the defines are from irq_vectors out of the mach-default directory */
//#define NR_IRQS			25
#define NR_IRQS_HW		16
//#define NR_IRQ_VECTORS		NR_IRQS
//#define NR_VECTORS		256

#define L4X_IRQ_CONS            20

static inline int irq_canonicalize(int irq)
{
	return ((irq == 2) ? 9 : irq);
}

#ifdef CONFIG_X86_LOCAL_APIC
# define ARCH_HAS_NMI_WATCHDOG
#endif

# define __ARCH_HAS_DO_SOFTIRQ

#ifdef CONFIG_4KSTACKS_ALWAYS_DISABLED_FOR_L4LX
  extern void irq_ctx_init(int cpu);
  extern void irq_ctx_exit(int cpu);
# define __ARCH_HAS_DO_SOFTIRQ
#else
# define irq_ctx_init(cpu) do { } while (0)
# define irq_ctx_exit(cpu) do { } while (0)
# ifdef CONFIG_X86_64
#  define __ARCH_HAS_DO_SOFTIRQ
# endif
#endif

#ifdef CONFIG_HOTPLUG_CPU
#include <linux/cpumask.h>
extern void fixup_irqs(void);
#endif

extern unsigned int do_IRQ(int irq, struct pt_regs *regs);
extern void init_IRQ(void);
extern void native_init_IRQ(void);

/* Interrupt vector management */
extern DECLARE_BITMAP(used_vectors, NR_VECTORS);
extern int vector_used_by_percpu_irq(unsigned int vector);

#endif /* __ASM_L4__ARCH_I386__IRQ_H__ */
