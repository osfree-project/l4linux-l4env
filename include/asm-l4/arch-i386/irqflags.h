/*
 * include/asm-l4/arch-i386/irqflags.h
 *
 * IRQ flags handling
 *
 * This file gets included from lowlevel asm headers too, to provide
 * wrapped versions of the local_irq_*() APIs, based on the
 * raw_local_irq_*() functions from the lowlevel headers.
 */
#ifndef __ASM_L4__ARCH_I386__IRQFLAGS_H__
#define __ASM_L4__ARCH_I386__IRQFLAGS_H__

#ifndef __ASSEMBLY__

#if defined(CONFIG_L4_USERPRIV_ONLY) || defined(CONFIG_L4_TAMED)

#include <asm/generic/irq.h>

#ifdef CONFIG_L4_TAMED

extern void l4x_global_cli(void);
extern void l4x_global_sti(void);
extern unsigned long l4x_global_save_flags(void);
extern void l4x_global_restore_flags(unsigned long flags);

static inline unsigned long __raw_local_save_flags(void)
{
	return l4x_global_save_flags();
}

#define raw_local_save_flags(flags) \
		do { (flags) = __raw_local_save_flags(); } while (0)

static inline void raw_local_irq_restore(unsigned long flags)
{
	l4x_global_restore_flags(flags);
}

static inline void raw_local_irq_disable(void)
{
	l4x_global_cli();
}

static inline void raw_local_irq_enable(void)
{
	l4x_global_sti();
}

#else
/* Use cli/sti but not popf, sufficient for Fiasco-UX */

static inline unsigned long __raw_local_save_flags(void)
{
	return l4x_local_save_flags();
}

#define raw_local_save_flags(flags) \
		do { (flags) = __raw_local_save_flags(); } while (0)

static inline void raw_local_irq_restore(unsigned long flags)
{
	l4x_local_irq_restore(flags);
}

static inline void raw_local_irq_disable(void)
{
	l4x_local_irq_disable();
}

static inline void raw_local_irq_enable(void)
{
	l4x_local_irq_enable();
}

static inline void l4x_real_irq_disable(void)
{
	__asm__ __volatile__("cli" : : : "memory");
}

static inline void l4x_real_irq_enable(void)
{
	__asm__ __volatile__("sti" : : : "memory");
}

#endif

static inline int raw_irqs_disabled_flags(unsigned long flags)
{
	return flags == L4_IRQ_DISABLED;
}

#else

static inline unsigned long __raw_local_save_flags(void)
{
	unsigned long flags;

	__asm__ __volatile__(
		"pushfl ; popl %0"
		: "=g" (flags)
		: /* no input */
	);

	return flags;
}

#define raw_local_save_flags(flags) \
		do { (flags) = __raw_local_save_flags(); } while (0)

static inline void raw_local_irq_restore(unsigned long flags)
{
	__asm__ __volatile__(
		"pushl %0 ; popfl"
		: /* no output */
		:"g" (flags)
		:"memory", "cc"
	);
}

static inline void raw_local_irq_disable(void)
{
	__asm__ __volatile__("cli" : : : "memory");
}

static inline void raw_local_irq_enable(void)
{
	__asm__ __volatile__("sti" : : : "memory");
}

/*
 * Used in the idle loop; sti takes one instruction cycle
 * to complete:
 */
static inline void raw_safe_halt(void)
{
	__asm__ __volatile__("sti; hlt" : : : "memory");
}

/*
 * Used when interrupts are already enabled or to
 * shutdown the processor:
 */
static inline void halt(void)
{
	__asm__ __volatile__("hlt": : :"memory");
}

static inline int raw_irqs_disabled_flags(unsigned long flags)
{
	return !(flags & (1 << 9));
}

#endif

static inline int raw_irqs_disabled(void)
{
	unsigned long flags = __raw_local_save_flags();

	return raw_irqs_disabled_flags(flags);
}

/*
 * For spinlocks, etc:
 */
static inline unsigned long __raw_local_irq_save(void)
{
	unsigned long flags = __raw_local_save_flags();

	raw_local_irq_disable();

	return flags;
}

#define raw_local_irq_save(flags) \
		do { (flags) = __raw_local_irq_save(); } while (0)

#endif /* __ASSEMBLY__ */

/*
 * Do the CPU's IRQ-state tracing from assembly code. We call a
 * C function, so save all the C-clobbered registers:
 */
#ifdef CONFIG_TRACE_IRQFLAGS

# define TRACE_IRQS_ON				\
	pushl %eax;				\
	pushl %ecx;				\
	pushl %edx;				\
	call trace_hardirqs_on;			\
	popl %edx;				\
	popl %ecx;				\
	popl %eax;

# define TRACE_IRQS_OFF				\
	pushl %eax;				\
	pushl %ecx;				\
	pushl %edx;				\
	call trace_hardirqs_off;		\
	popl %edx;				\
	popl %ecx;				\
	popl %eax;

#else
# define TRACE_IRQS_ON
# define TRACE_IRQS_OFF
#endif

#endif
