#ifndef _X86_IRQFLAGS_H_
#define _X86_IRQFLAGS_H_

#include <asm/processor-flags.h>

#ifndef __ASSEMBLY__
/*
 * Interrupt control:
 */

static inline unsigned long native_save_fl(void)
{
	unsigned long flags;

	/*
	 * Note: this needs to be "=r" not "=rm", because we have the
	 * stack offset from what gcc expects at the time the "pop" is
	 * executed, and so a memory reference with respect to the stack
	 * would end up using the wrong address.
	 */
	asm volatile("# __raw_save_flags\n\t"
		     "pushf ; pop %0"
		     : "=r" (flags)
		     : /* no input */
		     : "memory");

	return flags;
}

static inline void native_restore_fl(unsigned long flags)
{
	asm volatile("push %0 ; popf"
		     : /* no output */
		     :"g" (flags)
		     :"memory", "cc");
}

static inline void native_irq_disable(void)
{
	asm volatile("cli": : :"memory");
}

static inline void native_irq_enable(void)
{
	asm volatile("sti": : :"memory");
}

static inline void native_safe_halt(void)
{
	asm volatile("sti; hlt": : :"memory");
}

static inline void native_halt(void)
{
	asm volatile("hlt": : :"memory");
}

#endif

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#else
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
	asm volatile("cli" : : : "memory");
}

static inline void l4x_real_irq_enable(void)
{
	asm volatile("sti" : : : "memory");
}

#endif /* CONFIG_TAMED */
#else /* ! L4 */

static inline unsigned long __raw_local_save_flags(void)
{
	return native_save_fl();
}

static inline void raw_local_irq_restore(unsigned long flags)
{
	native_restore_fl(flags);
}

static inline void raw_local_irq_disable(void)
{
	native_irq_disable();
}

static inline void raw_local_irq_enable(void)
{
	native_irq_enable();
}

#endif /* !L4 */

/*
 * Used in the idle loop; sti takes one instruction cycle
 * to complete:
 */
static inline void raw_safe_halt(void)
{
	native_safe_halt();
}

/*
 * Used when interrupts are already enabled or to
 * shutdown the processor:
 */
static inline void halt(void)
{
	native_halt();
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
#else

#define ENABLE_INTERRUPTS(x)	sti
#define DISABLE_INTERRUPTS(x)	cli

#ifdef CONFIG_X86_64
#define SWAPGS	swapgs
/*
 * Currently paravirt can't handle swapgs nicely when we
 * don't have a stack we can rely on (such as a user space
 * stack).  So we either find a way around these or just fault
 * and emulate if a guest tries to call swapgs directly.
 *
 * Either way, this is a good way to document that we don't
 * have a reliable stack. x86_64 only.
 */
#define SWAPGS_UNSAFE_STACK	swapgs

#define PARAVIRT_ADJUST_EXCEPTION_FRAME	/*  */

#define INTERRUPT_RETURN	iretq
#define USERGS_SYSRET64				\
	swapgs;					\
	sysretq;
#define USERGS_SYSRET32				\
	swapgs;					\
	sysretl
#define ENABLE_INTERRUPTS_SYSEXIT32		\
	swapgs;					\
	sti;					\
	sysexit

#else
#define INTERRUPT_RETURN		iret
#define ENABLE_INTERRUPTS_SYSEXIT	sti; sysexit
#define GET_CR0_INTO_EAX		movl %cr0, %eax
#endif


#endif /* __ASSEMBLY__ */
#endif /* CONFIG_PARAVIRT */

#ifndef __ASSEMBLY__
#define raw_local_save_flags(flags)				\
	do { (flags) = __raw_local_save_flags(); } while (0)

#define raw_local_irq_save(flags)				\
	do { (flags) = __raw_local_irq_save(); } while (0)

static inline int raw_irqs_disabled_flags(unsigned long flags)
{
#if defined(CONFIG_L4_USERPRIV_ONLY) || defined(CONFIG_L4_TAMED)
	return flags == L4_IRQ_DISABLED;
#else
	return !(flags & X86_EFLAGS_IF);
#endif
}

static inline int raw_irqs_disabled(void)
{
	unsigned long flags = __raw_local_save_flags();

	return raw_irqs_disabled_flags(flags);
}

#else

#ifdef CONFIG_X86_64
#define ARCH_LOCKDEP_SYS_EXIT		call lockdep_sys_exit_thunk
#define ARCH_LOCKDEP_SYS_EXIT_IRQ	\
	TRACE_IRQS_ON; \
	sti; \
	SAVE_REST; \
	LOCKDEP_SYS_EXIT; \
	RESTORE_REST; \
	cli; \
	TRACE_IRQS_OFF;

#else
#define ARCH_LOCKDEP_SYS_EXIT			\
	pushl %eax;				\
	pushl %ecx;				\
	pushl %edx;				\
	call lockdep_sys_exit;			\
	popl %edx;				\
	popl %ecx;				\
	popl %eax;

#define ARCH_LOCKDEP_SYS_EXIT_IRQ
#endif

#ifdef CONFIG_TRACE_IRQFLAGS
#  define TRACE_IRQS_ON		call trace_hardirqs_on_thunk;
#  define TRACE_IRQS_OFF	call trace_hardirqs_off_thunk;
#else
#  define TRACE_IRQS_ON
#  define TRACE_IRQS_OFF
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
#  define LOCKDEP_SYS_EXIT	ARCH_LOCKDEP_SYS_EXIT
#  define LOCKDEP_SYS_EXIT_IRQ	ARCH_LOCKDEP_SYS_EXIT_IRQ
# else
#  define LOCKDEP_SYS_EXIT
#  define LOCKDEP_SYS_EXIT_IRQ
# endif

#endif /* __ASSEMBLY__ */
#endif
