/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

/*
 * 'Traps.c' handles hardware traps and faults after we have saved some
 * state in 'asm.s'.
 */
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/highmem.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/kdebug.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/unwind.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/kexec.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/init.h>
#include <linux/bug.h>
#include <linux/nmi.h>
#include <linux/mm.h>

#ifdef CONFIG_EISA
#include <linux/ioport.h>
#include <linux/eisa.h>
#endif

#ifdef CONFIG_MCA
#include <linux/mca.h>
#endif

#if defined(CONFIG_EDAC)
#include <linux/edac.h>
#endif

#include <asm/arch_hooks.h>
#include <asm/stacktrace.h>
#include <asm/processor.h>
#include <asm/debugreg.h>
#include <asm/atomic.h>
#include <asm/system.h>
#include <asm/unwind.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/nmi.h>
#include <asm/smp.h>
#include <asm/io.h>

#include "mach_traps.h"

#include <asm/api/ids.h>
#include <asm/api/macros.h>

#include <asm/generic/memory.h>
#include <asm/generic/kthreads.h>
#include <asm/generic/task.h>

#include <l4/sys/syscalls.h>
#include <asm/l4lxapi/thread.h>


int panic_on_unrecovered_nmi;

DECLARE_BITMAP(used_vectors, NR_VECTORS);
EXPORT_SYMBOL_GPL(used_vectors);

asmlinkage int system_call(void);

/* Do we ignore FPU interrupts ? */
char ignore_fpu_irq;

/*
 * The IDT has to be page-aligned to simplify the Pentium
 * F0 0F bug workaround.. We have a special link segment
 * for this.
 */
gate_desc idt_table[256]
	__attribute__((__section__(".data.idt"))) = { { { { 0, 0 } } }, };

void divide_error(void);
void debug(void);
void nmi(void);
void int3(void);
void overflow(void);
void bounds(void);
void invalid_op(void);
void device_not_available(void);
void double_fault(void);
void coprocessor_segment_overrun(void);
void invalid_TSS(void);
void segment_not_present(void);
void stack_segment(void);
void general_protection(void);
void page_fault(void);
void coprocessor_error(void);
void simd_coprocessor_error(void);
void alignment_check(void);
void spurious_interrupt_bug(void);
#ifdef CONFIG_X86_MCE
void machine_check(void);
#endif

int kstack_depth_to_print = 24;
static unsigned int code_bytes = 64;

void printk_address(unsigned long address, int reliable)
{
#ifdef CONFIG_KALLSYMS
	char namebuf[KSYM_NAME_LEN];
	unsigned long offset = 0;
	unsigned long symsize;
	const char *symname;
	char reliab[4] = "";
	char *delim = ":";
	char *modname;

	symname = kallsyms_lookup(address, &symsize, &offset,
					&modname, namebuf);
	if (!symname) {
		printk(" [<%08lx>]\n", address);
		return;
	}
	if (!reliable)
		strcpy(reliab, "? ");

	if (!modname)
		modname = delim = "";
	printk(" [<%08lx>] %s%s%s%s%s+0x%lx/0x%lx\n",
		address, reliab, delim, modname, delim, symname, offset, symsize);
#else
	printk(" [<%08lx>]\n", address);
#endif
}

static inline int valid_stack_ptr(struct thread_info *tinfo, void *p, unsigned size)
{
	return	p > (void *)tinfo &&
		p <= (void *)tinfo + THREAD_SIZE - size;
}

/* The form of the top of the frame on the stack */
struct stack_frame {
	struct stack_frame*next_frame;
	unsigned longreturn_address;
};

static inline unsigned long
print_context_stack(struct thread_info *tinfo,
		    unsigned long *stack, unsigned long bp,
		    const struct stacktrace_ops *ops, void *data)
{
	struct stack_frame *frame = (struct stack_frame *)bp;

	while (valid_stack_ptr(tinfo, stack, sizeof(*stack))) {
		unsigned long addr;

		addr = *stack;
		if (__kernel_text_address(addr)) {
			if ((unsigned long) stack == bp + 4) {
				ops->address(data, addr, 1);
				frame = frame->next_frame;
				bp = (unsigned long) frame;
			} else {
				ops->address(data, addr, bp == 0);
			}
		}
		stack++;
	}
	return bp;
}

#define MSG(msg)		ops->warning(data, msg)

void dump_trace(struct task_struct *task, struct pt_regs *regs,
		unsigned long *stack, unsigned long bp,
		const struct stacktrace_ops *ops, void *data)
{
	if (!task)
		task = current;

	if (!stack) {
		unsigned long dummy;

		stack = &dummy;
		if (task != current)
			stack = (unsigned long *)task->thread.sp;
	}

#ifdef CONFIG_FRAME_POINTER
	if (!bp) {
		if (task == current) {
			/* Grab bp right from our regs */
			asm("movl %%ebp, %0" : "=r" (bp) :);
		} else {
			/* bp is the last reg pushed by switch_to */
			bp = *(unsigned long *) task->thread.sp;
		}
	}
#endif

	while (1) {
		struct thread_info *context;

		context = (struct thread_info *)
			((unsigned long)stack & (~(THREAD_SIZE - 1)));
		bp = print_context_stack(context, stack, bp, ops, data);
		/*
		 * Should be after the line below, but somewhere
		 * in early boot context comes out corrupted and we
		 * can't reference it:
		 */
		if (ops->stack(data, "IRQ") < 0)
			break;
		stack = (unsigned long *)context->previous_esp;
		if (!stack)
			break;
		touch_nmi_watchdog();
	}
}
EXPORT_SYMBOL(dump_trace);

static void
print_trace_warning_symbol(void *data, char *msg, unsigned long symbol)
{
	printk(data);
	print_symbol(msg, symbol);
	printk("\n");
}

static void print_trace_warning(void *data, char *msg)
{
	printk("%s%s\n", (char *)data, msg);
}

static int print_trace_stack(void *data, char *name)
{
	return 0;
}

/*
 * Print one address/symbol entries per line.
 */
static void print_trace_address(void *data, unsigned long addr, int reliable)
{
	printk("%s [<%08lx>] ", (char *)data, addr);
	if (!reliable)
		printk("? ");
	print_symbol("%s\n", addr);
	touch_nmi_watchdog();
}

static const struct stacktrace_ops print_trace_ops = {
	.warning		= print_trace_warning,
	.warning_symbol		= print_trace_warning_symbol,
	.stack			= print_trace_stack,
	.address		= print_trace_address,
};

static void
show_trace_log_lvl(struct task_struct *task, struct pt_regs *regs,
		   unsigned long *stack, unsigned long bp, char *log_lvl)
{
	dump_trace(task, regs, stack, bp, &print_trace_ops, log_lvl);
	printk("%s =======================\n", log_lvl);
}

void show_trace(struct task_struct *task, struct pt_regs *regs,
		unsigned long *stack, unsigned long bp)
{
	show_trace_log_lvl(task, regs, stack, bp, "");
}

static void
show_stack_log_lvl(struct task_struct *task, struct pt_regs *regs,
		   unsigned long *sp, unsigned long bp, char *log_lvl)
{
	unsigned long *stack;
	int i;

	if (sp == NULL) {
		if (task)
			sp = (unsigned long *)task->thread.sp;
		else
			sp = (unsigned long *)&sp;
	}

	stack = sp;
	for (i = 0; i < kstack_depth_to_print; i++) {
		if (kstack_end(stack))
			break;
		if (i && ((i % 8) == 0))
			printk("\n%s       ", log_lvl);
		printk("%08lx ", *stack++);
	}
	printk("\n%sCall Trace:\n", log_lvl);

	show_trace_log_lvl(task, regs, sp, bp, log_lvl);
}

void show_stack(struct task_struct *task, unsigned long *sp)
{
	printk("       ");
	show_stack_log_lvl(task, NULL, sp, 0, "");
}

/*
 * The architecture-independent dump_stack generator
 */
void dump_stack(void)
{
	unsigned long bp = 0;
	unsigned long stack;

#ifdef CONFIG_FRAME_POINTER
	if (!bp)
		asm("movl %%ebp, %0" : "=r" (bp):);
#endif

	printk("Pid: %d, comm: %.20s %s %s %.*s\n",
		current->pid, current->comm, print_tainted(),
		init_utsname()->release,
		(int)strcspn(init_utsname()->version, " "),
		init_utsname()->version);

	show_trace(current, NULL, &stack, bp);
}

EXPORT_SYMBOL(dump_stack);

void show_registers(struct pt_regs *regs)
{
	int i;

	print_modules();
	__show_registers(regs, 0);

	printk(KERN_EMERG "Process %.*s (pid: %d, ti=%p task=%p task.ti=%p)",
		TASK_COMM_LEN, current->comm, task_pid_nr(current),
		current_thread_info(), current, task_thread_info(current));
	/*
	 * When in-kernel, we also print out the stack and code at the
	 * time of the fault..
	 */
	if (!user_mode_vm(regs)) {
		unsigned int code_prologue = code_bytes * 43 / 64;
		unsigned int code_len = code_bytes;
		unsigned char c;
		u8 *ip;

		printk("\n" KERN_EMERG "Stack: ");
		show_stack_log_lvl(NULL, regs, &regs->sp, 0, KERN_EMERG);

		printk(KERN_EMERG "Code: ");

		ip = (u8 *)regs->ip - code_prologue;
		if (ip < (u8 *)PAGE_OFFSET ||
			probe_kernel_address(ip, c)) {
			/* try starting at EIP */
			ip = (u8 *)regs->ip;
			code_len = code_len - code_prologue + 1;
		}
		for (i = 0; i < code_len; i++, ip++) {
#if 0
			if (ip < (u8 *)PAGE_OFFSET ||
				probe_kernel_address(ip, c)) {
				printk(" Bad EIP value.");
				break;
			}
#else
			c = *(unsigned char *)ip;
#endif
			if (ip == (u8 *)regs->ip)
				printk("<%02x> ", c);
			else
				printk("%02x ", c);
		}
	}
	printk("\n");
}

int is_valid_bugaddr(unsigned long ip)
{
	unsigned short ud2;

	if (ip < PAGE_OFFSET)
		return 0;
	if (probe_kernel_address((unsigned short *)ip, ud2))
		return 0;

	return ud2 == 0x0b0f;
}

static int die_counter;

int __kprobes __die(const char *str, struct pt_regs *regs, long err)
{
	unsigned short ss;
	unsigned long sp;

	printk(KERN_EMERG "%s: %04lx [#%d] ", str, err & 0xffff, ++die_counter);
#ifdef CONFIG_PREEMPT
	printk("PREEMPT ");
#endif
#ifdef CONFIG_SMP
	printk("SMP ");
#endif
#ifdef CONFIG_DEBUG_PAGEALLOC
	printk("DEBUG_PAGEALLOC");
#endif
	printk("\n");

	if (notify_die(DIE_OOPS, str, regs, err,
			current->thread.trap_no, SIGSEGV) != NOTIFY_STOP) {

		show_registers(regs);
		/* Executive summary in case the oops scrolled away */
		sp = (unsigned long) (&regs->sp);
		savesegment(ss, ss);
		if (user_mode(regs)) {
			sp = regs->sp;
			ss = regs->ss & 0xffff;
		}
		printk(KERN_EMERG "EIP: [<%08lx>] ", regs->ip);
		print_symbol("%s", regs->ip);
		printk(" SS:ESP %04x:%08lx\n", ss, sp);

		return 0;
	}

	return 1;
}

/*
 * This is gone through when something in the kernel has done something bad
 * and is about to be terminated:
 */
void die(const char *str, struct pt_regs *regs, long err)
{
	static struct {
		raw_spinlock_t lock;
		u32 lock_owner;
		int lock_owner_depth;
	} die = {
		.lock =			__RAW_SPIN_LOCK_UNLOCKED,
		.lock_owner =		-1,
		.lock_owner_depth =	0
	};
	unsigned long flags;

	oops_enter();

	if (die.lock_owner != raw_smp_processor_id()) {
		console_verbose();
		raw_local_irq_save(flags);
		__raw_spin_lock(&die.lock);
		die.lock_owner = smp_processor_id();
		die.lock_owner_depth = 0;
		bust_spinlocks(1);
	} else {
		raw_local_irq_save(flags);
	}

	if (++die.lock_owner_depth < 3) {
		report_bug(regs->ip, regs);

		if (__die(str, regs, err))
			regs = NULL;
	} else {
		printk(KERN_EMERG "Recursive die() failure, output suppressed\n");
	}

	bust_spinlocks(0);
	die.lock_owner = -1;
	add_taint(TAINT_DIE);
	__raw_spin_unlock(&die.lock);
	raw_local_irq_restore(flags);

	if (!regs)
		return;

	if (kexec_should_crash(current))
		crash_kexec(regs);

	if (in_interrupt())
		panic("Fatal exception in interrupt");

	if (panic_on_oops)
		panic("Fatal exception");

	oops_exit();
	do_exit(SIGSEGV);
}

static inline void
die_if_kernel(const char *str, struct pt_regs *regs, long err)
{
	if (!user_mode_vm(regs))
		die(str, regs, err);
}

#ifdef CONFIG_SMP
void __kprobes die_nmi(struct pt_regs *regs, const char *msg)
{
	printk("die_nmi: %s\n", msg);
	printk("Doing nothing\n");
	do_exit(SIGSEGV);
}
#endif

void do_kernel_error(const char * str, struct pt_regs * regs, long error_code)
{
/* 	current->thread.error_code = error_code; */
/* 	current->thread.trap_no = trapnr; */
	die(str, regs, error_code);
}

void unexpected_ret_from_exception(const char * str, struct pt_regs * regs, long error_code)
{
  	printk("unexpected_ret_from_exception: %s returned\n", str);
	panic("unexpected_ret_from_exception");
}

#define DO_ERROR(trapnr, signr, die_nr, str, name, tsk)			\
void __kprobes do_##name(struct pt_regs * regs, long error_code) \
{									\
	if (notify_die(die_nr, str, regs, error_code, trapnr, signr)	\
						== NOTIFY_STOP)		\
		return;							\
	tsk->thread.error_code = error_code;				\
	tsk->thread.trap_no = trapnr;					\
	force_sig(signr, tsk);						\
}

DO_ERROR( 0, SIGFPE,  DIE_TRAP,  "divide error", divide_error, current)
DO_ERROR( 1, SIGTRAP, DIE_DEBUG, "debug", debug, current)
DO_ERROR( 3, SIGTRAP, DIE_INT3,  "int3", int3, current)
DO_ERROR( 4, SIGSEGV, DIE_TRAP,  "overflow", overflow, current)
DO_ERROR( 5, SIGSEGV, DIE_TRAP,  "bounds", bounds, current)
DO_ERROR( 6, SIGILL,  DIE_TRAP,  "invalid opcode", invalid_op, current)
DO_ERROR( 7, SIGSEGV, DIE_TRAP,  "device not available", device_not_available, current)
DO_ERROR( 8, SIGSEGV, DIE_TRAP,  "double fault", double_fault, current)
DO_ERROR( 9, SIGFPE,  DIE_TRAP,  "coprocessor segment overrun", coprocessor_segment_overrun, current)
DO_ERROR(10, SIGSEGV, DIE_TRAP,  "invalid TSS", invalid_TSS, current)
DO_ERROR(11, SIGBUS,  DIE_TRAP,  "segment not present", segment_not_present, current)
DO_ERROR(12, SIGBUS,  DIE_TRAP,  "stack segment", stack_segment, current)
DO_ERROR(13, SIGSEGV, DIE_TRAP,  "general protection", general_protection, current)
DO_ERROR(17, SIGBUS,  DIE_TRAP,  "alignment check", alignment_check, current)
#ifdef CONFIG_X86_MCE
DO_ERROR(18, SIGSEGV, DIE_TRAP,  "machine check", machine_check, current)
#endif
DO_ERROR(19, SIGFPE,  DIE_TRAP,  "simd coprocessor error", simd_coprocessor_error, current)

void do_nmi(struct pt_regs * regs, long error_code)
{
}

void stop_nmi(void)
{
	printk("%s called\n", __func__);
}

void restart_nmi(void)
{
	printk("%s called\n", __func__);
}


void do_spurious_interrupt_bug(struct pt_regs * regs, long error_code)
{
}

/*
 * Note that we play around with the 'TS' bit in an attempt to get
 * the correct behaviour even in the presence of the asynchronous
 * IRQ13 behaviour
 */
void math_error(void)
{
	struct task_struct * task;

	/*
	 * Save the info for the exception handler and clear the error.
	 */
	task = current;
	task->thread.trap_no = 16;
	task->thread.error_code = 0;
	force_sig(SIGFPE, task);
}

void do_coprocessor_error(struct pt_regs * regs, long error_code)
{
	math_error();
}

asmlinkage void math_state_restore(void)
{
	struct thread_info *thread = current_thread_info();
	struct task_struct *tsk = thread->task;

	clts();		/* Allow maths ops (or we recurse) */
	if (!tsk_used_math(tsk))
		init_fpu(tsk);
	restore_fpu(tsk);
	thread->status |= TS_USEDFPU;	/* So we fnsave on switch_to() */
	tsk->fpu_counter++;
}
EXPORT_SYMBOL_GPL(math_state_restore);

/* Called from init/main.c */
void __init trap_init(void)
{

	init_thread_xstate();

	cpu_init();

	//trap_init_hook();
}

int l4x_deliver_signal(int exception_nr, int errcode)
{
	/* use exception entry points within kernel
	 * e.g. do_divide_error( struct ptregs * regs, long error);
	 */

	current->thread.regs.orig_ax = -1;

	switch (exception_nr) {
	case 0:
		do_divide_error(&current->thread.regs, errcode);
		break;
	case 1:
		do_debug(&current->thread.regs, errcode);
		break;
	case 2:
		do_nmi(&current->thread.regs, errcode);
		break;
	case 3:
		do_int3(&current->thread.regs, errcode);
		break;
	case 4:
		do_overflow(&current->thread.regs, errcode);
		break;
	case 5:
		do_bounds(&current->thread.regs, errcode);
		break;
	case 6:
		do_invalid_op(&current->thread.regs, errcode);
		break;
	case 7:			/* no */
		do_device_not_available(&current->thread.regs, errcode);
		break;
	case 8:			/* no */
		do_double_fault(&current->thread.regs, errcode);
		break;
	case 9:			/* no */
		do_coprocessor_segment_overrun(&current->thread.regs, errcode);
		break;
	case 10:		/* no */
		do_invalid_TSS(&current->thread.regs, errcode);
		break;
	case 11:
		do_segment_not_present(&current->thread.regs, errcode);
		break;
	case 12:
		do_stack_segment(&current->thread.regs, errcode);
		break;
	case 13:
	case 14:
		do_general_protection(&current->thread.regs, errcode);
		break;
	case 15:
		do_spurious_interrupt_bug(&current->thread.regs, errcode);
		break;
	case 16:
		do_coprocessor_error(&current->thread.regs, errcode);
		break;
	case 17:
		do_alignment_check(&current->thread.regs, errcode);
		break;
#ifdef CONFIG_X86_MCE
	case 18:
		do_machine_check(&current->thread.regs, errcode);
		break;
#endif
	case 19:
		do_simd_coprocessor_error(&current->thread.regs, errcode);
		break;
	default:
		printk("Unknown exception: %d\n", exception_nr);
		enter_kdebug("deliver_signal:unknown exception");
		break;
	}

	if (signal_pending(current)) {
		extern void do_signal(struct pt_regs *regs);
		do_signal(&current->thread.regs);
		return 1;
	}
	return 0;
}

static int __init kstack_setup(char *s)
{
	kstack_depth_to_print = simple_strtoul(s, NULL, 0);
	return 1;
}
__setup("kstack=", kstack_setup);

static int __init code_bytes_setup(char *s)
{
	code_bytes = simple_strtoul(s, NULL, 0);
	if (code_bytes > 8192)
		code_bytes = 8192;

	return 1;
}
__setup("code_bytes=", code_bytes_setup);
