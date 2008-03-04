/*
 *  linux/arch/arm/kernel/process.c
 *
 *  Copyright (C) 1996-2000 Russell King - Converted to ARM.
 *  Original Copyright (C) 1995  Linus Torvalds
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <stdarg.h>

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/user.h>
#include <linux/a.out.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/elfcore.h>
#include <linux/pm.h>
#include <linux/tick.h>
#include <linux/utsname.h>

#include <asm/leds.h>
#include <asm/processor.h>
#include <asm/system.h>
#include <asm/thread_notify.h>
#include <asm/uaccess.h>
#include <asm/mach/time.h>

#include <asm/generic/dispatch.h>
#include <asm/generic/task.h>
#include <asm/generic/sched.h>
#include <asm/generic/stack_id.h>
#include <asm/generic/hybrid.h>

#include <asm/l4lxapi/task.h>

#include <l4/sys/kdebug.h>

static const char *processor_modes[] = {
  "USER_26", "FIQ_26" , "IRQ_26" , "SVC_26" , "UK4_26" , "UK5_26" , "UK6_26" , "UK7_26" ,
  "UK8_26" , "UK9_26" , "UK10_26", "UK11_26", "UK12_26", "UK13_26", "UK14_26", "UK15_26",
  "USER_32", "FIQ_32" , "IRQ_32" , "SVC_32" , "UK4_32" , "UK5_32" , "UK6_32" , "ABT_32" ,
  "UK8_32" , "UK9_32" , "UK10_32", "UND_32" , "UK12_32", "UK13_32", "UK14_32", "SYS_32"
};

static const char *isa_modes[] = {
  "ARM" , "Thumb" , "Jazelle", "ThumbEE"
};

extern void setup_mm_for_reboot(char mode);

int thread_create_user(struct task_struct *p, int fork);

static volatile int hlt_counter;

#include <asm/arch/system.h>

void disable_hlt(void)
{
	hlt_counter++;
}

EXPORT_SYMBOL(disable_hlt);

void enable_hlt(void)
{
	hlt_counter--;
}

EXPORT_SYMBOL(enable_hlt);

static int __init nohlt_setup(char *__unused)
{
	hlt_counter = 1;
	return 1;
}

static int __init hlt_setup(char *__unused)
{
	hlt_counter = 0;
	return 1;
}

__setup("nohlt", nohlt_setup);
__setup("hlt", hlt_setup);

void arm_machine_restart(char mode)
{
	/*
	 * Clean and disable cache, and turn off interrupts
	 */
	cpu_proc_fin();

	/*
	 * Tell the mm system that we are going to reboot -
	 * we may need it to insert some 1:1 mappings so that
	 * soft boot works.
	 */
	setup_mm_for_reboot(mode);

	/*
	 * Now call the architecture specific reboot code.
	 */
	arch_reset(mode);

	/*
	 * Whoops - the architecture was unable to reboot.
	 * Tell the user!
	 */
	mdelay(1000);
	printk("Reboot failed -- System halted\n");
	while (1);
}

/*
 * Function pointers to optional machine specific functions
 */
void (*pm_idle)(void);
EXPORT_SYMBOL(pm_idle);

void (*pm_power_off)(void);
EXPORT_SYMBOL(pm_power_off);

void (*arm_pm_restart)(char str) = arm_machine_restart;
EXPORT_SYMBOL_GPL(arm_pm_restart);


/*
 * This is our default idle handler.  We need to disable
 * interrupts here to ensure we don't miss a wakeup call.
 */
#if 0
static void default_idle(void)
{
	if (hlt_counter)
		cpu_relax();
	else {
		local_irq_disable();
		if (!need_resched()) {
			timer_dyn_reprogram();
			arch_idle();
		}
		local_irq_enable();
	}
}
#endif

/*
 * The idle thread.  We try to conserve power, while trying to keep
 * overall latency low.  The architecture specific idle is passed
 * a value to indicate the level of "idleness" of the system.
 */
void cpu_idle(void)
{
#if 0
	local_fiq_enable();

	/* endless idle loop with no priority at all */
	while (1) {
		void (*idle)(void) = pm_idle;

#ifdef CONFIG_HOTPLUG_CPU
		if (cpu_is_offline(smp_processor_id())) {
			leds_event(led_idle_start);
			cpu_die();
		}
#endif

		if (!idle)
			idle = default_idle;
		leds_event(led_idle_start);
		tick_nohz_stop_sched_tick();
		while (!need_resched())
			idle();
		leds_event(led_idle_end);
		tick_nohz_restart_sched_tick();
		preempt_enable_no_resched();
		schedule();
		preempt_disable();
	}
#endif
	while (1)
		l4x_idle();
}

static char reboot_mode = 'h';

int __init reboot_setup(char *str)
{
	reboot_mode = str[0];
	return 1;
}

__setup("reboot=", reboot_setup);

void machine_halt(void)
{
}


void machine_power_off(void)
{
	if (pm_power_off)
		pm_power_off();
}

void machine_restart(char * __unused)
{
	arm_pm_restart(reboot_mode);
}

void __show_regs(struct pt_regs *regs)
{
	unsigned long flags;
	char buf[64];

	printk("CPU: %d    %s  (%s %.*s)\n",
		smp_processor_id(), print_tainted(), init_utsname()->release,
		(int)strcspn(init_utsname()->version, " "),
		init_utsname()->version);
	print_symbol("PC is at %s\n", instruction_pointer(regs));
	print_symbol("LR is at %s\n", regs->ARM_lr);
	printk("pc : [<%08lx>]    lr : [<%08lx>]    psr: %08lx\n"
	       "sp : %08lx  ip : %08lx  fp : %08lx\n",
		regs->ARM_pc, regs->ARM_lr, regs->ARM_cpsr,
		regs->ARM_sp, regs->ARM_ip, regs->ARM_fp);
	printk("r10: %08lx  r9 : %08lx  r8 : %08lx\n",
		regs->ARM_r10, regs->ARM_r9,
		regs->ARM_r8);
	printk("r7 : %08lx  r6 : %08lx  r5 : %08lx  r4 : %08lx\n",
		regs->ARM_r7, regs->ARM_r6,
		regs->ARM_r5, regs->ARM_r4);
	printk("r3 : %08lx  r2 : %08lx  r1 : %08lx  r0 : %08lx\n",
		regs->ARM_r3, regs->ARM_r2,
		regs->ARM_r1, regs->ARM_r0);

	flags = regs->ARM_cpsr;
	buf[0] = flags & PSR_N_BIT ? 'N' : 'n';
	buf[1] = flags & PSR_Z_BIT ? 'Z' : 'z';
	buf[2] = flags & PSR_C_BIT ? 'C' : 'c';
	buf[3] = flags & PSR_V_BIT ? 'V' : 'v';
	buf[4] = '\0';

	printk("Flags: %s  IRQs o%s  FIQs o%s  Mode %s  ISA %s  Segment %s\n",
		buf, interrupts_enabled(regs) ? "n" : "ff",
		fast_interrupts_enabled(regs) ? "n" : "ff",
		processor_modes[processor_mode(regs)],
		isa_modes[isa_mode(regs)],
		get_fs() == get_ds() ? "kernel" : "user");
#if 0
#ifdef CONFIG_CPU_CP15
	{
		unsigned int ctrl;

		buf[0] = '\0';
#ifdef CONFIG_CPU_CP15_MMU
		{
			unsigned int transbase, dac;
			asm("mrc p15, 0, %0, c2, c0\n\t"
			    "mrc p15, 0, %1, c3, c0\n"
			    : "=r" (transbase), "=r" (dac));
			snprintf(buf, sizeof(buf), "  Table: %08x  DAC: %08x",
			  	transbase, dac);
		}
#endif
		asm("mrc p15, 0, %0, c1, c0\n" : "=r" (ctrl));

		printk("Control: %08x%s\n", ctrl, buf);
	}
#endif
#endif
}

void show_regs(struct pt_regs * regs)
{
	printk("\n");
	printk("Pid: %d, comm: %20s\n", task_pid_nr(current), current->comm);
	__show_regs(regs);
	//__backtrace();
}

void show_fpregs(struct user_fp *regs)
{
	int i;

	for (i = 0; i < 8; i++) {
		unsigned long *p;
		char type;

		p = (unsigned long *)(regs->fpregs + i);

		switch (regs->ftype[i]) {
			case 1: type = 'f'; break;
			case 2: type = 'd'; break;
			case 3: type = 'e'; break;
			default: type = '?'; break;
		}
		if (regs->init_flag)
			type = '?';

		printk("  f%d(%c): %08lx %08lx %08lx%c",
			i, type, p[0], p[1], p[2], i & 1 ? '\n' : ' ');
	}
			

	printk("FPSR: %08lx FPCR: %08lx\n",
		(unsigned long)regs->fpsr,
		(unsigned long)regs->fpcr);
}

/*
 * Free current thread data structures etc..
 */
#if 0
void exit_thread(void)
{
}
#endif

ATOMIC_NOTIFIER_HEAD(thread_notify_head);

EXPORT_SYMBOL_GPL(thread_notify_head);

void flush_thread(void)
{
	struct thread_info *thread = current_thread_info();
	struct task_struct *tsk = current;
	int ret = 0, i;

	if (!current->thread.started)
		return;

	for (i = 0; i < NR_CPUS; i++) {
		l4_threadid_t id = tsk->thread.user_thread_ids[i];

		if (l4_thread_equal(id, L4_NIL_ID))
			continue;

		if (!(ret = l4lx_task_delete(id, l4x_hybrid_list_task_exists(id))))
			do_exit(9);

		if (ret == L4LX_TASK_DELETE_THREAD)
			l4x_hybrid_list_thread_remove(id);
		else {
			l4lx_task_number_free(id);
			l4x_hybrid_list_task_remove(id);
		}

		current->thread.user_thread_ids[i] = L4_NIL_ID;
	}
	current->thread.started = 0;
	current->thread.threads_up = 0;
	current->thread.user_thread_id = L4_NIL_ID;
	current->thread.cloner = L4_NIL_ID;

	memset(thread->used_cp, 0, sizeof(thread->used_cp));
	memset(&tsk->thread.debug, 0, sizeof(struct debug_info));
	memset(&thread->fpstate, 0, sizeof(union fp_state));

	thread_notify(THREAD_NOTIFY_FLUSH, thread);

	set_fs(USER_DS);
}

void release_thread(struct task_struct *dead_task)
{
	struct thread_info *thread = task_thread_info(dead_task);

	thread_notify(THREAD_NOTIFY_RELEASE, thread);
}

extern void kernel_thread_helper(void);
/*
 * Create the kernel context for a new process.  Our main duty here is
 * to fill in p->thread, the arch-specific part of the process'
 * task_struct */
static int l4x_thread_create(struct task_struct *p, unsigned long clone_flags,
                             int inkernel)
{
	struct thread_struct *t = &p->thread;
	int i;

	/* first, allocate task id for  client task */
	if (!inkernel && clone_flags & CLONE_VM) /* is this a user process and vm-cloned? */
		t->cloner = current->thread.user_thread_id;
	else
		t->cloner = L4_NIL_ID;

	for (i = 0; i < NR_CPUS; i++)
		p->thread.user_thread_ids[i] = L4_NIL_ID;
	p->thread.user_thread_id = L4_NIL_ID;
	p->thread.threads_up = 0;

	/* put thread id in stack */
	l4x_stack_setup(p->stack);

	/* if creating a kernel-internal thread, return at this point */
	if (inkernel) {
		task_thread_info(p)->cpu_context.pc = (unsigned long)kernel_thread_helper;
		return 0;
	}

	/* Fix up stack pointer from copy_thread */
	task_thread_info(p)->cpu_context.sp
	   = (unsigned long)p->stack + THREAD_SIZE;

	return 0;
}

asmlinkage void ret_from_fork(void) __asm__("ret_from_fork");

int
copy_thread(int nr, unsigned long clone_flags, unsigned long stack_start,
	    unsigned long stack_size___used_for_inkernel_process_flag,
            struct task_struct *p, struct pt_regs *regs)
{
	struct thread_info *thread = task_thread_info(p);
	struct pt_regs *childregs;

	if (unlikely(stack_size___used_for_inkernel_process_flag == COPY_THREAD_STACK_SIZE___FLAG_INKERNEL))
		childregs = (void *)thread + THREAD_START_SP - sizeof(*regs);
	else
		childregs = task_pt_regs(p);
	*childregs = *regs;
	childregs->ARM_r0 = 0;
	childregs->ARM_sp = stack_start;

	memset(&thread->cpu_context, 0, sizeof(struct cpu_context_save));
	thread->cpu_context.sp = (unsigned long)childregs;
	thread->cpu_context.pc = (unsigned long)ret_from_fork;

	if (clone_flags & CLONE_SETTLS)
		thread->tp_value = regs->ARM_r3;

	/* create the user task */
	return l4x_thread_create(p, clone_flags, stack_size___used_for_inkernel_process_flag == COPY_THREAD_STACK_SIZE___FLAG_INKERNEL);
}

/*
 * fill in the fpe structure for a core dump...
 */
int dump_fpu (struct pt_regs *regs, struct user_fp *fp)
{
	struct thread_info *thread = current_thread_info();
	int used_math = thread->used_cp[1] | thread->used_cp[2];

	if (used_math)
		memcpy(fp, &thread->fpstate.soft, sizeof (*fp));

	return used_math != 0;
}
EXPORT_SYMBOL(dump_fpu);

/*
 * fill in the user structure for a core dump..
 */
void dump_thread(struct pt_regs * regs, struct user * dump)
{
	struct task_struct *tsk = current;

	dump->magic = CMAGIC;
	dump->start_code = tsk->mm->start_code;
	dump->start_stack = regs->ARM_sp & ~(PAGE_SIZE - 1);

	dump->u_tsize = (tsk->mm->end_code - tsk->mm->start_code) >> PAGE_SHIFT;
	dump->u_dsize = (tsk->mm->brk - tsk->mm->start_data + PAGE_SIZE - 1) >> PAGE_SHIFT;
	dump->u_ssize = 0;

	dump->u_debugreg[0] = tsk->thread.debug.bp[0].address;
	dump->u_debugreg[1] = tsk->thread.debug.bp[1].address;
	dump->u_debugreg[2] = tsk->thread.debug.bp[0].insn.arm;
	dump->u_debugreg[3] = tsk->thread.debug.bp[1].insn.arm;
	dump->u_debugreg[4] = tsk->thread.debug.nsaved;

	if (dump->start_stack < 0x04000000)
		dump->u_ssize = (0x04000000 - dump->start_stack) >> PAGE_SHIFT;

	dump->regs = *regs;
	dump->u_fpvalid = dump_fpu (regs, &dump->u_fp);
}
EXPORT_SYMBOL(dump_thread);

/*
 * Shuffle the argument into the correct register before calling the
 * thread function.  r1 is the thread argument, r2 is the pointer to
 * the thread function, and r3 points to the exit function.
 */

asm(	".section .text\n"
"	.align\n"
"	.type	kernel_thread_helper, #function\n"
"kernel_thread_helper:\n"
"	bl	schedule_tail\n"
"	ldmia	sp, {r0 - r9}\n"
// XXX: Correct stack pointer?
//"	add	sp, sp, 12..\n"
"	mov	r0, r1\n"
"	mov	lr, r3\n"
"	mov	pc, r2\n"
"	.size	kernel_thread_helper, . - kernel_thread_helper\n"
"	.previous");

/*
 * Create a kernel thread.
 */
pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)
{
	struct pt_regs regs;

	memset(&regs, 0, sizeof(regs));

	regs.ARM_r1 = (unsigned long)arg;
	regs.ARM_r2 = (unsigned long)fn;
	regs.ARM_r3 = (unsigned long)do_exit;
	//regs.ARM_pc = (unsigned long)kernel_thread_helper;
	//regs.ARM_cpsr = SVC_MODE;

	return do_fork(flags|CLONE_VM|CLONE_UNTRACED, 0, &regs, COPY_THREAD_STACK_SIZE___FLAG_INKERNEL, NULL, NULL);
}
EXPORT_SYMBOL(kernel_thread);

void start_thread(struct pt_regs *regs, unsigned long pc,
		  unsigned long sp)
{
	regs->ARM_pc = pc & ~1;
	regs->ARM_sp = sp;

	current->thread.restart = 1;

	if (pc > TASK_SIZE)
		force_sig(SIGSEGV, current);
}
EXPORT_SYMBOL(start_thread);

unsigned long get_wchan(struct task_struct *p)
{
	unsigned long fp, lr;
	unsigned long stack_start, stack_end;
	int count = 0;
	if (!p || p == current || p->state == TASK_RUNNING)
		return 0;

	stack_start = (unsigned long)end_of_stack(p);
	stack_end = (unsigned long)task_stack_page(p) + THREAD_SIZE;

	fp = thread_saved_fp(p);
	do {
		if (fp < stack_start || fp > stack_end)
			return 0;
		lr = pc_pointer (((unsigned long *)fp)[-1]);
		if (!in_sched_functions(lr))
			return lr;
		fp = *(unsigned long *) (fp - 12);
	} while (count ++ < 16);
	return 0;
}
