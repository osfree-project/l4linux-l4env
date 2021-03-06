/*
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

/*
 * This file handles the architecture-dependent parts of process handling..
 */

#include <linux/stackprotector.h>
#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/elfcore.h>
#include <linux/smp.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/user.h>
#include <linux/interrupt.h>
#include <linux/utsname.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/init.h>
#include <linux/mc146818rtc.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/personality.h>
#include <linux/tick.h>
#include <linux/percpu.h>
#include <linux/prctl.h>
#include <linux/dmi.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/kdebug.h>

#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/ldt.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/desc.h>
#ifdef CONFIG_MATH_EMULATION
#include <asm/math_emu.h>
#endif

#include <linux/err.h>

#include <asm/tlbflush.h>
#include <asm/cpu.h>
#include <asm/idle.h>
#include <asm/syscalls.h>
#include <asm/ds.h>

#include <asm/api/macros.h>
#include <asm/api/ids.h>

#include <asm/generic/sched.h>
#include <asm/generic/dispatch.h>
#include <asm/generic/upage.h>
#include <asm/generic/assert.h>
#include <asm/generic/task.h>
#include <asm/generic/stack_id.h>

#include <asm/l4lxapi/task.h>
#include <asm/l4x/iodb.h>

DEFINE_PER_CPU(struct task_struct *, current_task) = &init_task;
EXPORT_PER_CPU_SYMBOL(current_task);

/*
 * Return saved PC of a blocked thread.
 */
unsigned long thread_saved_pc(struct task_struct *tsk)
{
	return ((unsigned long *)tsk->thread.sp)[3];
}

#ifndef CONFIG_SMP
static inline void play_dead(void)
{
	BUG();
}
#endif

/*
 * The idle thread. There's no useful work to be
 * done, so just try to conserve power and have a
 * low exit latency (ie sit in a loop waiting for
 * somebody to say that they'd like to reschedule)
 */
void cpu_idle(void)
{
	for (;;)
		l4x_idle();
}

void __show_regs(struct pt_regs *regs, int all)
{
#ifdef NOT_FOR_L4
	unsigned long cr0 = 0L, cr2 = 0L, cr3 = 0L, cr4 = 0L;
	unsigned long d0, d1, d2, d3, d6, d7;
#endif
	unsigned long sp;
	unsigned short ss, gs;
	const char *board;

	if (user_mode_vm(regs)) {
		sp = regs->sp;
		ss = regs->ss & 0xffff;
		gs = get_user_gs(regs);
	} else {
		sp = (unsigned long) (&regs->sp);
		savesegment(ss, ss);
		savesegment(gs, gs);
	}

	printk("\n");

	board = dmi_get_system_info(DMI_PRODUCT_NAME);
	if (!board)
		board = "";
	printk("Pid: %d, comm: %s %s (%s %.*s) %s\n",
			task_pid_nr(current), current->comm,
			print_tainted(), init_utsname()->release,
			(int)strcspn(init_utsname()->version, " "),
			init_utsname()->version, board);

	printk("EIP: %04x:[<%08lx>] EFLAGS: %08lx CPU: %d\n",
			(u16)regs->cs, regs->ip, regs->flags,
			smp_processor_id());
	print_symbol("EIP is at %s\n", regs->ip);

	printk("EAX: %08lx EBX: %08lx ECX: %08lx EDX: %08lx\n",
		regs->ax, regs->bx, regs->cx, regs->dx);
	printk("ESI: %08lx EDI: %08lx EBP: %08lx ESP: %08lx\n",
		regs->si, regs->di, regs->bp, sp);
	printk(" DS: %04x ES: %04x FS: %04x GS: %04x SS: %04x\n",
	       (u16)regs->ds, (u16)regs->es, (u16)regs->fs, gs, ss);

	if (!all)
		return;

#ifdef NOT_FOR_L4
	cr0 = read_cr0();
	cr2 = read_cr2();
	cr3 = read_cr3();
	cr4 = read_cr4_safe();
	printk("CR0: %08lx CR2: %08lx CR3: %08lx CR4: %08lx\n",
			cr0, cr2, cr3, cr4);

	get_debugreg(d0, 0);
	get_debugreg(d1, 1);
	get_debugreg(d2, 2);
	get_debugreg(d3, 3);
	printk("DR0: %08lx DR1: %08lx DR2: %08lx DR3: %08lx\n",
			d0, d1, d2, d3);

	get_debugreg(d6, 6);
	get_debugreg(d7, 7);
	printk("DR6: %08lx DR7: %08lx\n",
			d6, d7);
#endif
}

void show_regs(struct pt_regs *regs)
{
	__show_regs(regs, 1);
	{
		unsigned long foo; /* regs->sp is not on the stack */
		show_trace(NULL, regs, &foo, regs->bp);
	}
}

/*
 * Create a kernel thread
 */
int kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)
{
	struct pt_regs regs;

	memset(&regs, 0, sizeof(regs));

	regs.bx = (unsigned long) fn;
	regs.dx = (unsigned long) arg;

	regs.ds = __USER_DS;
	regs.es = __USER_DS;
	regs.fs = __KERNEL_PERCPU;
	regs.gs = __KERNEL_STACK_CANARY;
	regs.orig_ax = -1;
	//regs.ip = (unsigned long) kernel_thread_helper;
	regs.cs = __KERNEL_CS | get_kernel_rpl();
	regs.flags = X86_EFLAGS_IF | X86_EFLAGS_SF | X86_EFLAGS_PF | 0x2;

	/* Ok, create the new process.. */
	return do_fork(flags | CLONE_VM | CLONE_UNTRACED, 0, &regs, COPY_THREAD_STACK_SIZE___FLAG_INKERNEL, NULL, NULL);
}
EXPORT_SYMBOL(kernel_thread);

void release_thread(struct task_struct *dead_task)
{
	//outstring("release_thread\n");
	//printk("%s %d(%s)\n", __func__, current->pid, current->comm);
}

/* defined in kernel/sched.c -- other archs only use this in ASM */
asmlinkage void schedule_tail(struct task_struct *prev);

/* helpers for copy_thread() */
void ret_kernel_thread_start(void);

asm(".section .text\n"
    ".align 4\n"
    "ret_kernel_thread_start: \n\t"
    "call kernel_thread_start \n\t"
    ".previous");

void kernel_thread_start(struct task_struct *p)
{
	struct pt_regs *r = &current->thread.regs;
	int (*func)(void *) = (void *)r->bx;

	schedule_tail(p);
	do_exit(func((void *)r->dx));
}

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
		/* compute pointer to end of stack */
		unsigned long *sp = (unsigned long *)
		       ((unsigned long)p->stack + sizeof(union thread_union));
		/* switch_to will expect the new program pointer
		 * on the stack */
		*(--sp) = (unsigned long) ret_kernel_thread_start;

		t->sp = (unsigned long) sp;
		return 0;
	}

	l4x_setup_user_dispatcher_after_fork(p);
	return 0;
}

/*
 * This gets called before we allocate a new thread and copy
 * the current task into it.
 */
void prepare_to_copy(struct task_struct *tsk)
{
	unlazy_fpu(tsk);
}

int copy_thread(unsigned long clone_flags, unsigned long sp,
	unsigned long stack_size___used_for_inkernel_process_flag,
	struct task_struct *p, struct pt_regs *regs)
{
	struct pt_regs *childregs;
	struct task_struct *cur = current;
	int err;

	childregs = task_pt_regs(p);
	*childregs = *regs;
	childregs->ax = 0;
	childregs->sp = sp;

	childregs->flags |= 0x200;	/* sanity: set EI flag */
	childregs->flags &= 0x1ffff;

	//p->thread.ip = (unsigned long) ret_from_fork;

	/* Copy segment registers */
	p->thread.gs = cur->thread.gs;

	/*
	 * Inherit the IOPL
	 */
	if (unlikely(cur->thread.iodb))
		l4x_iodb_copy(cur, p);

	err = 0;

	/*
	 * Set a new TLS for the child thread?
	 */
	if (clone_flags & CLONE_SETTLS)
		err = do_set_thread_area(p, -1,
			(struct user_desc __user *)childregs->si, 0);

#ifdef NOT_FOR_L4
	if (err && p->thread.io_bitmap_ptr) {
		kfree(p->thread.io_bitmap_ptr);
		p->thread.io_bitmap_max = 0;
	}
#endif

	clear_tsk_thread_flag(p, TIF_DS_AREA_MSR);
	p->thread.ds_ctx = NULL;

	clear_tsk_thread_flag(p, TIF_DEBUGCTLMSR);
	p->thread.debugctlmsr = 0;

	/* create the user task */
	if (!err)
		err = l4x_thread_create(p, clone_flags, stack_size___used_for_inkernel_process_flag == COPY_THREAD_STACK_SIZE___FLAG_INKERNEL);
	return err;
}

void
start_thread(struct pt_regs *regs, unsigned long new_ip, unsigned long new_sp)
{
	//set_user_gs(regs, 0);
	regs->fs		= 0;
	set_fs(USER_DS);
	//regs->ds		= __USER_DS;
	//regs->es		= __USER_DS;
	//regs->ss		= __USER_DS;
	//regs->cs		= __USER_CS;
	regs->ip		= new_ip;
	regs->sp		= new_sp;
	/*
	 * Free the old FP and other extended state
	 */
	free_thread_xstate(current);

	current->thread.gs = 0;

	current->thread.restart = 1;

	if (new_ip > TASK_SIZE)
		force_sig(SIGSEGV, current);
}
EXPORT_SYMBOL(start_thread);

int sys_clone(struct pt_regs *regs)
{
	unsigned long clone_flags;
	unsigned long newsp;
	int __user *parent_tidptr, *child_tidptr;

	clone_flags = regs->bx;
	newsp = regs->cx;
	parent_tidptr = (int __user *)regs->dx;
	child_tidptr = (int __user *)regs->di;
	if (!newsp)
		newsp = regs->sp;
	return do_fork(clone_flags, newsp, regs, COPY_THREAD_STACK_SIZE___FLAG_USER, parent_tidptr, child_tidptr);
}

/*
 * sys_execve() executes a new program.
 */
int sys_execve(struct pt_regs *regs)
{
	int error;
	char *filename;

	filename = getname((char __user *) regs->bx);
	error = PTR_ERR(filename);
	if (IS_ERR(filename))
		goto out;
	error = do_execve(filename,
			(char __user * __user *) regs->cx,
			(char __user * __user *) regs->dx,
			regs);
	if (error == 0) {
		/* Make sure we don't return using sysenter.. */
		//set_thread_flag(TIF_IRET);
	}
	putname(filename);
out:
	return error;
}

/* kernel-internal execve() */
asmlinkage int l4_kernelinternal_execve(char * file, char ** argv, char ** envp)
{
	int ret;
	struct thread_struct *t = &current->thread;

	ASSERT(l4_thread_equal(t->user_thread_id, L4_NIL_ID));

	/* we are going to become a real user task now, so prepare a real
	 * pt_regs structure. */
	/* Enable Interrupts, Set IOPL (needed for X, hwclock etc.) */
	t->regs.flags = 0x3200; /* XXX hardcoded */

	/* do_execve() will create the user task for us in start_thread()
	   and call set_fs(USER_DS) in flush_thread. I know this sounds
	   strange but there are places in the kernel (kernel/kmod.c) which
	   call execve with parameters inside the kernel. They set fs to
	   KERNEL_DS before calling execve so we can't set it back to
	   USER_DS before execve had a chance to look at the name of the
	   executable. */

	ASSERT(segment_eq(get_fs(), KERNEL_DS));
	ret = do_execve(file, argv, envp, &t->regs);

	if (ret < 0) {
		/* we failed -- become a kernel thread again */
		l4lx_task_number_free(t->user_thread_id);
		set_fs(KERNEL_DS);
		t->user_thread_id = L4_NIL_ID;
		return -1;
	}

	l4x_user_dispatcher();

	/* not reached */
	return 0;
}

#define top_esp                (THREAD_SIZE - sizeof(unsigned long))
#define top_ebp                (THREAD_SIZE - 2*sizeof(unsigned long))

unsigned long get_wchan(struct task_struct *p)
{
	unsigned long bp, sp, ip;
	unsigned long stack_page;
	int count = 0;
	if (!p || p == current || p->state == TASK_RUNNING)
		return 0;
	stack_page = (unsigned long)task_stack_page(p);
	sp = p->thread.sp;
	if (!stack_page || sp < stack_page || sp > top_esp+stack_page)
		return 0;

	/* L4Linux has a different layout in switch_to(), but
	 *  the only difference is that we push a return
	 *  address after ebp. So we simply adjust the esp to
	 *  reflect that. And we leave the different name for
	 *  esp to catch direct usage of thread data. */

	sp += 4;/* add 4 to remove return address */

	/* include/asm-i386/system.h:switch_to() pushes bp last. */
	bp = *(unsigned long *) sp;
	do {
		if (bp < stack_page || bp > top_ebp+stack_page)
			return 0;
		ip = *(unsigned long *) (bp+4);
		if (!in_sched_functions(ip))
			return ip;
		bp = *(unsigned long *) bp;
	} while (count++ < 16);
	return 0;
}

