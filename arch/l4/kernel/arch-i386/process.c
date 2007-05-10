/*
 *  arch/l4/kernel/arch-i386/process.c
 */

#include <stdarg.h>

#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/elfcore.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/user.h>
#include <linux/a.out.h>
#include <linux/interrupt.h>
#include <linux/utsname.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/init.h>
#include <linux/mc146818rtc.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/random.h>
#include <linux/personality.h>
#include <linux/tick.h>

#include <asm/uaccess.h>
#include <asm/ldt.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>

#include <asm/api/macros.h>
#include <asm/api/ids.h>

#include <asm/generic/sched.h>
#include <asm/generic/dispatch.h>
#include <asm/generic/upage.h>
#include <asm/generic/task.h>
#include <asm/generic/assert.h>
#include <asm/generic/stack_id.h>
#include <asm/generic/hybrid.h>

#include <asm/l4lxapi/task.h>
#include <asm/l4x/iodb.h>

//#define DEBUG
#define MY_ASSERTIONS

int reboot_thru_bios;

asmlinkage int sys_enosys(void)
{
	return -ENOSYS;
}

static int hlt_counter;

/*
 * Return saved PC of a blocked thread.
 */
unsigned long thread_saved_pc(struct task_struct *tsk)
{
	return ((unsigned long *)tsk->thread.kernel_sp)[0];
}


/*
 * Powermanagement idle function, if any..
 */
void (*pm_idle)(void);

/*
 * Power off function, if any
 */
void (*pm_power_off)(void);

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

void cpu_idle(void)
{
	for (;;)
		l4x_idle();
}

void cpu_idle_wait(void)
{
	printk("%s called: implement me.\n", __func__);
}
EXPORT_SYMBOL_GPL(cpu_idle_wait);

void __init select_idle_routine(const struct cpuinfo_x86 *c)
{
	/* We only have one idle routine, so nothing to select. */
}

void show_regs(struct pt_regs * regs)
{
	printk("\n");

	if (!regs) {
		printk("Can't print regs from interrupt handler: &pt_regs == 0!");
		return;
	}

	printk("Pid: %d, comm: %20s\n", current->pid, current->comm);
	printk("EIP: %08lx CPU: %d\n", regs->eip, smp_processor_id());
	print_symbol("EIP is at %s\n", regs->eip);

	printk(" ESP: %08lx", regs->esp);
	printk(" EFLAGS: %08lx    %s  (%s %.*s)\n",
	       regs->eflags, print_tainted(), init_utsname()->release,
	       (int)strcspn(init_utsname()->version, " "),
	       init_utsname()->version);
	printk("EAX: %08lx EBX: %08lx ECX: %08lx EDX: %08lx\n",
		regs->eax,regs->ebx,regs->ecx,regs->edx);
	printk("ESI: %08lx EDI: %08lx EBP: %08lx\n",
		regs->esi, regs->edi, regs->ebp);
	printk(" DS: %04x ES: %04x FS: %04x\n",
	       0xffff & regs->xds,0xffff & regs->xes, 0xffff & regs->xfs);

	//show_trace(NULL, &regs->esp);
	{
		/* regs->esp is not on the stack */
		unsigned long foo;
		show_trace(NULL, regs, &foo);
	}
}

/*
 * Create a kernel thread
 */
int kernel_thread(int (*fn)(void *), void * arg, unsigned long flags)
{
	struct pt_regs regs;

	memset(&regs, 0, sizeof(regs));

	regs.ebx = (unsigned long) fn;
	regs.edx = (unsigned long) arg;

	regs.xds = __USER_DS;
	regs.xes = __USER_DS;
	regs.xfs = __KERNEL_PDA;
	regs.orig_eax = -1;
	//regs.eip = (unsigned long) kernel_thread_helper;
	regs.xcs = __KERNEL_CS | get_kernel_rpl();
	regs.eflags = X86_EFLAGS_IF | X86_EFLAGS_SF | X86_EFLAGS_PF | 0x2;

	return do_fork(flags | CLONE_VM | CLONE_UNTRACED | CLONE_L4_KERNEL, 0, &regs, 0, NULL, NULL);
}

/*
 * Called by release_task in kernel/exit.c
 */
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
    "pushl %eax               \n\t"
    "call kernel_thread_start \n\t"
    ".previous");

void kernel_thread_start(struct task_struct *p)
{
	struct pt_regs *r = &current->thread.regs;
	int (*func)(void *) = (void *)r->ebx;

	schedule_tail(p);
	do_exit(func((void *)r->edx));
}

/*
 * Create the kernel context for a new process.  Our main duty here is
 * to fill in p->thread, the arch-specific part of the process'
 * task_struct */
static int l4x_thread_create(struct task_struct *p, unsigned long clone_flags)
{
	struct thread_struct *t = &p->thread;

	//printk("%s: %p,%s(%d)\n", __func__, p, p->comm, p->pid);

	/* first, allocate task id for  client task */
	if (!(clone_flags & CLONE_L4_KERNEL)) { /* is this a user process? */
		//if (clone_flags & CLONE_VM)
		//	printk("CLONE_VM set for: %d, %s; parent: %d, %s\n",
		//	       p->pid, p->comm, current->pid, current->comm);
		if (l4lx_task_get_new_task(clone_flags & CLONE_VM ?
		                           current->thread.user_thread_id :
					   L4_NIL_ID,
		                           &t->user_thread_id) < 0) {
			printk("l4x_thread_create: No task no left for user\n"); 
			return -EBUSY;
		}
	} else {
		/* we're a kernel process */
		t->user_thread_id = L4_NIL_ID;
	}

	/* put thread id in stack */
	l4x_stack_setup(p->thread_info);

	/* if creating a kernel-internal thread, return at this point */
	if (clone_flags & CLONE_L4_KERNEL) {
		/* compute pointer to end of stack */
		unsigned long *sp = (unsigned long *)
		       ((unsigned long)p->thread_info + sizeof(union thread_union));
		/* switch_to will expect the new program pointer
		 * on the stack */
		*(--sp) = (unsigned long) ret_kernel_thread_start;

		t->kernel_sp = (unsigned long) sp;
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

int copy_thread(int nr, unsigned long clone_flags, unsigned long esp,
	unsigned long unused,
	struct task_struct * p, struct pt_regs * regs)
{
	struct pt_regs * childregs;
	struct task_struct *cur = current;
	int err;

	/* set up regs for child */
	childregs  = &p->thread.regs;
	*childregs = *regs;
	childregs->eax = 0;
	childregs->esp = esp;

	childregs->eflags |= 0x200;	/* sanity: set EI flag */
	childregs->eflags &= 0x1ffff;

#ifdef DEBUG
	printk("%s: esp: %lx on_page: %x\n",
	       __func__, esp, (int)&childregs->esp);
	printk("%s: current(%p)=%d, new(%p)=%d\n",
	       __func__, current, current->pid, p, p->pid);
	printk("%s: old eflags=%lx, new eflags=%lx\n",
	       __func__, regs->eflags, childregs->eflags);
#endif

	/* Copy segment registers */
	p->thread.gs = cur->thread.gs;
	p->thread.fs = cur->thread.fs;

	/*
	 * Inherit the IOPL
	 */
	if (unlikely(cur->thread.iodb))
		l4x_iodb_copy(cur, p);

	/*
	 * Set a new TLS for the child thread?
	 */
	if (clone_flags & CLONE_SETTLS) {
		struct desc_struct *desc;
		struct user_desc info;
		int idx;

		err = -EFAULT;
		if (copy_from_user(&info, (void __user *)childregs->esi, sizeof(info)))
			goto out;
		err = -EINVAL;
		if (LDT_empty(&info))
			goto out;

		idx = info.entry_number;
		if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX)
			goto out;

		desc = p->thread.tls_array + idx - GDT_ENTRY_TLS_MIN;
		desc->a = LDT_entry_a(&info);
		desc->b = LDT_entry_b(&info);
	}

	/* create the user task */
	err = l4x_thread_create(p, clone_flags);
out:
	return err;
}

/*
 * called by do_execve()/.../flush_old_exec(); should recycle the thread so
 * that a new process can run in it
 */
void flush_thread(void)
{
	struct task_struct *tsk = current;
	l4_threadid_t task = tsk->thread.user_thread_id;
	int ret = 0;

	memset(tsk->thread.tls_array, 0, sizeof(tsk->thread.tls_array));
	clear_tsk_thread_flag(tsk, TIF_DEBUG);

	/* When processes are started from kernel threads there's no
	 * process to flush */
	if (!current->thread.started)
		return;

	// turn back to normal flush-behavior
	//current->mm->context.releasing = 0;

	if ((!l4_thread_equal(task, L4_NIL_ID)) &&
	    !(ret = l4lx_task_delete(task, l4x_hybrid_list_task_exists(task))))
		do_exit(9);

	current->thread.started = 0;

	if (ret == L4LX_TASK_DELETE_THREAD) {
		/*
		 * User task was not alone in its address space before,
		 * we have to create a new address space now.
		 */
		l4x_hybrid_list_thread_remove(task);
		if (l4lx_task_get_new_task(L4_NIL_ID,
		                           &current->thread.user_thread_id) < 0) {
			printk("%s: No task no left for user\n", __func__); 
			do_exit(9);
		}
	} else
		l4x_hybrid_list_task_remove(task);

	/* i386 does this in start_thread but we have to do it earlier since
	   we have to access user space in do_execve */
	set_fs(USER_DS);

	/*
	 * Forget coprocessor state..
	 */
	clear_fpu(tsk);
	clear_used_math();
}

void start_thread(struct pt_regs *regs, unsigned long eip,
                  unsigned long esp)
{
	regs->eip = eip;
	regs->esp = esp;

	current->thread.gs = 0;
	current->thread.fs = 0;

	current->thread.restart = 1;

	if (eip > TASK_SIZE)
		force_sig(SIGSEGV, current);
}
EXPORT_SYMBOL(start_thread);

/* next is from arch/i386/kernel/process.c and adjusted to new pt_regs
   structure */
void dump_thread(struct pt_regs * regs, struct user * dump)
{
	int i;

/* changed the size calculations - should hopefully work better. lbt */
	dump->magic = CMAGIC;
	dump->start_code = 0;
	dump->start_stack = regs->esp & ~(PAGE_SIZE - 1);
	dump->u_tsize = ((unsigned long) current->mm->end_code) >> PAGE_SHIFT;
	dump->u_dsize = ((unsigned long) (current->mm->brk + (PAGE_SIZE-1))) >> PAGE_SHIFT;
	dump->u_dsize -= dump->u_tsize;
	dump->u_ssize = 0;
	for (i = 0; i < 8; i++)
		dump->u_debugreg[i] = 0; //current->debugreg[i];  

	if (dump->start_stack < TASK_SIZE)
		dump->u_ssize = ((unsigned long) (TASK_SIZE - dump->start_stack)) >> PAGE_SHIFT;

	/* copy register contents */
	memset((void *)&dump->regs, 0, (size_t)sizeof(dump->regs));
	dump->regs.ebx = regs->ebx;
	dump->regs.ecx = regs->ecx;
	dump->regs.edx = regs->edx;
	dump->regs.esi = regs->esi;
	dump->regs.edi = regs->edi;
	dump->regs.ebp = regs->ebp;
	dump->regs.eax = regs->eax;
	dump->regs.fs = regs->xfs;
	dump->regs.orig_eax = regs->orig_eax;
	dump->regs.eip = regs->eip;
	dump->regs.eflags = regs->eflags;
	dump->regs.esp = regs->esp;

	dump->u_fpvalid = dump_fpu (regs, &dump->i387);
}
EXPORT_SYMBOL(dump_thread);

/* 
 * Capture the user space registers if the task is not running (in user space)
 */
int dump_task_regs(struct task_struct *tsk, elf_gregset_t *regs)
{
	struct pt_regs ptregs = *task_pt_regs(tsk);
#if 0
	ptregs.xcs &= 0xffff;
	ptregs.xds &= 0xffff;
	ptregs.xes &= 0xffff;
	ptregs.xss &= 0xffff;
#endif

	elf_core_copy_regs(regs, &ptregs);

	return 1;
}


/* fork/exec system calls (copied from arch/i386/kernel/process.c) */

asmlinkage int sys_fork(void)
{
	struct pt_regs *regs = &current->thread.regs;
	return do_fork(SIGCHLD, regs->esp, regs, 0, NULL, NULL);
}

asmlinkage int sys_clone(void)
{
	struct pt_regs *regs = &current->thread.regs;
	unsigned long clone_flags;
	unsigned long newsp;
	int __user *parent_tidptr, *child_tidptr;

	clone_flags = regs->ebx & ~CLONE_L4_KERNEL;
	newsp = regs->ecx;
	parent_tidptr = (int __user *)regs->edx;
	child_tidptr = (int __user *)regs->edi;
	if (!newsp)
		newsp = regs->esp;

	return do_fork(clone_flags, newsp, regs, 0, parent_tidptr, child_tidptr);
}


/*
 * This is trivial, and on the face of it looks like it
 * could equally well be done in user mode.
 *
 * Not so, for quite unobvious reasons - register pressure.
 * In user mode vfork() cannot have a stack frame, and if
 * done by calling the "clone()" system call directly, you
 * do not have enough call-clobbered registers to hold all
 * the information you need.
 */
asmlinkage int sys_vfork(void)
{
	struct pt_regs *regs = &current->thread.regs;

	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, regs->esp, regs, 0, NULL, NULL);
}

/*
 * sys_execve() executes a new program.
 */
/* sys_*(ebx, ecx, edx, esi, edi); */
asmlinkage int sys_execve(char *name, char **argv, char **envp)
{
	int error;
	char * filename;

	filename = getname(name);
	error = PTR_ERR(filename);
	if (IS_ERR(filename))
		goto out;

	error = do_execve(filename, argv, envp,
			&current->thread.regs);
	if (error == 0) {
		task_lock(current);
		current->ptrace &= ~PT_DTRACE;
		task_unlock(current);
	}
	putname(filename);
out:
	return error;
}

/* kernel-internal execve() */
int l4_kernelinternal_execve(char * file, char ** argv, char ** envp)
{
	int error;

	ASSERT(l4_thread_equal(current->thread.user_thread_id, L4_NIL_ID));

	/* we are going to become a real user task now, so prepare a real
	 * pt_regs structure. */
	/* Enable Interrupts, Set IOPL (needed for X, hwclock etc.) */
	current->thread.regs.eflags = 0x3200; /* XXX hardcoded */

	/* we're about to exec, so get a task id now */
	if (l4lx_task_get_new_task(L4_NIL_ID, &current->thread.user_thread_id) < 0) {
		printk("execve: No task no left for user\n");
		return -1;
	}

	/* do_execve() will create the user task for us in start_thread()
	   and call set_fs(USER_DS) in flush_thread. I know this sounds
	   strange but there are places in the kernel (kernel/kmod.c) which
	   call execve with parameters inside the kernel. They set fs to
	   KERNEL_DS before calling execve so we can't set it back to
	   USER_DS before execve had a chance to look at the name of the
	   executable. */

	ASSERT(segment_eq(get_fs(), KERNEL_DS));
	lock_kernel();
	error = do_execve(file, argv, envp, &current->thread.regs);

	if (error < 0) {
		/* we failed -- become a kernel thread again */
		//printk("Error in kernel-internal exec for " PRINTF_L4TASK_FORM ": %d\n", PRINTF_L4TASK_ARG(current->thread.user_thread_id), error);
		l4lx_task_number_free(current->thread.user_thread_id);
		set_fs(KERNEL_DS);
		current->thread.user_thread_id = L4_NIL_ID;
		return -1;
	}

	unlock_kernel();

	l4x_user_dispatcher();

	/* not reached */
	return 0;
}

/*
 * These bracket the sleeping functions..
 */
#define top_esp                 (THREAD_SIZE - sizeof(unsigned long))
#define top_ebp                 (THREAD_SIZE - 2*sizeof(unsigned long))


unsigned long get_wchan(struct task_struct *p)
{
	unsigned long ebp, esp, eip;
	unsigned long stack_page;
	int count = 0;
	if (!p || p == current || p->state == TASK_RUNNING)
		return 0;
	stack_page = (unsigned long)task_stack_page(p);
	esp = p->thread.kernel_sp;
	if (!stack_page || esp < stack_page || esp > top_esp+stack_page)
		return 0;

	/* L4Linux has a different layout in switch_to(), but
	 *  the only difference is that we push a return
	 *  address after ebp. So we simply adjust the esp to
	 *  reflect that. And we leave the different name for
	 *  esp to catch direct usage of thread data. */

	esp = p->thread.kernel_sp + 4;/* add 4 to remove return address */

	/* include/asm-i386/system.h:switch_to() pushes ebp last. */
	ebp = *(unsigned long *) esp;
	do {
		if (ebp < stack_page || ebp > top_ebp+stack_page)
			return 0;
		eip = *(unsigned long *) (ebp+4);
		if (!in_sched_functions(eip))
			return eip;
		ebp = *(unsigned long *) ebp;
	} while (count++ < 16);
	return 0;
}

/*
 * sys_alloc_thread_area: get a yet unused TLS descriptor index.
 */
static int get_free_idx(void)
{
	struct thread_struct *t = &current->thread;
	int idx;

	for (idx = 0; idx < GDT_ENTRY_TLS_ENTRIES; idx++)
		if (desc_empty(t->tls_array + idx))
			return idx + GDT_ENTRY_TLS_MIN;
	return -ESRCH;
}

/*
 * Set a given TLS descriptor:
 */
asmlinkage int sys_set_thread_area(struct user_desc __user *u_info)
{
	struct thread_struct *t = &current->thread;
	struct user_desc info;
	struct desc_struct *desc;
	int cpu, idx;

	if (copy_from_user(&info, u_info, sizeof(info)))
		return -EFAULT;
	idx = info.entry_number;

	/*
	 * index -1 means the kernel should try to find and
	 * allocate an empty descriptor:
	 */
	if (idx == -1) {
		idx = get_free_idx();
		if (idx < 0)
			return idx;
		if (put_user(idx, &u_info->entry_number))
			return -EFAULT;
	}

	if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX)
		return -EINVAL;

	desc = t->tls_array + idx - GDT_ENTRY_TLS_MIN;

	/*
	 * We must not get preempted while modifying the TLS.
	 */
	cpu = get_cpu();

	if (LDT_empty(&info)) {
		desc->a = 0;
		desc->b = 0;
	} else {
		desc->a = LDT_entry_a(&info);
		desc->b = LDT_entry_b(&info);
	}
	load_TLS(t, cpu);

	put_cpu();

	return 0;
}

/*
 * Get the current Thread-Local Storage area:
 */

#define GET_BASE(desc) ( \
	(((desc)->a >> 16) & 0x0000ffff) | \
	(((desc)->b << 16) & 0x00ff0000) | \
	( (desc)->b        & 0xff000000)   )

#define GET_LIMIT(desc) ( \
	((desc)->a & 0x0ffff) | \
	 ((desc)->b & 0xf0000) )
	
#define GET_32BIT(desc)		(((desc)->b >> 22) & 1)
#define GET_CONTENTS(desc)	(((desc)->b >> 10) & 3)
#define GET_WRITABLE(desc)	(((desc)->b >>  9) & 1)
#define GET_LIMIT_PAGES(desc)	(((desc)->b >> 23) & 1)
#define GET_PRESENT(desc)	(((desc)->b >> 15) & 1)
#define GET_USEABLE(desc)	(((desc)->b >> 20) & 1)

asmlinkage int sys_get_thread_area(struct user_desc __user *u_info)
{
	struct user_desc info;
	struct desc_struct *desc;
	int idx;

	if (get_user(idx, &u_info->entry_number))
		return -EFAULT;
	if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX)
		return -EINVAL;

	memset(&info, 0, sizeof(info));

	desc = current->thread.tls_array + idx - GDT_ENTRY_TLS_MIN;

	info.entry_number = idx;
	info.base_addr = GET_BASE(desc);
	info.limit = GET_LIMIT(desc);
	info.seg_32bit = GET_32BIT(desc);
	info.contents = GET_CONTENTS(desc);
	info.read_exec_only = !GET_WRITABLE(desc);
	info.limit_in_pages = GET_LIMIT_PAGES(desc);
	info.seg_not_present = !GET_PRESENT(desc);
	info.useable = GET_USEABLE(desc);

	if (copy_to_user(u_info, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

unsigned long arch_align_stack(unsigned long sp)
{
	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		sp -= get_random_int() % 8192;
	return sp & ~0xf;
}
