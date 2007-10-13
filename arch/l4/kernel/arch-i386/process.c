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
#include <linux/percpu.h>

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/ldt.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/desc.h>

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

int reboot_thru_bios;

asmlinkage int sys_enosys(void)
{
	return -ENOSYS;
}

static int hlt_counter;

DEFINE_PER_CPU(struct task_struct *, current_task) = &init_task;
EXPORT_PER_CPU_SYMBOL(current_task);

DEFINE_PER_CPU(int, cpu_number);
EXPORT_PER_CPU_SYMBOL(cpu_number);

/*
 * Return saved PC of a blocked thread.
 */
unsigned long thread_saved_pc(struct task_struct *tsk)
{
	return ((unsigned long *)tsk->thread.esp)[0];
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
#ifdef NOT_FOR_L4
	unsigned long cr0 = 0L, cr2 = 0L, cr3 = 0L, cr4 = 0L;
	unsigned long d0, d1, d2, d3, d6, d7;
#endif

	if (!regs) {
		printk("Can't print regs from interrupt handler: &pt_regs == 0!");
		return;
	}

	printk("\n");
	printk("Pid: %d, comm: %20s\n", current->pid, current->comm);
	printk("EIP: %04x:[<%08lx>] CPU: %d\n",0xffff & regs->xcs,regs->eip, smp_processor_id());
	print_symbol("EIP is at %s\n", regs->eip);

	if (user_mode_vm(regs))
		printk(" ESP: %04x:%08lx",0xffff & regs->xss,regs->esp);
	printk(" EFLAGS: %08lx    %s  (%s %.*s)\n",
	       regs->eflags, print_tainted(), init_utsname()->release,
	       (int)strcspn(init_utsname()->version, " "),
	       init_utsname()->version);
	printk("EAX: %08lx EBX: %08lx ECX: %08lx EDX: %08lx\n",
		regs->eax,regs->ebx,regs->ecx,regs->edx);
	printk("ESI: %08lx EDI: %08lx EBP: %08lx",
		regs->esi, regs->edi, regs->ebp);
	printk(" DS: %04x ES: %04x FS: %04x\n",
	       0xffff & regs->xds,0xffff & regs->xes, 0xffff & regs->xfs);

#ifdef NOT_FOR_L4
	cr0 = read_cr0();
	cr2 = read_cr2();
	cr3 = read_cr3();
	cr4 = read_cr4_safe();
	printk("CR0: %08lx CR2: %08lx CR3: %08lx CR4: %08lx\n", cr0, cr2, cr3, cr4);

	get_debugreg(d0, 0);
	get_debugreg(d1, 1);
	get_debugreg(d2, 2);
	get_debugreg(d3, 3);
	printk("DR0: %08lx DR1: %08lx DR2: %08lx DR3: %08lx\n",
			d0, d1, d2, d3);
	get_debugreg(d6, 6);
	get_debugreg(d7, 7);
	printk("DR6: %08lx DR7: %08lx\n", d6, d7);
#endif

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
	regs.xfs = __KERNEL_PERCPU;
	regs.orig_eax = -1;
	//regs.eip = (unsigned long) kernel_thread_helper;
	regs.xcs = __KERNEL_CS | get_kernel_rpl();
	regs.eflags = X86_EFLAGS_IF | X86_EFLAGS_SF | X86_EFLAGS_PF | 0x2;

	/* Ok, create the new process.. */
	return do_fork(flags | CLONE_VM | CLONE_UNTRACED, 0, &regs, COPY_THREAD_STACK_SIZE___FLAG_INKERNEL, NULL, NULL);
}
EXPORT_SYMBOL(kernel_thread);

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
static int l4x_thread_create(struct task_struct *p, unsigned long clone_flags,
                             int inkernel)
{
	struct thread_struct *t = &p->thread;
	int i;

	/* first, allocate task id for  client task */
	if (!inkernel && clone_flags & CLONE_VM) /* is this a user process and vm-cloned? */
		t->cloner = current->thread.user_thread_id;

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

		t->esp = (unsigned long) sp;
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
	unsigned long stack_size___used_for_inkernel_process_flag,
	struct task_struct * p, struct pt_regs * regs)
{
	struct pt_regs * childregs;
	struct task_struct *cur = current;
	int err;

	childregs = task_pt_regs(p);
	*childregs = *regs;
	childregs->eax = 0;
	childregs->esp = esp;

	childregs->eflags |= 0x200;	/* sanity: set EI flag */
	childregs->eflags &= 0x1ffff;

	//p->thread.eip = (unsigned long) ret_from_fork;

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
	err = l4x_thread_create(p, clone_flags, stack_size___used_for_inkernel_process_flag == COPY_THREAD_STACK_SIZE___FLAG_INKERNEL);
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
	int ret = 0, i;

	//LOG_printf("%s\n", __func__);
	//enter_kdebug("flush thread");

	memset(tsk->thread.tls_array, 0, sizeof(tsk->thread.tls_array));
	clear_tsk_thread_flag(tsk, TIF_DEBUG);

	/* When processes are started from kernel threads there's no
	 * process to flush */
	if (!current->thread.started)
		return;

	// turn back to normal flush-behavior
	//current->mm->context.releasing = 0;

	for (i = 0; i < NR_CPUS; i++) {
		l4_threadid_t id = tsk->thread.user_thread_ids[i];

		//LOG_printf("flush of " PRINTF_L4TASK_FORM "\n", PRINTF_L4TASK_ARG(id));
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
	regs->xfs = 0;

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

#ifdef CONFIG_SECCOMP
void hard_disable_TSC(void)
{
}

void disable_TSC(void)
{
}

void hard_enable_TSC(void)
{
}
#endif /* CONFIG_SECCOMP */

/* fork/exec system calls (copied from arch/i386/kernel/process.c) */

asmlinkage int sys_fork(void)
{
	struct pt_regs *regs = &current->thread.regs;
	return do_fork(SIGCHLD, regs->esp, regs, COPY_THREAD_STACK_SIZE___FLAG_USER, NULL, NULL);
}

asmlinkage int sys_clone(void)
{
	struct pt_regs *regs = &current->thread.regs;
	unsigned long clone_flags;
	unsigned long newsp;
	int __user *parent_tidptr, *child_tidptr;

	clone_flags = regs->ebx;
	newsp = regs->ecx;
	parent_tidptr = (int __user *)regs->edx;
	child_tidptr = (int __user *)regs->edi;
	if (!newsp)
		newsp = regs->esp;

	return do_fork(clone_flags, newsp, regs, COPY_THREAD_STACK_SIZE___FLAG_USER, parent_tidptr, child_tidptr);
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

	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, regs->esp, regs, COPY_THREAD_STACK_SIZE___FLAG_USER, NULL, NULL);
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
	//int cpu = smp_processor_id();
	struct thread_struct *t = &current->thread;

	ASSERT(l4_thread_equal(t->user_thread_id, L4_NIL_ID));

	/* we are going to become a real user task now, so prepare a real
	 * pt_regs structure. */
	/* Enable Interrupts, Set IOPL (needed for X, hwclock etc.) */
	t->regs.eflags = 0x3200; /* XXX hardcoded */

	/* do_execve() will create the user task for us in start_thread()
	   and call set_fs(USER_DS) in flush_thread. I know this sounds
	   strange but there are places in the kernel (kernel/kmod.c) which
	   call execve with parameters inside the kernel. They set fs to
	   KERNEL_DS before calling execve so we can't set it back to
	   USER_DS before execve had a chance to look at the name of the
	   executable. */

	ASSERT(segment_eq(get_fs(), KERNEL_DS));
	lock_kernel();
	error = do_execve(file, argv, envp, &t->regs);

	if (error < 0) {
		/* we failed -- become a kernel thread again */
		//printk("Error in kernel-internal exec for " PRINTF_L4TASK_FORM ": %d\n", PRINTF_L4TASK_ARG(current->thread.user_thread_id), error);
		l4lx_task_number_free(t->user_thread_id);
		set_fs(KERNEL_DS);
		t->user_thread_id = L4_NIL_ID;
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
	esp = p->thread.esp;
	if (!stack_page || esp < stack_page || esp > top_esp+stack_page)
		return 0;

	/* L4Linux has a different layout in switch_to(), but
	 *  the only difference is that we push a return
	 *  address after ebp. So we simply adjust the esp to
	 *  reflect that. And we leave the different name for
	 *  esp to catch direct usage of thread data. */

	esp = p->thread.esp + 4;/* add 4 to remove return address */

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
