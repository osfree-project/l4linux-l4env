
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/tick.h>

#include <asm/processor.h>
#include <asm/mmu_context.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>
#include <asm/i387.h>

#include <l4/sys/ipc.h>
#include <l4/sys/kdebug.h>
#include <l4/sys/ktrace.h>
#include <l4/sys/utcb.h>
#include <l4/sys/segment.h>
#include <l4/sys/syscalls.h>
#include <l4/names/libnames.h>		/* For name registration */
#include <l4/util/util.h>

#include <asm/l4lxapi/task.h>
#include <asm/l4lxapi/thread.h>
#include <asm/l4lxapi/memory.h>
#include <asm/api/macros.h>

#include <asm/generic/dispatch.h>
#include <asm/generic/ferret.h>
#include <asm/generic/task.h>
#include <asm/generic/upage.h>
#include <asm/generic/memory.h>
#include <asm/generic/process.h>
#include <asm/generic/setup.h>
#include <asm/generic/ioremap.h>
#include <asm/generic/hybrid.h>
#include <asm/generic/syscall_guard.h>
#include <asm/generic/stats.h>
#include <asm/generic/smp.h>
#include <asm/generic/signal.h>

#include <asm/l4x/exception.h>
#include <asm/l4x/iodb.h>
#include <asm/l4x/l4_syscalls.h>
#include <asm/l4x/lx_syscalls.h>
#include <asm/l4x/utcb.h>

#define TBUF_TID(tid) ((tid.id.task << 8) | tid.id.lthread)
#if 0
#define TBUF_LOG_IDLE(x)        do { x; } while (0)
#define TBUF_LOG_WAKEUP_IDLE(x)	do { x; } while (0)
#define TBUF_LOG_USER_PF(x)     do { x; } while (0)
#define TBUF_LOG_INT80(x)       do { x; } while (0)
#define TBUF_LOG_EXCP(x)        do { x; } while (0)
#define TBUF_LOG_START(x)       do { x; } while (0)
#define TBUF_LOG_SUSP_PUSH(x)   do { x; } while (0)
#define TBUF_LOG_DSP_IPC_IN(x)  do { x; } while (0)
#define TBUF_LOG_DSP_IPC_OUT(x) do { x; } while (0)
#define TBUF_LOG_SUSPEND(x)     do { x; } while (0)
#define TBUF_LOG_SWITCH(x)      do { x; } while (0)
#define TBUF_LOG_HYB_BEGIN(x)   do { x; } while (0)
#define TBUF_LOG_HYB_RETURN(x)  do { x; } while (0)

#else

#define TBUF_LOG_IDLE(x)
#define TBUF_LOG_WAKEUP_IDLE(x)
#define TBUF_LOG_USER_PF(x)
#define TBUF_LOG_INT80(x)
#define TBUF_LOG_EXCP(x)
#define TBUF_LOG_START(x)
#define TBUF_LOG_SUSP_PUSH(x)
#define TBUF_LOG_DSP_IPC_IN(x)
#define TBUF_LOG_DSP_IPC_OUT(x)
#define TBUF_LOG_SUSPEND(x)
#define TBUF_LOG_SWITCH(x)
#define TBUF_LOG_HYB_BEGIN(x)
#define TBUF_LOG_HYB_RETURN(x)

#endif

asmregparm long syscall_trace_enter(struct pt_regs *regs);
asmregparm long syscall_trace_leave(struct pt_regs *regs);

static DEFINE_PER_CPU(int, l4x_fpu_enabled);
static inline int l4x_msgtag_fpu(void)
{
	return per_cpu(l4x_fpu_enabled, smp_processor_id()) ? 0x8000 : 0;
}

static inline int l4x_is_triggered_exception(l4_umword_t val)
{
	return val == 0xff;
}

static inline unsigned long regs_pc(struct thread_struct *t)
{
	return t->regs.ip;
}

static inline unsigned long regs_sp(struct thread_struct *t)
{
	return t->regs.sp;
}

static inline void l4x_arch_task_setup(struct thread_struct *t)
{
	load_TLS(t, 0);
}

static inline void l4x_arch_do_syscall_trace(struct task_struct *p,
                                             struct thread_struct *t)
{
	if (unlikely(current_thread_info()->flags & _TIF_WORK_SYSCALL_EXIT))
		syscall_trace_leave(&t->regs);
}

static inline int l4x_hybrid_check_after_syscall(l4_utcb_t *utcb)
{
	return (utcb->exc.trapno == 0xd /* after L4 syscall */
	        && l4x_l4syscall_get_nr(utcb->exc.err, utcb->exc.eip) != -1
	        && (utcb->exc.err & 4))
	       || (utcb->exc.trapno == 0xff /* L4 syscall exr'd */
	           && utcb->exc.err == 0);
}

static inline void l4x_dispatch_delete_polling_flag(void)
{
	current_thread_info()->status &= ~TS_POLLING;
}

static inline void l4x_dispatch_set_polling_flag(void)
{
	current_thread_info()->status |= TS_POLLING;
}

static inline void l4x_arch_task_start_setup(struct task_struct *p)
{
	// - remember GS in FS so that programs can find their UTCB
	//   libl4sys-l4x.a uses %fs to get the UTCB address
	// - do not set GS because glibc does not seem to like if gs is not 0
	// - only do this if this is the first usage of the L4 thread in
	//   this task, otherwise gs will have the glibc-gs
	// - ensure this by checking if the segment is one of the user ones or
	//   another one (then it's the utcb one)
	unsigned int gs = l4x_utcb_get(l4_myself())->exc.gs;
	unsigned int v = (gs & 0xffff) >> 3;
	if (   v < l4x_fiasco_gdt_entry_offset
	    || v > l4x_fiasco_gdt_entry_offset + 3)
		p->thread.regs.fs = gs;

	/* Setup LDTs */
	if (p->mm && p->mm->context.size)
		fiasco_ldt_set(p->mm->context.ldt,
		               p->mm->context.size * LDT_ENTRY_SIZE, 0,
		               p->thread.user_thread_id.id.task);
}

static inline int l4x_do_signal(struct pt_regs *regs, int syscall)
{
	do_signal(regs);
	return 0;
}

// foo
extern void l4x_show_sigpending_processes(void);

static inline l4_umword_t l4x_l4pfa(struct thread_struct *t)
{
	return (t->pfa & ~3) | (t->error_code & 2);
}

static inline int l4x_ispf(struct thread_struct *t)
{
	return t->trap_no == 14;
}

static inline void l4x_print_regs(struct thread_struct *t)
{
	printk("ip: %08lx sp: %08lx err: %08lx trp: %08lx\n",
	       t->regs.ip, t->regs.sp, t->error_code, t->trap_no);
	printk("ax: %08lx bx: %08lx  cx: %08lx  dx: %08lx\n",
	       t->regs.ax, t->regs.bx, t->regs.cx, t->regs.dx);
	printk("di: %08lx si: %08lx  bp: %08lx\n",
	       t->regs.di, t->regs.si, t->regs.bp);
}

asmlinkage void ret_from_fork(void) __asm__("ret_from_fork");
asm(
".section .text			\n"
"ret_from_fork:			\n"
"pushl	%ebx			\n"
"call	schedule_tail		\n"
"popl	%ebx			\n"
"jmp	l4x_user_dispatcher	\n"
".previous			\n"
);

void l4x_idle(void);

int  l4x_deliver_signal(int exception_nr, int error_code);

DEFINE_PER_CPU(struct task_struct *, l4x_current_process) = &init_task;
DEFINE_PER_CPU(struct thread_info *, l4x_current_proc_run);
static DEFINE_PER_CPU(unsigned, utcb_snd_size);

void l4x_fpu_set(int on_off)
{
	per_cpu(l4x_fpu_enabled, smp_processor_id()) = on_off;
}

static void l4x_setup_next_exec(struct task_struct *p, unsigned long f)
{
	unsigned long *sp = (unsigned long *)
	                     ((unsigned long)p->stack + THREAD_SIZE);

	BUG_ON(current == p);

	/* setup stack of p to come out in f on next switch_to() */
	*--sp = 0;
	*--sp = f;

	p->thread.sp = (unsigned long)sp;
}

void l4x_setup_user_dispatcher_after_fork(struct task_struct *p)
{
	l4x_setup_next_exec(p, (unsigned long)ret_from_fork);
}

static inline void // from process.c
__switch_to_xtra(struct task_struct *prev_p, struct task_struct *next_p,
                 struct tss_struct *tss)
{
	struct thread_struct *prev, *next;
	//unsigned long debugctl;

	prev = &prev_p->thread;
	next = &next_p->thread;

#ifdef NOT_FOR_L4
	debugctl = prev->debugctlmsr;
	if (next->ds_area_msr != prev->ds_area_msr) {
		/* we clear debugctl to make sure DS
		 * is not in use when we change it */
		debugctl = 0;
		wrmsrl(MSR_IA32_DEBUGCTLMSR, 0);
		wrmsr(MSR_IA32_DS_AREA, next->ds_area_msr, 0);
	}

	if (next->debugctlmsr != debugctl)
		wrmsr(MSR_IA32_DEBUGCTLMSR, next->debugctlmsr, 0);

	if (test_tsk_thread_flag(next_p, TIF_DEBUG)) {
		set_debugreg(next->debugreg0, 0);
		set_debugreg(next->debugreg1, 1);
		set_debugreg(next->debugreg2, 2);
		set_debugreg(next->debugreg3, 3);
		/* no 4 and 5 */
		set_debugreg(next->debugreg6, 6);
		set_debugreg(next->debugreg7, 7);
	}

#ifdef CONFIG_SECCOMP
	if (test_tsk_thread_flag(prev_p, TIF_NOTSC) ^
	    test_tsk_thread_flag(next_p, TIF_NOTSC)) {
		/* prev and next are different */
		if (test_tsk_thread_flag(next_p, TIF_NOTSC))
			hard_disable_TSC();
		else
			hard_enable_TSC();
	}
#endif
#endif

#ifdef X86_BTS
	if (test_tsk_thread_flag(prev_p, TIF_BTS_TRACE_TS))
		ptrace_bts_take_timestamp(prev_p, BTS_TASK_DEPARTS);

	if (test_tsk_thread_flag(next_p, TIF_BTS_TRACE_TS))
		ptrace_bts_take_timestamp(next_p, BTS_TASK_ARRIVES);
#endif

#ifdef NOT_FOR_L4
	if (!test_tsk_thread_flag(next_p, TIF_IO_BITMAP)) {
		/*
		 * Disable the bitmap via an invalid offset. We still cache
		 * the previous bitmap owner and the IO bitmap contents:
		 */
		tss->x86_tss.io_bitmap_base = INVALID_IO_BITMAP_OFFSET;
		return;
	}

	if (likely(next == tss->io_bitmap_owner)) {
		/*
		 * Previous owner of the bitmap (hence the bitmap content)
		 * matches the next task, we dont have to do anything but
		 * to set a valid offset in the TSS:
		 */
		tss->x86_tss.io_bitmap_base = IO_BITMAP_OFFSET;
		return;
	}
	/*
	 * Lazy TSS's I/O bitmap copy. We set an invalid offset here
	 * and we let the task to get a GPF in case an I/O instruction
	 * is performed.  The handler of the GPF will verify that the
	 * faulting task has a valid I/O bitmap and, it true, does the
	 * real copy and restart the instruction.  This will save us
	 * redundant copies when the currently switched task does not
	 * perform any I/O during its timeslice.
	 */
	tss->x86_tss.io_bitmap_base = INVALID_IO_BITMAP_OFFSET_LAZY;
#endif
}



#include <asm/generic/stack_id.h>

void l4x_switch_to(struct task_struct *prev, struct task_struct *next)
{
#if 0
	LOG_printf("%s: " PRINTF_L4TASK_FORM ": %s(%d)[%ld] -> %s(%d)[%ld]\n",
	           __func__, PRINTF_L4TASK_ARG(l4_myself()),
	           prev->comm, prev->pid, prev->state,
	           next->comm, next->pid, next->state);
#endif
	TBUF_LOG_SWITCH(fiasco_tbuf_log_3val("SWITCH", (prev->pid << 16) | TBUF_TID(prev->thread.user_thread_id), (next->pid << 16) | TBUF_TID(next->thread.user_thread_id), 0));

	__unlazy_fpu(prev);
	per_cpu(l4x_current_process, smp_processor_id()) = next;

	if (unlikely(task_thread_info(prev)->flags & _TIF_WORK_CTXSW_PREV ||
	             task_thread_info(next)->flags & _TIF_WORK_CTXSW_NEXT))
		__switch_to_xtra(prev, next, NULL);


	x86_write_percpu(current_task, next);

#ifdef CONFIG_SMP
	next->thread.user_thread_id = next->thread.user_thread_ids[smp_processor_id()];
	l4x_stack_struct_get(next->stack)->l4id = l4x_cpu_thread_get(smp_processor_id());
#endif

	if (next->thread.user_thread_id.id.task)
		load_TLS(&next->thread, 0);

	//return prev;
}

static inline void l4x_pte_add_access_and_mapped(pte_t *ptep)
{
	ptep->pte_low |= (_PAGE_ACCESSED + _PAGE_MAPPED);
}

static inline void l4x_pte_add_access_mapped_and_dirty(pte_t *ptep)
{
	ptep->pte_low |= (_PAGE_ACCESSED + _PAGE_DIRTY + _PAGE_MAPPED);
}

static inline void utcb_to_thread_struct(l4_utcb_t *utcb,
                                         struct thread_struct *t)
{
	utcb_to_ptregs(utcb, &t->regs);
	t->gs         = utcb->exc.gs;
	t->trap_no    = utcb->exc.trapno;
	t->error_code = utcb->exc.err;
	t->pfa        = utcb->exc.pfa;
}

static inline void thread_struct_to_utcb(struct thread_struct *t,
                                         l4_utcb_t *utcb,
                                         unsigned int send_size)
{
	ptregs_to_utcb(&t->regs, utcb);
	utcb->exc.gs   = t->gs;
	per_cpu(utcb_snd_size, smp_processor_id()) = send_size;
}

static int l4x_hybrid_begin(struct task_struct *p,
                            struct thread_struct *t);


static void l4x_dispatch_suspend(struct task_struct *p,
                                 struct thread_struct *t);

static inline void dispatch_system_call(struct task_struct *p)
{
	struct thread_struct *t = &p->thread;
	register struct pt_regs *regsp = &t->regs;
	unsigned int syscall;
	syscall_t syscall_fn = NULL;

	//syscall_count++;

	regsp->orig_ax = syscall = regsp->ax;
	regsp->ax = -ENOSYS;

#ifdef CONFIG_L4_FERRET_SYSCALL_COUNTER
	ferret_histo_bin_inc(l4x_ferret_syscall_ctr, syscall);
#endif

#if 0
	if (syscall == 11) {
		char *filename;
		printk("execve: pid: %d(%s), " PRINTF_L4TASK_FORM ": ",
		       p->pid, p->comm, PRINTF_L4TASK_ARG(p->thread.user_thread_id));
		filename = getname((char *)regsp->bx);
		printk("%s\n", IS_ERR(filename) ? "UNKNOWN" : filename);
	}
#endif
#if 0
	if (p->comm[0] == '_')
		printk("Syscall %3d for %s(%d) [" PRINTF_L4TASK_FORM "]\n", syscall,
			p->comm, p->pid,
			PRINTF_L4TASK_ARG(p->thread.user_thread_id));
#endif
#if 0
	LOG_printf("Syscall %3d for %s(%d at %p): arg1 = %lx\n",
	           syscall, p->comm, p->pid, (void *)regsp->ip,
	           regsp->bx);
#endif

#if 0
	if (syscall == 120)
		LOG_printf("Syscall %3d for %s(%d at %p): arg1 = %lx\n",
		           syscall, p->comm, p->pid, (void *)regsp->ip,
		           regsp->bx);
#endif
	if (!is_lx_syscall(syscall))
	{
	  // XXX
	LOG_printf("Syscall %3d for %s(%d at %p): arg1 = %lx\n",
	           syscall, p->comm, p->pid, (void *)regsp->ip,
	           regsp->bx);
		enter_kdebug("no syscall");
	}
	if (likely((is_lx_syscall(syscall))
		   && ((syscall_fn = sys_call_table[syscall])))) {
		if (!p->user)
			enter_kdebug("dispatch_system_call: !p->user");

		/* valid system call number.. */
		if (unlikely(current_thread_info()->flags
		             & (_TIF_SYSCALL_EMU
		                | _TIF_SYSCALL_TRACE
		                | _TIF_SECCOMP
		                | _TIF_SYSCALL_AUDIT))) {
			syscall_trace_enter(regsp);
			regsp->ax = syscall_fn(regsp->bx, regsp->cx,
			                       regsp->dx, regsp->si,
			                       regsp->di, regsp->bp);
			syscall_trace_leave(regsp);
		} else {
			regsp->ax = syscall_fn(regsp->bx, regsp->cx,
			                       regsp->dx, regsp->si,
			                       regsp->di, regsp->bp);
		}
	}
	//LOG_printf("syscall: %d ret=%d\n", syscall, regsp->ax);

	if (signal_pending(p))
		l4x_do_signal(regsp, syscall);

	if (need_resched())
		schedule();

#if 0
	LOG_printf("Syscall %3d for %s(%d at %p): return %lx\n",
	           syscall, p->comm, p->pid, (void *)regsp->ip,
	           regsp->ax);
#endif
	if (unlikely(syscall == -38))
		enter_kdebug("no syscall");
}

/*
 * A primitive emulation.
 *
 * Returns 1 if something could be handled, 0 if not.
 */
static inline int l4x_port_emulation(struct pt_regs *regs)
{
	u8 op;

	if (get_user(op, (char *)regs->ip))
		return 0; /* User memory could not be accessed */

	//printf("OP: %x (ip: %08x) dx = 0x%x\n", op, regs->ip, regs->edx & 0xffff);

	switch (op) {
		case 0xed: /* in dx, eax */
		case 0xec: /* in dx, al */
			switch (regs->dx & 0xffff) {
				case 0xcf8:
				case 0x3da:
				case 0x3cc:
				case 0x3c1:
					regs->ax = -1;
					regs->ip++;
					return 1;
			};
		case 0xee: /* out al, dx */
			switch (regs->dx & 0xffff) {
				case 0x3c0:
					regs->ip++;
					return 1;
			};
	};

	return 0; /* Not handled here */
}

/*
 * Emulation of (some) jdb commands. The user program may not
 * be allowed to issue jdb commands, they trap in here. Nevertheless
 * hybrid programs may want to use some of them. Emulate them here.
 * Note:  When there's a failure reading the string from user we
 *        nevertheless return true.
 * Note2: More commands to be emulated can be added on request.
 */
static int l4x_kdebug_emulation(struct pt_regs *regs)
{
	u8 op = 0, val;
	char *addr = (char *)regs->ip;
	int i, len;

	if (get_user(op, addr))
		return 0; /* User memory could not be accessed */

	if (op != 0xcc) /* Check for int3 */
		return 0; /* Not for us */

	/* jdb command group */
	if (get_user(op, addr + 1))
		return 0; /* User memory could not be accessed */

	if (op == 0xeb) { /* enter_kdebug */
		if (get_user(len, addr + 2))
			return 0; /* Access failure */
		regs->ip += len + 3;
		outstring("User enter_kdebug text: ");
		for (i = 3; len; len--) {
			if (get_user(val, addr + i++))
				break;
			outchar(val);
		}
		outchar('\n');
		enter_kdebug("User program enter_kdebug");

		return 1; /* handled */

	} else if (op == 0x3c) {
		if (get_user(op, addr + 2))
			return 0; /* Access failure */
		switch (op) {
			case 0: /* outchar */
				outchar(regs->ax & 0xff);
				break;
			case 1: /* outnstring */
				len = regs->bx;
				for (i = 0;
				     !get_user(val, (char *)(regs->ax + i++))
				     && len;
				     len--)
					outchar(val);
				break;
			case 2: /* outstring */
				for (i = 0;
				     !get_user(val, (char *)(regs->ax + i++))
				     && val;)
					outchar(val);
				break;
			case 5: /* outhex32 */
				outhex32(regs->ax);
				break;
			case 6: /* outhex20 */
				outhex20(regs->ax);
				break;
			case 7: /* outhex16 */
				outhex16(regs->ax);
				break;
			case 8: /* outhex12 */
				outhex12(regs->ax);
				break;
			case 9: /* outhex8 */
				outhex8(regs->ax);
				break;
			case 11: /* outdec */
				outdec(regs->ax);
				break;
			default:
				return 0; /* Did not understand */
		};
		regs->ip += 3;
		return 1; /* handled */
	}

	return 0; /* Not handled here */
}

/*
 * Return values: 0 -> do send a reply
 *                1 -> don't send a reply
 */
static inline int l4x_dispatch_exception(struct task_struct *p,
                                         struct thread_struct *t)
{
	struct pt_regs *regs = &t->regs;

	l4x_hybrid_do_regular_work();
	l4x_debug_stats_exceptions_hit();

	if (t->trap_no == 0xff) {
		/* we come here for suspend events */
		TBUF_LOG_SUSPEND(fiasco_tbuf_log_3val("dsp susp", TBUF_TID(t->user_thread_id), regs->ip, 0));
		l4x_dispatch_suspend(p, t);

		return 0;
	} else if (likely(t->trap_no == 0xd && t->error_code == 0x402)) {
		/* int 0x80 is trap 0xd and err 0x402 (0x80 << 3 | 2) */

		TBUF_LOG_INT80(fiasco_tbuf_log_3val("int80  ", TBUF_TID(t->user_thread_id), regs->ip, regs->ax));

		/* set after int 0x80, before syscall so the forked childs
		 * get the increase too */
		regs->ip += 2;

		dispatch_system_call(p);

		BUG_ON(p != current);

		if (likely(!t->restart))
			/* fine, go send a reply and return to userland */
			return 0;

		//LOG_printf("Restart triggered for %s(%d)\n", p->comm, p->pid);
		/* Restart whole dispatch loop, also restarts thread */
		t->restart = 0;
		return 2;

	} else if (t->trap_no == 7) {
		math_state_restore();

		/* XXX: math emu*/
		/* if (!cpu_has_fpu) math_emulate(..); */

		return 0;

	} else if (unlikely(t->trap_no == 0x1)) {
		/* Singlestep */
#if 0
		LOG_printf("ip: %08lx sp: %08lx err: %08lx trp: %08lx\n",
		           regs->ip, regs->sp,
		           t->error_code, t->trap_no);
		LOG_printf("ax: %08lx ebx: %08lx ecx: %08lx edx: %08lx\n",
		           regs->ax, regs->bx, regs->cx,
		           regs->dx);
#endif
		return 0;
	} else if (t->trap_no == 0xd) {
		if (l4x_hybrid_begin(p, t))
			return 0;

		/* Fall through otherwise */
	}

	if (t->trap_no == 3)
		if (l4x_kdebug_emulation(regs))
			return 0; /* known and handled */

	if (l4x_port_emulation(regs))
		return 0; /* known and handled */

	TBUF_LOG_EXCP(fiasco_tbuf_log_3val("except ", TBUF_TID(t->user_thread_id), t->trap_no, t->error_code));

	if (l4x_deliver_signal(t->trap_no, t->error_code)) {
		return 0; /* handled signal, reply */
	}

	/* This path should never be reached... */

	printk("(Unknown) EXCEPTION [" PRINTF_L4TASK_FORM "]\n", PRINTF_L4TASK_ARG(t->user_thread_id));
	l4x_print_regs(t);
	printk("will die...\n");

	enter_kdebug("check");

	/* The task somehow misbehaved, so it has to die */
	l4x_sig_current_kill();

	return 1; /* no reply */
}

static inline int l4x_handle_page_fault_with_exception(struct thread_struct *t)
{
	return 0; // not for us
}

#define __INCLUDED_FROM_L4LINUX_DISPATCH
#include "../dispatch.c"
