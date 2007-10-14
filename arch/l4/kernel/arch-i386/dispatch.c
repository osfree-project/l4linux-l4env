
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

__attribute__((regparm(3)))
void do_syscall_trace(struct pt_regs *regs, int entryexit);

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
	return t->regs.eip;
}

static inline unsigned long regs_sp(struct thread_struct *t)
{
	return t->regs.esp;
}

static inline void l4x_arch_task_setup(struct thread_struct *t)
{
	load_TLS(t, 0);
}

static inline void l4x_arch_do_syscall_trace(struct task_struct *p,
                                             struct thread_struct *t)
{
	if (unlikely(current_thread_info()->flags
	             & (_TIF_SYSCALL_TRACE | _TIF_SYSCALL_AUDIT | _TIF_SECCOMP)))
		do_syscall_trace(&t->regs, 1);
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
	/* Setup LDTs */
	if (p->mm && p->mm->context.size)
		fiasco_ldt_set(p->mm->context.ldt,
		               p->mm->context.size * LDT_ENTRY_SIZE, 0,
		               p->thread.user_thread_id.id.task);
}

extern void fastcall do_signal(struct pt_regs *regs);
static inline int l4x_do_signal(struct pt_regs *regs, int syscall)
{
	do_signal(regs);
	return 0;
}

// foo
extern void l4x_show_sigpending_processes(void);
extern void schedule_tail(struct task_struct *prev);

static inline l4_umword_t l4x_l4pfa(struct thread_struct *t)
{
	return (t->pfa & ~3) | (t->error_code & 2);
}

static inline int l4x_ispf(struct thread_struct *t)
{
	return t->trap_no == 14;
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

	p->thread.esp = (unsigned long)sp;
}

void l4x_setup_user_dispatcher_after_fork(struct task_struct *p)
{
	l4x_setup_next_exec(p, (unsigned long)ret_from_fork);
}

#include <asm/generic/stack_id.h>
//struct task_struct fastcall * __switch_to(struct task_struct *prev, struct task_struct *next)
void fastcall l4x_switch_to(struct task_struct *prev, struct task_struct *next)
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
	x86_write_percpu(current_task, next);

#ifdef CONFIG_SMP
	next->thread.user_thread_id = next->thread.user_thread_ids[smp_processor_id()];
	l4x_stack_struct_get(next->stack)->id = l4x_cpu_thread_get(smp_processor_id());
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


static inline void l4x_dispatch_suspend(struct task_struct *p,
                                        struct thread_struct *t);

static inline void dispatch_system_call(struct task_struct *p)
{
	struct thread_struct *t = &p->thread;
	register struct pt_regs *regsp = &t->regs;
	unsigned int syscall;
	syscall_t syscall_fn = NULL;

	//syscall_count++;

	regsp->orig_eax = syscall = regsp->eax;
	regsp->eax = -ENOSYS;

#ifdef CONFIG_L4_FERRET_SYSCALL_COUNTER
	ferret_histo_bin_inc(l4x_ferret_syscall_ctr, syscall);
#endif

#if 0
	if (syscall == 11) {
		char *filename;
		printk("execve: pid: %d(%s), " PRINTF_L4TASK_FORM ": ",
		       p->pid, p->comm, PRINTF_L4TASK_ARG(p->thread.user_thread_id));
		filename = getname((char *)regsp->ebx);
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
	           syscall, p->comm, p->pid, (void *)regsp->eip,
	           regsp->ebx);
#endif

#if 0
	if (syscall == 120)
		LOG_printf("Syscall %3d for %s(%d at %p): arg1 = %lx\n",
		           syscall, p->comm, p->pid, (void *)regsp->eip,
		           regsp->ebx);
#endif
	if (!is_lx_syscall(syscall))
	{
	LOG_printf("Syscall %3d for %s(%d at %p): arg1 = %lx\n",
	           syscall, p->comm, p->pid, (void *)regsp->eip,
	           regsp->ebx);
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
			do_syscall_trace(regsp, 0);
			regsp->eax = syscall_fn(regsp->ebx, regsp->ecx,
						regsp->edx, regsp->esi,
						regsp->edi, regsp->ebp);
			do_syscall_trace(regsp, 1);
		} else {
			regsp->eax = syscall_fn(regsp->ebx, regsp->ecx,
						regsp->edx, regsp->esi,
						regsp->edi, regsp->ebp);
		}
	}
	//LOG_printf("syscall: %d ret=%d\n", syscall, regsp->eax);

	if (signal_pending(p))
		l4x_do_signal(regsp, syscall);

	if (need_resched())
		schedule();

#if 0
	LOG_printf("Syscall %3d for %s(%d at %p): return %lx\n",
	           syscall, p->comm, p->pid, (void *)regsp->eip,
	           regsp->eax);
#endif
	if (unlikely(syscall == -38))
		enter_kdebug("no ssycall");
}

/*
 * A primitive emulation.
 *
 * Returns 1 if something could be handled, 0 if not.
 */
static inline int l4x_port_emulation(struct pt_regs *regs)
{
	u8 op;

	if (get_user(op, (char *)regs->eip))
		return 0; /* User memory could not be accessed */

	//printf("OP: %x (eip: %08x) dx = 0x%x\n", op, regs->eip, regs->edx & 0xffff);

	switch (op) {
		case 0xed: /* in dx, eax */
		case 0xec: /* in dx, al */
			switch (regs->edx & 0xffff) {
				case 0xcf8:
				case 0x3da:
				case 0x3cc:
				case 0x3c1:
					regs->eax = -1;
					regs->eip++;
					return 1;
			};
		case 0xee: /* out al, dx */
			switch (regs->edx & 0xffff) {
				case 0x3c0:
					regs->eip++;
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
	char *addr = (char *)regs->eip;
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
		regs->eip += len + 3;
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
				outchar(regs->eax & 0xff);
				break;
			case 1: /* outnstring */
				len = regs->ebx;
				for (i = 0;
				     !get_user(val, (char *)(regs->eax + i++))
				     && len;
				     len--)
					outchar(val);
				break;
			case 2: /* outstring */
				for (i = 0;
				     !get_user(val, (char *)(regs->eax + i++))
				     && val;)
					outchar(val);
				break;
			case 5: /* outhex32 */
				outhex32(regs->eax);
				break;
			case 6: /* outhex20 */
				outhex20(regs->eax);
				break;
			case 7: /* outhex16 */
				outhex16(regs->eax);
				break;
			case 8: /* outhex12 */
				outhex12(regs->eax);
				break;
			case 9: /* outhex8 */
				outhex8(regs->eax);
				break;
			case 11: /* outdec */
				outdec(regs->eax);
				break;
			default:
				return 0; /* Did not understand */
		};
		regs->eip += 3;
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
		TBUF_LOG_SUSPEND(fiasco_tbuf_log_3val("dsp susp", TBUF_TID(t->user_thread_id), regs->eip, 0));
		l4x_dispatch_suspend(p, t);

		return 0;
	} else if (likely(t->trap_no == 0xd && t->error_code == 0x402)) {
		/* int 0x80 is trap 0xd and err 0x402 (0x80 << 3 | 2) */

		TBUF_LOG_INT80(fiasco_tbuf_log_3val("int80  ", TBUF_TID(t->user_thread_id), regs->eip, regs->eax));

		/* set after int 0x80, before syscall so the forked childs
		 * get the increase too */
		regs->eip += 2;

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

		extern asmlinkage void math_state_restore(void/*struct pt_regs regs*/);
		math_state_restore();

		/* XXX: math emu*/
		/* if (!cpu_has_fpu) math_emulate(..); */

		return 0;

	} else if (unlikely(t->trap_no == 0x1)) {
		/* Singlestep */
		LOG_printf("eip: %08lx esp: %08lx err: %08lx trp: %08lx\n",
		           regs->eip, regs->esp,
		           t->error_code, t->trap_no);
		LOG_printf("eax: %08lx ebx: %08lx ecx: %08lx edx: %08lx\n",
		           regs->eax, regs->ebx, regs->ecx,
		           regs->edx);
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
	printk("eip: %08lx esp: %08lx err: %08lx trp: %08lx\n", regs->eip, regs->esp, t->error_code, t->trap_no);
	printk("eax: %08lx ebx: %08lx ecx: %08lx edx: %08lx\n", regs->eax, regs->ebx, regs->ecx, regs->edx);
	printk("will die...\n");

	enter_kdebug("check");

	/* The task somehow misbehaved, so it has to die */
	l4x_sig_current_kill();

	return 1; /* no reply */
}

#define __INCLUDED_FROM_L4LINUX_DISPATCH
#include "../dispatch.c"
