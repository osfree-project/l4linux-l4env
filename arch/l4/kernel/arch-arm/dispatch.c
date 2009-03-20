
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/tick.h>

#include <asm/processor.h>
#include <asm/mmu_context.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>
#include <asm/pgalloc.h>

#include <l4/sys/ipc.h>
#include <l4/sys/kdebug.h>
#include <l4/sys/ktrace.h>
#include <l4/sys/utcb.h>
#include <l4/sys/syscalls.h>
#include <l4/names/libnames.h>		/* For name registration */
#include <l4/util/util.h>

#include <asm/l4lxapi/task.h>
#include <asm/l4lxapi/thread.h>
#include <asm/l4lxapi/memory.h>
#include <asm/api/macros.h>

#include <asm/generic/dispatch.h>
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

asmlinkage void syscall_trace(int why, struct pt_regs *regs, int scno);

static inline int l4x_msgtag_fpu(void)
{
	return 0;
}

static inline int l4x_is_triggered_exception(l4_umword_t val)
{
	return (val & 0x00f00000) == 0x00500000;
}

static inline unsigned long regs_pc(struct thread_struct *t)
{
	return t->regs.ARM_pc;
}

static inline unsigned long regs_sp(struct thread_struct *t)
{
	return t->regs.ARM_sp;
}

static inline void l4x_arch_task_setup(struct thread_struct *t)
{

}

static inline void l4x_arch_do_syscall_trace(struct task_struct *p,
                                             struct thread_struct *t)
{
	if (unlikely(test_tsk_thread_flag(p, TIF_SYSCALL_TRACE)))
		syscall_trace(1, &t->regs, __NR_fork);
}

static inline int l4x_hybrid_check_after_syscall(l4_utcb_t *utcb)
{
	return utcb->exc.err == 0x00310000 // after L4 syscall
	       //|| utcb->exc.err == 0x00200000
	       || utcb->exc.err == 0x00500000; // L4 syscall exr
}

static inline void l4x_dispatch_delete_polling_flag(void)
{
}

static inline void l4x_dispatch_set_polling_flag(void)
{
}

static inline void l4x_arch_task_start_setup(struct task_struct *p)
{
}

#include <asm/signal.h>
extern int do_signal(sigset_t *oldset, struct pt_regs *regs, int syscall);
static inline int l4x_do_signal(struct pt_regs *regs, int syscall)
{
	return do_signal(&current->blocked, regs, syscall);
}

// foo
extern void l4x_show_sigpending_processes(void);
extern void schedule_tail(struct task_struct *prev);

static inline l4_umword_t l4x_l4pfa(struct thread_struct *t)
{
	return (t->address & ~3) | (!(t->error_code & 0x00020000) << 1);
}

static inline int l4x_ispf(struct thread_struct *t)
{
	return t->error_code & 0x00010000;
}

void l4x_finish_task_switch(struct task_struct *prev);
int  l4x_deliver_signal(int exception_nr, int error_code);

DEFINE_PER_CPU(struct task_struct *, l4x_current_process) = &init_task;
DEFINE_PER_CPU(struct thread_info *, l4x_current_proc_run);
static DEFINE_PER_CPU(unsigned, utcb_snd_size);


asm(
".section .text				\n"
".global ret_from_fork			\n"
"ret_from_fork:				\n"
"	bl	schedule_tail		\n"
"	bl	l4x_user_dispatcher	\n"
".previous				\n"
);

#include <asm/generic/stack_id.h>
void l4x_switch_to(struct task_struct *prev, struct task_struct *next)
{
	TBUF_LOG_SWITCH(fiasco_tbuf_log_3val("SWITCH", TBUF_TID(prev->thread.user_thread_id), TBUF_TID(next->thread.user_thread_id), 0));

	per_cpu(l4x_current_process, smp_processor_id()) = next;

#ifdef CONFIG_SMP
	next->thread.user_thread_id = next->thread.user_thread_ids[smp_processor_id()];
	l4x_stack_struct_get(next->stack)->l4id = l4x_cpu_thread_get(smp_processor_id());
#endif
}

static inline void l4x_pte_add_access_and_mapped(pte_t *ptep)
{
	pte_val(*ptep) |= (L_PTE_YOUNG + L_PTE_MAPPED);
}

static inline void l4x_pte_add_access_mapped_and_dirty(pte_t *ptep)
{
	pte_val(*ptep) |= (L_PTE_YOUNG + L_PTE_DIRTY + L_PTE_MAPPED);
}

static inline void utcb_to_thread_struct(l4_utcb_t *utcb,
                                         struct thread_struct *t)
{
	utcb_to_ptregs(utcb, &t->regs);
	t->error_code     = utcb->exc.err;
	t->address        = utcb->exc.pfa;
}

static inline void thread_struct_to_utcb(struct thread_struct *t,
                                         l4_utcb_t *utcb,
                                         unsigned int send_size)
{
	ptregs_to_utcb(&t->regs, utcb);
	per_cpu(utcb_snd_size, smp_processor_id()) = send_size;
}

static int l4x_hybrid_begin(struct task_struct *p,
                            struct thread_struct *t);


static void l4x_dispatch_suspend(struct task_struct *p,
                                 struct thread_struct *t);

static inline void l4x_print_regs(struct thread_struct *t)
{
#define R(nr) t->regs.uregs[nr]
	printk("0: %08lx %08lx %08lx %08lx %08lx %08lx %08lx %08lx\n",
	       R(0), R(1), R(2), R(3), R(4), R(5), R(6), R(7));
	printk("8: %08lx %08lx %08lx %08lx %08lx [01;34m%08lx[0m "
	       "%08lx [01;34m%08lx[0m\n",
	       R(8), R(9), R(10), R(11), R(12), R(13), R(14), R(15));
#undef R
}

//#include <linux/fs.h>

static inline void call_system_call_args(unsigned long syscall,
                                         unsigned long arg1,
                                         unsigned long arg2,
                                         unsigned long arg3,
                                         unsigned long arg4,
                                         unsigned long arg5,
                                         unsigned long arg6,
                                         struct pt_regs *regsp)
{
	syscall_t syscall_fn;

#if 0
	printk("Syscall call: %ld for %d(%s, %p, " PRINTF_L4TASK_FORM ") (%08lx %08lx %08lx)\n",
			syscall, current->pid, current->comm, (void *)regsp->ARM_pc,
			PRINTF_L4TASK_ARG(current->thread.user_thread_id),
			arg1, arg2, arg3);
	if (syscall == 11) {
		char *filename = getname((char *)arg1);
		printk("execve: pid: %d(%s), " PRINTF_L4TASK_FORM ": %s (%08lx)\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       IS_ERR(filename) ? "UNKNOWN" : filename, arg1);
		putname(filename);
	}
	if (syscall == 1) {
		printk("exit: pid: %d(%s), " PRINTF_L4TASK_FORM "\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id));
	}
	if (syscall == 2) {
		printk("fork: pid: %d(%s), " PRINTF_L4TASK_FORM "\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id));
	}
	if (syscall == 3) {
		printk("read: pid: %d(%s), " PRINTF_L4TASK_FORM ": fd = %ld\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       arg1);
	}
	if (syscall == 4) {
		printk("write: pid: %d(%s), " PRINTF_L4TASK_FORM ": fd = %ld\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       arg1);
	}
	if (syscall == 5) {
		char *filename = getname((char *)arg1);
		printk("open: pid: %d(%s), " PRINTF_L4TASK_FORM ": %s (%lx)\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       IS_ERR(filename) ? "UNKNOWN" : filename, arg1);
		putname(filename);
	}
	if (syscall == 39) {
		char *filename = getname((char *)arg1);
		printk("mkdir: pid: %d(%s), " PRINTF_L4TASK_FORM ": %s (%lx)\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       IS_ERR(filename) ? "UNKNOWN" : filename, arg1);
		putname(filename);
	}
	if (syscall == 21) {
		char *f1 = getname((char *)arg1);
		char *f2 = getname((char *)arg2);
		printk("mount: pid: %d(%s), " PRINTF_L4TASK_FORM ": %s -> %s\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       IS_ERR(f1) ? "UNKNOWN" : f1,
		       IS_ERR(f2) ? "UNKNOWN" : f2);
		putname(f1);
		putname(f2);
	}
	if (syscall == 120) {
		printk("clone: pid: %d(%s), " PRINTF_L4TASK_FORM "\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id));
	}
	if (syscall == 190) {
		printk("vfork: pid: %d(%s), " PRINTF_L4TASK_FORM "\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id));
	}
	if (syscall == 192) {
		printk("mmap2 size: pid: %d(%s), " PRINTF_L4TASK_FORM ": %lx\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       arg2);
	}
#endif

	/* ============================================================ */

	if (likely(is_lx_syscall(syscall))
	           && ((syscall_fn = sys_call_table[syscall]))) {
		if (unlikely(!current->user))
			enter_kdebug("call_system_call_args: !current->user");

		/* valid system call number.. */
		if (likely(!test_tsk_thread_flag(current, TIF_SYSCALL_TRACE))) {
			regsp->ARM_r0 = syscall_fn(arg1, arg2, arg3, arg4, arg5, arg6);
		} else {
			syscall_trace(0, regsp, syscall);
			regsp->ARM_r0 = syscall_fn(arg1, arg2, arg3, arg4, arg5, arg6);
			syscall_trace(1, regsp, syscall);
		}
	} else
		regsp->ARM_r0 = -ENOSYS;

	/* ============================================================ */
#if 0
	if (syscall == 192) {
		printk("mmap2 result: pid: %d(%s), " PRINTF_L4TASK_FORM ": %lx\n", 
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       regsp->ARM_r0);
	}
	if (syscall == 65) {
		printk("getpgrp result: pid: %d(%s), " PRINTF_L4TASK_FORM ": %lx\n", 
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       regsp->ARM_r0);
	}
	printk("Syscall return: 0x%lx\n", regsp->ARM_r0);
#endif
}

static inline void dispatch_system_call(struct task_struct *p, unsigned long syscall)
{
	struct thread_struct *t = &p->thread;
	struct pt_regs *regsp = &t->regs;

	//syscall_count++;

	//utcb_to_thread_struct(utcb, t); /* XXX Hmm, we don't need to copy eax */

	regsp->ARM_ORIG_r0 = regsp->ARM_r0;

	if (unlikely(syscall == __NR_syscall - __NR_SYSCALL_BASE)) {
		call_system_call_args(regsp->ARM_r0,
		                      regsp->ARM_r1, regsp->ARM_r2,
		                      regsp->ARM_r3, regsp->ARM_r4,
		                      regsp->ARM_r5, regsp->ARM_r6,
		                      regsp);
	} else {
		call_system_call_args(syscall,
		                      regsp->ARM_r0, regsp->ARM_r1,
		                      regsp->ARM_r2, regsp->ARM_r3,
		                      regsp->ARM_r4, regsp->ARM_r5,
		                      regsp);
	}

	if (signal_pending(p))
		l4x_do_signal(regsp, syscall);

	if (need_resched())
		schedule();

	/* Prepare UTCB reply */
	//thread_struct_to_utcb(t, utcb, L4_UTCB_EXCEPTION_REGS_SIZE);
}

static char *l4x_arm_decode_error_code(unsigned long error_code)
{
	switch (error_code & 0x00f00000) {
		case 0x00100000:
			return "Undefined instruction";
		case 0x00200000:
			return "SWI";
		case 0x00400000:
			if (error_code & 0x00020000)
				return "Data abort (read)";
			return "Data abort";
		case 0x00500000:
			return "Forced exception";
	}
	return "Unknown";
}

/* XXX: Move that out to a separate file to avoid the VM_EXEC clash
 *      (they have the same value, but anyway... */
#undef VM_EXEC
#include <asm/asm-offsets.h>
#include <linux/stringify.h>

/* FP emu */
asm(
"	.data						\n"
"	.global fp_enter				\n"
"fp_enter:						\n"
"	.word callswi					\n"
"	.text						\n"
"callswi:						\n"
"	swi #2						\n"
);

/*
 * We directly call into the nwfpe code and do not take the fp_enter hook,
 * because otherwise the sp handling would be a bit too tricky.
 */
#ifndef CONFIG_FPE_NWFPE
#warning Building without floating point emulation support?
static inline unsigned int EmulateAll(unsigned int opcode)
{
	return 0;
}
static inline unsigned int checkCondition(const unsigned int opcode,
                                          const unsigned int ccode)
{
	return 0;
}
#else
unsigned int EmulateAll(unsigned int opcode);
unsigned int checkCondition(const unsigned int opcode, const unsigned int ccode);

struct pt_regs *l4x_fp_get_user_regs(void)
{
	return &current->thread.regs;
}
#endif

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

	if ((t->error_code & 0x00f00000) == 0x00500000) {
		/* we come here for suspend events */
		TBUF_LOG_SUSPEND(fiasco_tbuf_log_3val("dsp susp", TBUF_TID(t->user_thread_id), regs->ARM_pc, 0));
		l4x_dispatch_suspend(p, t);

		return 0;
	} else if ((t->error_code & 0x00f00000) == 0x00200000
	           && regs->ARM_pc < TASK_SIZE) {

		unsigned long val;
		enum { OABI_MASK = 0x0f000000 | __NR_OABI_SYSCALL_BASE };

		get_user(val, (unsigned long *)regs->ARM_pc);

		TBUF_LOG_INT80(fiasco_tbuf_log_3val("swi    ", TBUF_TID(t->user_thread_id), regs->ARM_pc, val));

		if (likely((val & OABI_MASK) == OABI_MASK)) {
			/* This is a Linux syscall swi */
			val &= ~(0xf0000000 | OABI_MASK);
		} else if ((val & 0x0fffffff) == 0x0f000000) {
			val = regs->uregs[7];
		} else
			val = ~0UL;

		if (likely(val != ~0UL)) {
			/* set after swi, before syscall so the forked childs
			 * get the increase too */
			regs->ARM_pc += thumb_mode(&t->regs) ? 2 : 4;

			// handle private ARM syscalls?
			if (unlikely(0xf0000 < val && val <= 0xf0000 + 5)) {
				// from traps.c
				asmlinkage int arm_syscall(int no, struct pt_regs *regs);
				arm_syscall(val | __NR_SYSCALL_BASE, regs);
				return 0;
			}

#ifdef CONFIG_L4_DEBUG_SEGFAULTS
			if (unlikely(val > 400))
				printk("Hmm, BIG syscall nr %ld\n", val);
#endif

			dispatch_system_call(p, val);

			BUG_ON(p != current);

			if (likely(!t->restart))
				/* fine, go send a reply and return to userland */
				return 0;

			/* Restart whole dispatch loop, also restarts thread */
			t->restart = 0;
			return 2;
		}

#ifdef CONFIG_L4_DEBUG_SEGFAULTS
		/* Unknown SWI */
		printk(PRINTF_L4TASK_FORM ": Strange SWI: Op %lx at %lx\n",
		       PRINTF_L4TASK_ARG(t->user_thread_id), val, regs->ARM_pc);
		enter_kdebug("strswi");
#endif

	} else if (t->error_code == 0x00300000) {
		/* Syscall alien exception */
		if (l4x_hybrid_begin(p, t))
			return 0;
	} else if (t->pf_signal_pending) {

		t->pf_signal_pending = 0;

		if (!signal_pending(p))
			enter_kdebug("BUG: no signal_pending");

		return 0;
	}

	TBUF_LOG_EXCP(fiasco_tbuf_log_3val("except ", TBUF_TID(t->user_thread_id), 0, regs->ARM_pc));

	{
		int handled = 0;

		while (1) {
			unsigned long insn;
			int ret;

			if (thumb_mode(&t->regs))
				LOG_printf("ATTN/FIXME: user does thumb code!!\n");

			ret = get_user(insn, (unsigned long *)t->regs.ARM_pc);
			t->regs.ARM_pc += 4;

			if (ret)
				break;

			if (!checkCondition(insn, t->regs.ARM_cpsr))
				break;

			if (EmulateAll(insn))
				handled = 1;
			else
				break;
		}

		t->regs.ARM_pc -= 4;

		if (likely(handled)) {
			//thread_struct_to_utcb(t, utcb,
			 //                     L4_UTCB_EXCEPTION_REGS_SIZE);
			return 0; /* handled */
		}
	}

#ifdef CONFIG_L4_DEBUG_SEGFAULTS
	l4x_print_regs(t);

	if (t->error_code == 0x00100000 || t->error_code == 0x00200000) {
		unsigned long val;

		get_user(val, (unsigned long *)regs->ARM_pc);

		printk(PRINTF_L4TASK_FORM ": Undefined instruction at %08lx with content %08lx\n",
		       PRINTF_L4TASK_ARG(t->user_thread_id), regs->ARM_pc, val);
		enter_kdebug("undef insn");
	}
#endif

	if (l4x_deliver_signal(0, t->error_code))
		return 0; /* handled signal, reply */

	/* This path should never be reached... */

	printk("Error code: %s\n", l4x_arm_decode_error_code(t->error_code));
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
#if 0
	if (t->regs.ARM_pc >= TASK_SIZE)
		printk("PC>3G: %08lx\n", t->regs.ARM_pc);
	if (l4x_l4pfa(t) >= TASK_SIZE)
		printk("PF>3G: %08lx\n", l4x_l4pfa(t));
#endif
	if (l4x_l4pfa(t) == 0xffff0ff0) {
		unsigned long pc = t->regs.ARM_pc;
		int targetreg = -1;

		if (thumb_mode(&t->regs)) {
			unsigned short op;
			get_user(op, (unsigned short *)pc);
			if ((op & 0xf800) == 0x6800) // ldr
				targetreg = op & 7;
			if (targetreg != -1)
				t->regs.uregs[targetreg] = current_thread_info()->tp_value;
			else
				LOG_printf("Lx: Unknown thumb opcode %hx at %lx\n", op, pc);
			t->regs.ARM_pc += 2;
		} else {
			unsigned long op;
			get_user(op, (unsigned long *)pc);
			// TBD
			LOG_printf("Lx: Unknown opcode %lx at %lx\n", op, pc);
			t->regs.ARM_pc += 4;
		}
		return 1; // handled
	}

	// __kuser_get_tls
	if (l4x_l4pfa(t) == 0xffff0fe0 && t->regs.ARM_pc == 0xffff0fe0) {
		t->regs.ARM_r0 = current_thread_info()->tp_value;
		t->regs.ARM_pc = t->regs.ARM_lr;
		return 1; // handled
	}

	if (t->regs.ARM_pc == 0xffff0fc0 && l4x_l4pfa(t) == 0xffff0fc0) {
		asmlinkage int arm_syscall(int no, struct pt_regs *regs);
		t->regs.ARM_r0 = arm_syscall(0x9ffff0 | __NR_SYSCALL_BASE, &t->regs);
		t->regs.ARM_pc = t->regs.ARM_lr;

		return 1; // handled
	}
	return 0; // not for us
}

#define __INCLUDED_FROM_L4LINUX_DISPATCH
#include "../dispatch.c"
