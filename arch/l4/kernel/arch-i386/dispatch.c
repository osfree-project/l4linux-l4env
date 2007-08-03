
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

extern void fastcall do_signal(struct pt_regs *regs);

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
static DEFINE_PER_CPU(int, l4x_fpu_enabled);

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

static inline l4_umword_t l4x_parse_ptabs(struct task_struct *p,
                                          l4_umword_t address,
                                          l4_umword_t *pferror,
					  l4_fpage_t *fp)
{
	l4_umword_t phy = (l4_umword_t)(-EFAULT);
	pte_t *ptep = lookup_pte(p->mm->pgd, address);

	if (ptep && (pte_present(*ptep))) {
		if (!(address & PF_EWRITE)) {
			/* read access */
			ptep->pte_low |= (_PAGE_ACCESSED + _PAGE_MAPPED);
			phy = pte_val(*ptep) & PAGE_MASK;

			/* handle zero page specially */
			if (phy == 0)
				phy = PAGE0_PAGE_ADDRESS;

			*fp = l4_fpage(phy, L4_LOG2_PAGESIZE,
			               L4_FPAGE_RO, L4_FPAGE_MAP);
		} else {
			/* write access */
			if (pte_write(*ptep)) {
				/* page present and writable */
				ptep->pte_low |= (_PAGE_ACCESSED +
				                  _PAGE_DIRTY + _PAGE_MAPPED);
				phy = pte_val(*ptep) & PAGE_MASK;

				/* handle the zero page specially */
				if (phy == 0)
					phy = PAGE0_PAGE_ADDRESS;

				*fp = l4_fpage(phy, L4_LOG2_PAGESIZE,
				               L4_FPAGE_RW, L4_FPAGE_MAP);
			} else {
				/* page present, but not writable
				 * --> return error */
				*pferror = PF_EUSER + PF_EWRITE +
				           PF_EPROTECTION; /* = 7 */
			}
		}
	} else {
		/* page and/or pgdir not present --> return error */
		if ((address & PF_EWRITE))
			*pferror = PF_EUSER + PF_EWRITE +
				   PF_ENOTPRESENT; /* = 6  write access */
		else
			*pferror = PF_EUSER + PF_EREAD +
			           PF_ENOTPRESENT; /* = 4 rd access */
	}

	return phy;
}

static int l4x_no_page_found(struct task_struct *p,
                             l4_fpage_t *fp,
                             l4_umword_t eip,
			     l4_umword_t pfa)
{
	pte_t *ptep = lookup_pte(p->mm->pgd, pfa);

	if (ptep && pte_present(*ptep) &&
	    (pfa & PF_EWRITE) && !pte_write(*ptep)) {
		*fp = l4_fpage(pte_val(*ptep), L4_LOG2_PAGESIZE, 0, 0);
		return 1;
	}
	printk("\nNo page found for addr %lx\n"
	       "   eip: %lx, task: %p (%s, " PRINTF_L4TASK_FORM "), pgdir: %p\n",
	       pfa, eip, p, p->comm,
	       PRINTF_L4TASK_ARG(p->thread.user_thread_id),
	       p->mm->pgd);
	printk("lookup returns: pteptr: %p, pte: %lx\n",
	       ptep, ptep ? pte_val(*ptep) : 0UL);

	return 0;
}

/*
 * Handle device memory.
 *
 * \return address, 0 on error
 */
static inline unsigned long l4x_handle_dev_mem(unsigned long phy)
{
	unsigned long devmem;

#ifdef ARCH_x86
	if (phy > 0x80000000U) {
		if (!(devmem = find_ioremap_entry(phy))
		    && !(devmem = (unsigned long)ioremap(phy & L4_PAGEMASK,
							 L4_PAGESIZE))) {
			printk("Invalid device region requested: %08lx\n", phy);
			return 0;
		}
		devmem |= phy & (L4_PAGESIZE - 1);
	} else
#endif
	{
		if (!l4lx_memory_page_mapped(phy))
			return 0;
		devmem = phy;
	}
	return devmem;
}

static inline int l4x_handle_page_fault(struct task_struct *p,
                                        l4_umword_t pfa, l4_umword_t ip,
                                        l4_umword_t *d0, l4_umword_t *d1)
{
	l4_fpage_t fp;
	l4_umword_t pferror = 0;

	l4x_debug_stats_pagefault_hit();

	*d0 = pfa;

	if (likely(pfa < TASK_SIZE)) {
		/* Normal page fault with a process' virtual address space
		 */
		l4_umword_t phy;

		phy = l4x_parse_ptabs(p, pfa, &pferror, &fp);
		if (phy == (l4_umword_t)(-EFAULT)) {
			l4_umword_t pfe_old = pferror;

			if (l4x_do_page_fault(pfa, pferror)) {
#ifdef CONFIG_L4_DEBUG_SEGFAULTS
				LOG_printf("segfault for %s(%d) [" PRINTF_L4TASK_FORM "] "
				           "at %08lx, ip=%08lx, pferror = %lx\n",
				           p->comm, p->pid,
				           PRINTF_L4TASK_ARG(p->thread.user_thread_id),
				           pfa, ip, pferror);
				l4x_print_vm_area_maps(p);
				enter_kdebug("segfault");
#endif
				return 1;
			}

			pferror = 0;
			phy = l4x_parse_ptabs(p, pfa, &pferror, &fp);

			if (phy == (l4_umword_t)(-EFAULT)) {
				if (!l4x_no_page_found(p, &fp, ip, pfa)) {
					printk("segfault @ %lx, ip = %lx\n", pfa, ip);
					return 1;
				}
				phy = 0; /* reset phy */
			} else if (phy > 0xffff0000) {
				pte_t *ptep = lookup_pte(p->mm->pgd, pfa);
				printk("%s: phy=%lx pfa=%lx pferror=%lx pte_val=%lx "
				       "present=%ld\n    old_pferror=%lx %s(%d)\n",
				       __func__, phy, pfa, pferror, pte_val(*ptep),
				       pte_present(*ptep), pfe_old,
				       p->comm, p->pid);
				return 1;
			}
		}

		/* if the physical address is above RAM, then the user wants
		 * device memory.  Go grab it. */
		if (phy > (l4_umword_t)high_memory) {
			unsigned long devmem = l4x_handle_dev_mem(phy);
			if (!devmem)
				return 1; /* No region found */

			*d0 &= L4_PAGEMASK;
			*d1  = l4_fpage(devmem & L4_PAGEMASK,
			                L4_LOG2_PAGESIZE,
					L4_FPAGE_RW, L4_FPAGE_MAP).fpage;
		} else {
			*d0 &= PAGE_MASK;
			*d1  = fp.fpage;
		}
	} else if (unlikely(l4_is_io_page_fault(pfa))) {

		fp.fpage = pfa;
		DBG_IODB("USR [%s]: IO port 0x%04x", p->comm, fp.iofp.iopage);
		if (fp.iofp.iosize)
			DBG_IODB("-0x%04x",
			         fp.iofp.iopage + (1 << fp.iofp.iosize) - 1);
		DBG_IODB("\n");

		if (l4x_iodb_read_portrange(p, L4X_IODB_PORT_IOPL, 0) == 3) {
			DBG_IODB("USR [%s]: IOPL == 3.\n", p->comm);
			*d0  = 0;
			*d1  = fp.fpage;
		} else {
			DBG_IODB("USR [%s]: IOPL != 3.\n", p->comm);
			if (l4x_iodb_read_portrange(p, fp.iofp.iopage,
			                            1 << fp.iofp.iosize)) {
				DBG_IODB("USR [%s]: port allowed.\n",
				         p->comm);
				*d0  = 0;
				*d1  = fp.fpage;
			} else {
				DBG_IODB("USR  [%s]: I/O not allowed.\n",
				         p->comm);
				return 1;
			}
		}

#ifdef CONFIG_L4_FERRET_USER
	} else if (l4x_ferret_handle_pf(pfa, d0, d1)) {
		/* Handled */
#endif
	} else {
		/* page fault in upage */
		if ((pfa & PAGE_MASK) == UPAGE_USER_ADDRESS && !(pfa & 2)) {
			*d1 = l4_fpage((l4_umword_t)&_upage_start,
					L4_LOG2_PAGESIZE, L4_FPAGE_RO, L4_FPAGE_MAP).fpage;
		} else
			return 1;   /* invalid access */

		*d0 &= PAGE_MASK;
	}

	return 0; /* Success */
}

static inline void utcb_to_thread_struct(l4_utcb_t *utcb,
                                         struct thread_struct *t)
{
	//LOG_printf("utcb_to_thread_struct: utcb=%p pc=%lx\n", utcb, l4_utcb_exc_pc(utcb));
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
	//LOG_printf("thread_struct_to_utcb: utcb=%p pc=%lx\n", utcb, l4_utcb_exc_pc(utcb));
}

/*
 * First phase of a L4 system call by the user program
 */
static int l4x_hybrid_begin(struct task_struct *p,
                            struct thread_struct *t,
                            l4_utcb_t *utcb)
{
	int ret;
	l4_msgdope_t dummydope;
	int intnr = l4x_l4syscall_get_nr(t->error_code, t->regs.eip);

	if (intnr == -1
	    || !l4x_syscall_guard(p, intnr)
	    || t->hybrid_sc_in_prog)
		return 0;

	TBUF_LOG_HYB_BEGIN(fiasco_tbuf_log_3val("hyb-beg", TBUF_TID(t->user_thread_id), l4_utcb_exc_pc(utcb), intnr));

	t->hybrid_sc_in_prog = 1;

	if (!t->is_hybrid) {
#ifdef CONFIG_L4_DEBUG_REGISTER_NAMES
		char s[20] = "*";

		strncpy(s + 1, p->comm, sizeof(s) - 1);
		s[sizeof(s) - 1] = 0;

		fiasco_register_thread_name(p->thread.user_thread_id, s);
#endif

		t->is_hybrid = 1;
		/* l4x_hybrid_list_add may sleep */
		l4x_hybrid_list_add(p->thread.user_thread_id, p);
	}

	/* Let the user go on on the syscall instruction */
	per_cpu(utcb_snd_size, smp_processor_id()) = 0; /* We haven't modified the UTCB, so nothing to send */
	ret = l4_ipc_send(p->thread.user_thread_id,
	                  L4_IPC_SHORT_MSG, L4_EXCEPTION_REPLY_DW0_DEALIEN, 0,
	                  L4_IPC_SEND_TIMEOUT_0, &dummydope);

	if (unlikely(ret))
		LOG_printf("%s: send error %x\n", __func__, ret);

	do {
		t->hybrid_pf = t->hybrid_pf_addr = 0;

		/* Mark current as uninterruptible and schedule away */
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule();

		/* PF pending? */
		if (t->hybrid_pf) {
			int ret;
			l4_umword_t data0, data1 = 0;
			l4_msgdope_t dummydope;

			if (unlikely(l4x_handle_page_fault(p,
			                                   t->hybrid_pf_addr, 0,
			                                   &data0, &data1))) {
				/* Umm, failed?!
				 * XXX: call sighandler here */
				force_sig(SIGKILL, p);

				printk("Failed to resolved page fault "
				       "for hybrid task %s(%d) at %08lx. "
				       "Killed.\n",
				       p->comm, p->pid, data0);

				/* Leave loop */
				t->hybrid_pf = t->hybrid_pf_addr = 0;
			}

			per_cpu(utcb_snd_size, smp_processor_id()) = 0;
			ret = l4_ipc_send(p->thread.user_thread_id,
			                  L4_IPC_SHORT_FPAGE, data0, data1,
			                  L4_IPC_SEND_TIMEOUT_0, &dummydope);
			if (unlikely(ret))
				LOG_printf("%s: send error %x\n",
				           __func__, ret);
		}
	} while (t->hybrid_pf);

	if (signal_pending(p))
		do_signal(&t->regs);

	/* When coming back from schedule, the register state was stored in
	 * pt_regs so move it to the utcb now for a proper reply */
	//thread_struct_to_utcb(t, l4_utcb_get_l4lx(smp_processor_id()), L4_UTCB_EXCEPTION_REGS_SIZE);

	return 1;
}

static void l4x_hybrid_return(l4_threadid_t src_id,
                              l4_utcb_t *utcb,
                              l4_umword_t d0, l4_umword_t d1,
                              l4_msgtag_t tag)
{
	struct task_struct *h = l4x_hybrid_list_get(src_id);
	struct thread_struct *t;

	if (unlikely(!h))
		goto out_fail;

	t = &h->thread;

	if (l4_msgtag_is_page_fault(tag)) {
		/* No exception IPC, it's a page fault */
		t->hybrid_pf_addr = d0;
		t->hybrid_pf      = 1;
	} else {
		if (unlikely(   (utcb->exc.trapno != 0xd /* after L4 syscall */
		                 || l4x_l4syscall_get_nr(utcb->exc.err, utcb->exc.eip) == -1
		                 || !(utcb->exc.err & 4))
		             && (utcb->exc.trapno != 0xff /* L4 syscall exr'd */
		                 || utcb->exc.err != 0)))
			goto out_fail;

		t->hybrid_sc_in_prog = 0;

		/* Keep registers */
		//utcb_to_thread_struct(utcb, t);
	}

	TBUF_LOG_HYB_RETURN(fiasco_tbuf_log_3val("hyb-ret", TBUF_TID(t->user_thread_id), l4_utcb_exc_pc(utcb), t->hybrid_pf_addr));

	/* Wake up hybrid task h and reschedule */
	wake_up_process(h);
	set_need_resched();

	return;

out_fail:
	LOG_printf("%s: Invalid hybrid return for " PRINTF_L4TASK_FORM " ("
	           "%p, %lx, %lx, %d, %lx)!\n",
	           __func__, PRINTF_L4TASK_ARG(src_id),
	           h, utcb->exc.trapno, utcb->exc.err, l4x_l4syscall_get_nr(utcb->exc.err, utcb->exc.eip),
	           l4_utcb_exc_pc(utcb));
	LOG_printf("%s: Currently running: " PRINTF_L4TASK_FORM "\n",
	           __func__, PRINTF_L4TASK_ARG(current->thread.user_thread_id));
	enter_kdebug("hybrid_return failed");
}

static l4_threadid_t idler_thread[NR_CPUS];
static int           idler_up[NR_CPUS];

void l4x_wakeup_idler(int cpu)
{
	l4_threadid_t pager_id, preempter_id;
	l4_umword_t o_efl, o_ip, o_sp;

	if (!idler_up[cpu])
		return;

	pager_id = preempter_id = L4_INVALID_ID;
	l4_thread_ex_regs_flags(idler_thread[cpu], 0, 0,
	                        &preempter_id, &pager_id,
	                        &o_efl, &o_ip, &o_sp,
	                        L4_THREAD_EX_REGS_RAISE_EXCEPTION);
	TBUF_LOG_WAKEUP_IDLE(fiasco_tbuf_log_3val("wakeup idle", cpu, 0, 0));
}

static void idler_func(void *data)
{
	while (1)
		l4_sleep_forever();
}

void l4x_idle(void)
{
	l4_threadid_t src_id;
	int error;
	l4_umword_t data0, data1;
	l4_msgdope_t dummydope;
	l4_msgtag_t tag;
	int cpu = smp_processor_id();
	l4_utcb_t *utcb = l4_utcb_get_l4lx(cpu);
	char s[9];

#ifdef CONFIG_SMP
	snprintf(s, sizeof(s), "idler%d", cpu);
#else
	snprintf(s, sizeof(s), "idler");
#endif
	s[sizeof(s) - 1] = 0;

	LOG_printf("idler%d: utcb=%p " PRINTF_L4TASK_FORM "\n",
			cpu, utcb, PRINTF_L4TASK_ARG(l4_myself()));

	idler_thread[cpu] = l4lx_thread_create(idler_func, NULL, NULL, 0,
	                                       CONFIG_L4_PRIO_SERVER + 1, s);
	if (l4_is_invalid_id(idler_thread[cpu])) {
		LOG_printf("Could not create idler thread... exiting\n");
		l4x_exit_l4linux();
	}
	l4lx_thread_pager_change(idler_thread[cpu], l4_myself());
	idler_up[cpu] = 1;

	tick_nohz_stop_sched_tick();

	while (1) {

		/* &init_thread_info == current_thread_info() */
		per_cpu(l4x_current_proc_run, cpu) = &init_thread_info;
		current_thread_info()->status &= ~TS_POLLING;

		l4x_smp_process_IPI();

		if (need_resched()) {
			per_cpu(l4x_current_proc_run, cpu) = NULL;
			current_thread_info()->status |= TS_POLLING;
			tick_nohz_restart_sched_tick();
			preempt_enable_no_resched();
			schedule();
			preempt_disable();
			tick_nohz_stop_sched_tick();
			continue;
		}
		check_pgt_cache();

		TBUF_LOG_IDLE(fiasco_tbuf_log_3val("l4x_idle <", cpu, 0, 0));

		error = l4_ipc_wait_tag(&src_id,
		                        L4_IPC_SHORT_MSG, &data0, &data1,
		                        L4_IPC_SEND_TIMEOUT_0, &dummydope, &tag);

		per_cpu(l4x_current_proc_run, cpu) = NULL;
		current_thread_info()->status |= TS_POLLING;

		TBUF_LOG_IDLE(fiasco_tbuf_log_3val("l4x_idle >",
		              TBUF_TID(src_id) | (cpu << 16), error, data0));

		if (unlikely(error)) {
			if (error != L4_IPC_RECANCELED) {
				LOG_printf("idle%d: IPC error = %x (idle)\n",
				           smp_processor_id(), error);
				enter_kdebug("l4_idle: ipc_wait failed");
			}
			continue;
		}

		if (likely(src_id.id.task == l4x_kernel_taskno)) {
			/* We have received a wakeup message from another
			 * kernel thread. Reschedule. */
			l4x_hybrid_do_regular_work();

			/* Check for IPI */
			if (l4x_IPI_is_ipi_message(data0))
				continue;

			/* Paranoia */
			if (!l4_msgtag_is_exception(tag)
			    || l4_utcb_get_l4lx(smp_processor_id())->exc.trapno != 0xff) {
				LOG_printf("idler%d: src=" PRINTF_L4TASK_FORM " exc.trapno = 0x%lx (d0 = %lx, d1 = %lx, tag = %lx)\n",
				           cpu, PRINTF_L4TASK_ARG(src_id), l4_utcb_get_l4lx(smp_processor_id())->exc.trapno, data0, data1, l4_msgtag_label(tag));
				enter_kdebug("Uhh, no exc?!");
			}
		} else
			l4x_hybrid_return(src_id, l4_utcb_get_l4lx(smp_processor_id()), data0, data1, tag);
	}
}

static inline void dispatch_system_call(struct task_struct *p)
{
	struct thread_struct *t = &p->thread;
	register struct pt_regs *regsp = &t->regs;
	unsigned int syscall;
	syscall_t syscall_fn = NULL;

	//syscall_count++;

	//utcb_to_thread_struct(l4_utcb_get_l4lx(smp_processor_id()), t); /* XXX Hmm, we don't need to copy eax */
	regsp->orig_eax = syscall = regsp->eax; //l4_utcb_get_l4lx(smp_processor_id())->exc.eax;
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
		do_signal(regsp);

	if (need_resched())
		schedule();

	/* Prepare UTCB reply */
	//thread_struct_to_utcb(t, l4_utcb_get_l4lx(smp_processor_id()), L4_UTCB_EXCEPTION_REGS_SIZE);

#if 0
	LOG_printf("Syscall %3d for %s(%d at %p): return %lx\n",
	           syscall, p->comm, p->pid, (void *)regsp->eip,
	           regsp->eax);
#endif
	if (unlikely(syscall == -38))
		enter_kdebug("no ssycall");
}

static inline void l4x_dispatch_suspend(struct task_struct *p,
                                        struct thread_struct *t)
{
	/* We're a suspended user process and want to
	 * sleep (aka schedule) now */

	if (unlikely(!t->initial_state_set
	             || !test_bit(smp_processor_id(), &t->threads_up)))
		return;

	/* Go to sleep */
	schedule();

	/* Handle signals */
	if (signal_pending(p))
		do_signal(&t->regs);
}

static inline void l4x_task_start_setup(struct task_struct *p, struct thread_struct *t)
{
	if (signal_pending(p))
		do_signal(&t->regs);

	t->initial_state_set = 1;
	t->is_hybrid = 0; /* cloned thread need to reset this */

	/* Setup LDTs */
	if (p->mm && p->mm->context.size)
		fiasco_ldt_set(p->mm->context.ldt,
		               p->mm->context.size * LDT_ENTRY_SIZE, 0,
		               p->thread.user_thread_id.id.task);
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
					per_cpu(utcb_snd_size, smp_processor_id()) = L4_UTCB_EXCEPTION_REGS_SIZE;
					return 1;
			};
		case 0xee: /* out al, dx */
			switch (regs->edx & 0xffff) {
				case 0x3c0:
					regs->eip++;
					per_cpu(utcb_snd_size, smp_processor_id()) = L4_UTCB_EXCEPTION_REGS_SIZE;
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

		per_cpu(utcb_snd_size, smp_processor_id()) = L4_UTCB_EXCEPTION_REGS_SIZE;
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
		per_cpu(utcb_snd_size, smp_processor_id()) = L4_UTCB_EXCEPTION_REGS_SIZE;
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
		per_cpu(utcb_snd_size, smp_processor_id()) = L4_UTCB_EXCEPTION_REGS_SIZE;
		return 0;
	} else if (t->trap_no == 0xd) {
		if (l4x_hybrid_begin(p, t, l4_utcb_get_l4lx(smp_processor_id())))
			return 0;

		/* Fall through otherwise */
	}

	if (t->trap_no == 3)
		if (l4x_kdebug_emulation(regs))
			return 0; /* known and handled */

	if (l4x_port_emulation(regs))
		return 0; /* known and handled */

	TBUF_LOG_EXCP(fiasco_tbuf_log_3val("except ", TBUF_TID(t->user_thread_id), t->trap_no, t->error_code));

	//utcb_to_thread_struct(l4_utcb_get_l4lx(smp_processor_id()), t);
	if (l4x_deliver_signal(t->trap_no, t->error_code)) {
		//thread_struct_to_utcb(t,
		//l4_utcb_get_l4lx(smp_processor_id()), L4_UTCB_EXCEPTION_REGS_SIZE);
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

static inline void l4x_dispatch_page_fault(struct task_struct *p,
                                           struct thread_struct *t,
                                           l4_umword_t *d0,
                                           l4_umword_t *d1,
                                           void **msg_desc)
{
	TBUF_LOG_USER_PF(fiasco_tbuf_log_3val("U-PF   ",
	                 TBUF_TID(p->thread.user_thread_id),
	                 t->pfa, t->regs.eip));

	if (l4x_handle_page_fault(p, l4x_l4pfa(t),
	                          t->regs.eip, d0, d1)) {

		if (!signal_pending(p))
			force_sig(SIGSEGV, p);

		do_signal(&t->regs);

		*msg_desc = L4_IPC_SHORT_MSG;

		return;
	}

	if (need_resched())
		schedule();

	*msg_desc = L4_IPC_SHORT_FPAGE;
	per_cpu(utcb_snd_size, smp_processor_id()) = L4_UTCB_EXCEPTION_REGS_SIZE;
}

/*
 * - Suspend thread
 */
void l4x_suspend_user(struct task_struct *p, int cpu)
{
	l4_threadid_t pager_id, preempter_id;
	l4_umword_t o_efl, o_ip, o_sp;

	/* Do not suspend if it is still in the setup phase, also
	 * no need to interrupt as it will not stay out long... */
	//if (unlikely(!p->thread.initial_state_set))
	if (!test_bit(cpu, &p->thread.threads_up))
		return;

	pager_id = preempter_id = L4_INVALID_ID;

	l4_inter_task_ex_regs(p->thread.user_thread_id,
	                      ~0UL, ~0UL,
	                      &preempter_id, &pager_id,
	                      &o_efl, &o_ip, &o_sp,
	                      L4_THREAD_EX_REGS_NO_CANCEL
	                       | L4_THREAD_EX_REGS_ALIEN
	                       | L4_THREAD_EX_REGS_RAISE_EXCEPTION);
	TBUF_LOG_SUSP_PUSH(fiasco_tbuf_log_3val("suspend", TBUF_TID(p->thread.user_thread_id), o_ip, o_efl));

	l4x_debug_stats_suspend_hit();
}

static inline void l4x_spawn_cpu_thread(int cpu_change,
                                        struct task_struct *p,
                                        struct thread_struct *t)
{
	int cpu = smp_processor_id();
	l4_threadid_t me = l4_myself(); // XXX: use stack function
	int error;
	l4_umword_t data0;
	l4_msgdope_t dummydope;
	l4_threadid_t pseudo_parent = L4_NIL_ID;
#ifdef CONFIG_L4_DEBUG_REGISTER_NAMES
	char s[10];
#endif

	if (cpu_change)
		pseudo_parent = t->user_thread_ids[t->start_cpu];

	if (l4lx_task_get_new_task(pseudo_parent,
	                           &t->user_thread_id)) {
		printk("l4x_thread_create: No task no left for user\n"); 
		return;
	}


	t->user_thread_ids[cpu] = t->user_thread_id;
	if (!cpu_change)
		t->start_cpu = cpu;



	if (!l4lx_task_create_pager(t->user_thread_id, me)) {
		printk("%s: Failed to create user task\n", __func__);
		return;
	}

	// now wait that thread comes in

	error = l4_ipc_receive(t->user_thread_id,
	                       L4_IPC_SHORT_MSG, &data0, &data0,
	                       L4_IPC_SEND_TIMEOUT_0, &dummydope);
	if (error)
		LOG_printf("%s: IPC error %x\n", __func__, error);

	set_bit(cpu, &t->threads_up);

#ifdef CONFIG_L4_DEBUG_REGISTER_NAMES
#ifdef CONFIG_SMP
	snprintf(s, sizeof(s), "%s-%d", p->comm, cpu);
#else
	snprintf(s, sizeof(s), "%s", p->comm);
#endif
	s[sizeof(s)-1] = 0;
	fiasco_register_thread_name(t->user_thread_id, s);
#endif


	if (!cpu_change) {

		t->started = 1;

		if (t->task_start_fork) {
			if (unlikely(current_thread_info()->flags
			             & (_TIF_SYSCALL_TRACE
			                | _TIF_SYSCALL_AUDIT
			                | _TIF_SECCOMP)))
				do_syscall_trace(&t->regs, 1);
			t->task_start_fork = 0;
		}

		TBUF_LOG_START(fiasco_tbuf_log_3val("task start", TBUF_TID(t->user_thread_id), t->regs.eip, t->regs.esp));

		l4x_task_start_setup(p, t);
	}

	per_cpu(utcb_snd_size, smp_processor_id()) = L4_UTCB_EXCEPTION_REGS_SIZE;

	load_TLS(t, 0);
}

static inline int l4x_msgtag_fpu(void)
{
	return per_cpu(l4x_fpu_enabled, smp_processor_id()) ? 0x8000 : 0;
}

asmlinkage void l4x_user_dispatcher(void)
{
	struct task_struct *p = current;
	struct thread_struct *t = &p->thread;
	l4_umword_t data0 = 0, data1 = 0;
	int error = 0;
	l4_threadid_t src_id;
	l4_msgdope_t dummydope;
	l4_msgtag_t tag;
	void *msg_desc;
	int ret;

	/* Start L4 activity */
	t->restart = 0;
restart_loop:
	l4x_spawn_cpu_thread(0, p, t);
	msg_desc = L4_IPC_SHORT_MSG;
	goto reply_IPC;

	while (1) {
		if (l4x_ispf(t)) {
			l4x_dispatch_page_fault(p, t, &data0, &data1, &msg_desc);
		} else {
			if ((ret = l4x_dispatch_exception(p, t))) {
				if (ret == 2)
					goto restart_loop;
				goto only_receive_IPC;
			}

			msg_desc = L4_IPC_SHORT_MSG;
		}

		if (!test_bit(smp_processor_id(), &p->thread.threads_up))
			l4x_spawn_cpu_thread(1, p, t);

		p->thread.user_thread_id
			= p->thread.user_thread_ids[smp_processor_id()];

reply_IPC:
		thread_struct_to_utcb(t, l4_utcb_get_l4lx(smp_processor_id()),
		                      per_cpu(utcb_snd_size, smp_processor_id()));

		per_cpu(l4x_current_proc_run, smp_processor_id()) = current_thread_info();

		/*
		 * Actually we could use l4_ipc_call here but for our
		 * (asynchronous) hybrid apps and IPIs we need to do an open
		 * wait.
		 */

		TBUF_LOG_DSP_IPC_IN(fiasco_tbuf_log_3val
		   ((msg_desc != L4_IPC_SHORT_FPAGE) ? "DSP-inM" : "DSP-inF",
		    TBUF_TID(current->thread.user_thread_id), 0, 0));

		/* send the reply message and wait for a new request. */
		tag = l4_msgtag(0, per_cpu(utcb_snd_size, smp_processor_id()), 0,
		                l4x_msgtag_fpu());
		error = l4_ipc_reply_and_wait_tag(p->thread.user_thread_id,
		                                  msg_desc, data0, data1,
		                                  tag,
		                                  &src_id,
		                                  L4_IPC_SHORT_MSG,
		                                  &data0, &data1,
		                                  L4_IPC_SEND_TIMEOUT_0,
		                                  &dummydope, &tag);
after_IPC:
		per_cpu(l4x_current_proc_run, smp_processor_id()) = NULL;

		TBUF_LOG_DSP_IPC_OUT(fiasco_tbuf_log_3val("DSP-out", TBUF_TID(src_id),
		                     (error << 16), TBUF_TID(current->thread.user_thread_id)));
		TBUF_LOG_DSP_IPC_OUT(fiasco_tbuf_log_3val("DSP-val", TBUF_TID(src_id), data0, data1));

		if (unlikely(error == L4_IPC_SETIMEOUT)) {
			LOG_printf("dispatch%d: "
			           "IPC error SETIMEOUT (context) (to = "
			           PRINTF_L4TASK_FORM ", src = "
			           PRINTF_L4TASK_FORM ")\n",
			           smp_processor_id(),
			           PRINTF_L4TASK_ARG(p->thread.user_thread_id),
			           PRINTF_L4TASK_ARG(src_id));
			enter_kdebug("L4_IPC_SETIMEOUT?!");

only_receive_IPC:
			per_cpu(l4x_current_proc_run, smp_processor_id()) = current_thread_info();
			TBUF_LOG_DSP_IPC_IN(fiasco_tbuf_log_3val("DSP-in (O) ",
			                    TBUF_TID(current->thread.user_thread_id),
			                    TBUF_TID(src_id), 0));
			error = l4_ipc_wait_tag(&src_id,
			                        L4_IPC_SHORT_MSG, &data0, &data1,
			                        L4_IPC_SEND_TIMEOUT_0,
			                        &dummydope, &tag);
			goto after_IPC;
		} else if (unlikely(error)) {
			LOG_printf("dispatch%d: IPC error = 0x%x (context) (to = "
			           PRINTF_L4TASK_FORM ", src = "
			           PRINTF_L4TASK_FORM ")\n",
			           smp_processor_id(), error,
			           PRINTF_L4TASK_ARG(p->thread.user_thread_id),
			           PRINTF_L4TASK_ARG(src_id));
			enter_kdebug("ipc error");
		}

		if (!l4_thread_equal(src_id, t->user_thread_id)) {

			if (src_id.id.task == l4x_kernel_taskno) {

				if (l4x_IPI_is_ipi_message(data0))
					l4x_smp_process_IPI();

				goto only_receive_IPC;
			}

			l4x_hybrid_return(src_id, l4_utcb_get_l4lx(smp_processor_id()),
			                  data0, data1, tag);

			goto only_receive_IPC;
		}

		// copy utcb now that we have made sure to have received
		// from t
		utcb_to_thread_struct(l4_utcb_get_l4lx(smp_processor_id()), t);
	} /* endless loop */

	enter_kdebug("end of dispatch loop!?");
	l4x_deliver_signal(13, 0);
} /* l4x_user_dispatcher */
