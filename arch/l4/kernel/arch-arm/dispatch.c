
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>

#include <asm/processor.h>
#include <asm/mmu_context.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>

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

#include <asm/l4x/exception.h>
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

asmlinkage void syscall_trace(int why, struct pt_regs *regs, int scno);

#include <asm/signal.h>
extern int do_signal(sigset_t *oldset, struct pt_regs *regs, int syscall);
static inline int l4x_do_signal(struct pt_regs *regs, int syscall)
{
	return do_signal(&current->blocked, regs, syscall);
}

// foo
extern void l4x_show_sigpending_processes(void);
extern void schedule_tail(struct task_struct *prev);

static inline l4_umword_t l4x_l4pfa(l4_utcb_t *utcb)
{
	return (utcb->exc.pfa & ~3) | (!(utcb->exc.err & 0x00020000) << 1);
}

static inline int l4x_ispf(l4_utcb_t *utcb)
{
	return utcb->exc.err & 0x00010000;
}

void l4x_finish_task_switch(struct task_struct *prev);
int  l4x_deliver_signal(int exception_nr, int error_code);

struct task_struct *l4x_current_process = l4x_idle_task(0);
struct thread_info *l4x_current_proc_run;

static volatile int show_state_trigger;

asm(
".section .text				\n"
".global ret_from_fork			\n"
"ret_from_fork:				\n"
"	bl	schedule_tail		\n"
"	bl	l4x_user_dispatcher	\n"
".previous				\n"
);

void fastcall l4x_switch_to(struct task_struct *prev, struct task_struct *next)
{
#if 0
	printk("%s: %s(%d)[%ld] -> %s(%d)[%ld]\n",
	       __func__, prev->comm, prev->pid, prev->state,
	                 next->comm, next->pid, next->state);
#endif
	TBUF_LOG_SWITCH(fiasco_tbuf_log_3val("SWITCH", TBUF_TID(prev->thread.user_thread_id), TBUF_TID(next->thread.user_thread_id), 0));
	l4x_current_process = next;
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
			pte_val(*ptep) |= (L_PTE_YOUNG + L_PTE_MAPPED);
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
				pte_val(*ptep) |= (L_PTE_YOUNG +
				                   L_PTE_DIRTY + L_PTE_MAPPED);
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

#if 0
	printk("l4lx-PF: pfa=%08x ip=%08x for %s(%d)\n",
	       pfa, ip, p->comm, p->pid);
#endif

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
	utcb_to_ptregs(utcb, &t->regs);
	t->error_code     = utcb->exc.err;
	t->address        = utcb->exc.pfa;
}

static inline void thread_struct_to_utcb(struct thread_struct *t,
                                         l4_utcb_t *utcb,
                                         unsigned int send_size)
{
	ptregs_to_utcb(&t->regs, utcb);
	utcb->snd_size = send_size;
}

static int l4x_hybrid_begin(struct task_struct *p,
                            struct thread_struct *t,
                            l4_utcb_t *utcb)
{
	int ret;
	l4_msgdope_t dummydope;
	int intnr = l4x_l4syscall_get_nr(utcb);

	if (intnr == -1
	    || !l4x_syscall_guard(p, utcb, intnr)
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
	utcb->snd_size = 0; /* We haven't modified the UTCB, so nothing to send */
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
			l4_umword_t data0, data1;
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

			utcb->snd_size = 0;
			ret = l4_ipc_send(p->thread.user_thread_id,
			                  L4_IPC_SHORT_FPAGE, data0, data1,
			                  L4_IPC_SEND_TIMEOUT_0, &dummydope);
			if (unlikely(ret))
				LOG_printf("%s: send error %x\n",
				           __func__, ret);
		}
	} while (t->hybrid_pf);

	if (signal_pending(p))
		l4x_do_signal(&t->regs, 0);

	/* When coming back from schedule, the register state was stored in
	 * pt_regs so move it to the utcb now for a proper reply */
	thread_struct_to_utcb(t, utcb, L4_UTCB_EXCEPTION_REGS_SIZE);

	return 1;
}

static void l4x_hybrid_return(l4_threadid_t src_id,
                              l4_utcb_t *utcb,
                              l4_umword_t d0, l4_umword_t d1)
{
	struct task_struct *h = l4x_hybrid_list_get(src_id);
	struct thread_struct *t;

	if (unlikely(!h))
		goto out_fail;

	t = &h->thread;

	if (!l4_utcb_exc_is_exc_ipc(d0, d1)) {
		/* No exception IPC, it's a page fault */
		t->hybrid_pf_addr = d0;
		t->hybrid_pf      = 1;
	} else {
		if (utcb->exc.err != 0x00310000
		    && utcb->exc.err != 0x00200000)
			goto out_fail;

		t->hybrid_sc_in_prog = 0;

		/* Keep registers */
		utcb_to_thread_struct(utcb, t);
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
	           h, utcb->exc.pfa, utcb->exc.err, l4x_l4syscall_get_nr(utcb),
	           l4_utcb_exc_pc(utcb));
	LOG_printf("%s: Currently running: " PRINTF_L4TASK_FORM "\n",
	           __func__, PRINTF_L4TASK_ARG(current->thread.user_thread_id));
	enter_kdebug("hybrid_return failed");
}

l4_threadid_t idler_thread = L4_INVALID_ID;

void l4x_wakeup_idler(void)
{
	l4_threadid_t pager_id, preempter_id;
	l4_umword_t o_efl, o_ip, o_sp;

	pager_id = preempter_id = L4_INVALID_ID;
	l4_thread_ex_regs_flags(idler_thread, 0, 0,
	                        &preempter_id, &pager_id,
	                        &o_efl, &o_ip, &o_sp,
	                        L4_THREAD_EX_REGS_RAISE_EXCEPTION);
	TBUF_LOG_WAKEUP_IDLE(fiasco_tbuf_log_3val("wakeup idle", 0, 0, 0));
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
	l4_utcb_t *utcb = l4_utcb_get_l4lx();

	idler_thread = l4lx_thread_create(idler_func, NULL, NULL, 0,
	                                  CONFIG_L4_PRIO_SERVER + 1,
	                                  "Idler");
	if (l4_is_invalid_id(idler_thread)) {
		LOG_printf("Could not create idler thread... exiting\n");
		l4x_exit_l4linux();
	}
	l4lx_thread_pager_change(idler_thread, l4_myself());

	utcb->rcv_size = L4_UTCB_EXCEPTION_REGS_SIZE;

	while (1) {

		/* &init_thread_info == current_thread_info() */
		l4x_current_proc_run = &init_thread_info;
		if (need_resched()) {
			l4x_current_proc_run = NULL;
			schedule();
			continue;
		}

		TBUF_LOG_IDLE(fiasco_tbuf_log_3val("l4x_idle <", 0, 0, 0));

		error = l4_ipc_wait(&src_id,
		                    L4_IPC_SHORT_MSG, &data0, &data1,
		                    L4_IPC_SEND_TIMEOUT_0, &dummydope);

		l4x_current_proc_run = NULL;

		TBUF_LOG_IDLE(fiasco_tbuf_log_3val("l4x_idle >", TBUF_TID(src_id), error, data0));

		if (unlikely(error)) {
			if (error != L4_IPC_RECANCELED) {
				LOG_printf("IPC error = %x (idle)\n", error);
				enter_kdebug("l4_idle: ipc_wait failed");
			}
			continue;
		}

		if (show_state_trigger) {
			show_state();
			show_state_trigger = 0;
		}

		if (likely(src_id.id.task == l4x_kernel_taskno)) {
			/* We have received a wakeup message from another
			 * kernel thread. Reschedule. */
			l4x_hybrid_do_regular_work();
			/* Paranoia */
			if ((utcb->exc.err & 0x00f00000) != 0x00500000) {
				LOG_printf("exc.err = 0x%lx\n", utcb->exc.err);
				enter_kdebug("Uhh, no exc?!");
			}
		} else
			l4x_hybrid_return(src_id, utcb, data0, data1);
	}
}

static inline void utcb_print_regs(l4_utcb_t *utcb)
{
#define R(nr) utcb->exc.r[nr]
	printk("0: %08lx %08lx %08lx %08lx %08lx %08lx %08lx %08lx\n",
	       R(0), R(1), R(2), R(3), R(4), R(5), R(6), R(7));
	printk("8: %08lx %08lx %08lx %08lx %08lx [01;34m%08lx[0m "
	       "%08lx [01;34m%08lx[0m\n",
	       R(8), R(9), R(10), R(11), R(12), utcb->exc.sp,
	       utcb->exc.ulr, utcb->exc.pc);
	printk("cpsr: %08lx err: %08lx addr: %08lx\n",
	       utcb->exc.cpsr, utcb->exc.err, utcb->exc.pfa);
#undef R
}

static inline unsigned long call_system_call_args(unsigned long syscall,
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
#endif

#if 0
	if (syscall == 11) {
		char *filename = getname((char *)arg1);
		printk("execve: pid: %d(%s), " PRINTF_L4TASK_FORM ": %s (%08lx)\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       IS_ERR(filename) ? "UNKNOWN" : filename, arg1);
		putname(filename);
	}
#endif
#if 0
	if (syscall == 1) {
		printk("exit: pid: %d(%s), " PRINTF_L4TASK_FORM "\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id));
	}
#endif
#if 0
	if (syscall == 2) {
		printk("fork: pid: %d(%s), " PRINTF_L4TASK_FORM "\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id));
	}
#endif
#if 0
	if (syscall == 3) {
		printk("read: pid: %d(%s), " PRINTF_L4TASK_FORM ": fd = %ld\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       arg1);
	}
#endif
#if 0
	if (syscall == 4) {
		printk("write: pid: %d(%s), " PRINTF_L4TASK_FORM ": fd = %ld\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       arg1);
	}
#endif
#if 0
	if (syscall == 5) {
		char *filename = getname((char *)arg1);
		printk("open: pid: %d(%s), " PRINTF_L4TASK_FORM ": %s (%lx)\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       IS_ERR(filename) ? "UNKNOWN" : filename, arg1);
		putname(filename);
	}
#endif
#if 0
	if (syscall == 120) {
		printk("clone: pid: %d(%s), " PRINTF_L4TASK_FORM "\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id));
	}
#endif
#if 0
	if (syscall == 190) {
		printk("vfork: pid: %d(%s), " PRINTF_L4TASK_FORM "\n",
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id));
	}
#endif
#if 0
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
#endif
#if 0
	if (syscall == 65) {
		printk("getpgrp result: pid: %d(%s), " PRINTF_L4TASK_FORM ": %lx\n", 
		       current->pid, current->comm,
		       PRINTF_L4TASK_ARG(current->thread.user_thread_id),
		       regsp->ARM_r0);
	}
#endif
#if 0
	printk("Syscall return: 0x%lx\n", regsp->ARM_r0);
#endif
}

static inline void dispatch_system_call(l4_utcb_t *utcb, unsigned long syscall)
{
	struct thread_struct *t = &current->thread;
	struct pt_regs *regsp = &t->regs;

	//syscall_count++;

	utcb_to_thread_struct(utcb, t); /* XXX Hmm, we don't need to copy eax */

	regsp->ARM_ORIG_r0 = utcb->exc.r[0];

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

	if (signal_pending(current))
		l4x_do_signal(regsp, syscall);

	if (need_resched())
		schedule();

	/* Prepare UTCB reply */
	thread_struct_to_utcb(t, utcb, L4_UTCB_EXCEPTION_REGS_SIZE);
}

static inline void l4x_dispatch_suspend(struct task_struct *p,
                                        struct thread_struct *t,
                                        l4_utcb_t *utcb)
{
	/* We're a suspended user process and want to
	 * sleep (aka schedule) now */

	if (unlikely(!t->initial_state_set))
		return;

	/* safe state */
	utcb_to_thread_struct(utcb, t);

	/* Go to sleep */
	schedule();

	/* Handle signals */
	if (signal_pending(p))
		l4x_do_signal(&t->regs, 0);

	/* Wakeup... reply to suspend exception */
	thread_struct_to_utcb(t, utcb, L4_UTCB_EXCEPTION_REGS_SIZE);
}

static inline void l4x_task_start_setup(struct task_struct *p, struct thread_struct *t,
                                        l4_utcb_t *utcb)
{
#if 0
	printk("%s: %d(%s), " PRINTF_L4TASK_FORM ": old sp = %p pc = %p\n",
	       __func__, p->pid, p->comm,
	       PRINTF_L4TASK_ARG(p->thread.user_thread_id),
	       (void *)utcb->exc.sp, (void *)utcb->exc.pc);
#endif
	if (signal_pending(p))
		l4x_do_signal(&p->thread.regs, 0);

	/* Copy initial regs */
	thread_struct_to_utcb(t, utcb, L4_UTCB_EXCEPTION_REGS_SIZE);
	t->initial_state_set = 1;
	t->is_hybrid = 0; /* cloned thread need to reset this */

#ifdef CONFIG_L4_DEBUG_REGISTER_NAMES
	fiasco_register_thread_name(p->thread.user_thread_id, p->comm);
#endif
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
                                         struct thread_struct *t,
                                         l4_utcb_t *utcb)
{
	TBUF_LOG_EXCP(fiasco_tbuf_log_3val("exceptB", TBUF_TID(t->user_thread_id), utcb->exc.pc, utcb->exc.err));

	l4x_hybrid_do_regular_work();
	l4x_debug_stats_exceptions_hit();

	if ((utcb->exc.err & 0x00f00000) == 0x00500000) {
		if (unlikely(!t->initial_state_set)) {
			if (unlikely(t->task_start_fork)) {
				if (unlikely(test_tsk_thread_flag(p,
				                                  TIF_SYSCALL_TRACE)))
					syscall_trace(1, &t->regs, __NR_fork);
				t->task_start_fork = 0;
			}

			/* forced kernel entry upon task start, just fill in
			 * the registers,
			 * this will only happen for additional threads in an
			 * address space, so that the first page-fault will not hit */
			TBUF_LOG_START(fiasco_tbuf_log_3val("task start", TBUF_TID(t->user_thread_id), t->regs.ARM_pc, t->regs.ARM_sp));

			/* Initial state already set? */
			BUG_ON(t->initial_state_set);

			l4x_task_start_setup(p, t, utcb);
			return 0;
		}

		/* we come here for suspend events */
		TBUF_LOG_SUSPEND(fiasco_tbuf_log_3val("dsp susp", TBUF_TID(t->user_thread_id), utcb->exc.pc, 0));
		l4x_dispatch_suspend(p, t, utcb);

		return 0;
	} else if ((utcb->exc.err & 0x00f00000) == 0x00200000
	           && utcb->exc.pc < TASK_SIZE) {

		unsigned long val;

		get_user(val, (unsigned long *)utcb->exc.pc);

		TBUF_LOG_INT80(fiasco_tbuf_log_3val("swi    ", TBUF_TID(t->user_thread_id), utcb->exc.pc, val));

		//printk("insn: %08lx\n", val);
		if (likely((val & 0x0f900000) == 0x0f900000)) {
			/* This is a Linux syscall swi */
			val &= ~0xff900000;

			/* set after swi, before syscall so the forked childs
			 * get the increase too */
			utcb->exc.pc += 4;

#ifdef CONFIG_L4_DEBUG_SEGFAULTS
			if (unlikely(val > 300))
				printk("Hmm, BIG syscall nr %ld\n", val);
#endif

			dispatch_system_call(utcb, val);

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
		       PRINTF_L4TASK_ARG(t->user_thread_id), val, utcb->exc.pc);
		enter_kdebug("strswi");
#endif

	} else if (utcb->exc.err == 0x00300000) {
		/* Syscall alien exception */
		if (l4x_hybrid_begin(p, t, utcb))
			return 0;
	} else if (t->pf_signal_pending) {

		t->pf_signal_pending = 0;

		if (!signal_pending(p))
			enter_kdebug("BUG: no signal_pending");

		return 0;
	}

	TBUF_LOG_EXCP(fiasco_tbuf_log_3val("except ", TBUF_TID(t->user_thread_id), 0, utcb->exc.err));

	utcb_to_thread_struct(utcb, t);

	{
		int handled = 0;

		while (1) {
			unsigned long insn;
			int ret;

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
			thread_struct_to_utcb(t, utcb,
			                      L4_UTCB_EXCEPTION_REGS_SIZE);
			return 0; /* handled */
		}
	}

#ifdef CONFIG_L4_DEBUG_SEGFAULTS
	utcb_print_regs(utcb);

	if (utcb->exc.err == 0x00100000) {
		unsigned long val;

		get_user(val, (unsigned long *)utcb->exc.pc);

		printk(PRINTF_L4TASK_FORM ": Undefined instruction at %08lx with content %08lx\n",
		       PRINTF_L4TASK_ARG(t->user_thread_id), utcb->exc.pc, val);
		enter_kdebug("undef insn");
	}
#endif

	if (l4x_deliver_signal(0, utcb->exc.err)) {
		thread_struct_to_utcb(t, utcb, L4_UTCB_EXCEPTION_REGS_SIZE);
		return 0; /* handled signal, reply */
	}

	/* This path should never be reached... */

	printk("Error code: %s\n", l4x_arm_decode_error_code(utcb->exc.err));
	printk("(Unknown) EXCEPTION [" PRINTF_L4TASK_FORM "]\n", PRINTF_L4TASK_ARG(t->user_thread_id));
	utcb_print_regs(utcb);
	printk("will die...\n");

	//enter_kdebug("check");

	/* The task somehow misbehaved, so it has to die */
	l4x_sig_current_kill();

	return 1; /* no reply */
}

static inline void l4x_dispatch_page_fault(struct task_struct *p,
                                           struct thread_struct *t,
                                           l4_utcb_t *utcb,
                                           l4_umword_t *d0,
                                           l4_umword_t *d1,
                                           void **msg_desc)
{
	TBUF_LOG_USER_PF(fiasco_tbuf_log_3val("U-PF   ",
	                 TBUF_TID(p->thread.user_thread_id),
	                 utcb->exc.pfa, l4_utcb_exc_pc(utcb)));

	utcb_to_thread_struct(utcb, t);

	if (l4x_handle_page_fault(p, l4x_l4pfa(utcb),
	                          l4_utcb_exc_pc(utcb), d0, d1)) {

		if (!signal_pending(p))
			force_sig(SIGSEGV, p);

		l4x_do_signal(&t->regs, 0);
		thread_struct_to_utcb(t, utcb, L4_UTCB_EXCEPTION_REGS_SIZE);

		*msg_desc = L4_IPC_SHORT_MSG;

		return;
	}

	if (need_resched())
		schedule();

	thread_struct_to_utcb(t, utcb, L4_UTCB_EXCEPTION_REGS_SIZE);

	*msg_desc = L4_IPC_SHORT_FPAGE;
	utcb->snd_size = 0;
}

/*
 * - Suspend thread
 */
void l4x_suspend_user(struct task_struct *p)
{
	l4_threadid_t pager_id, preempter_id;
	l4_umword_t o_efl, o_ip, o_sp;

	/* Do not suspend if it is still in the setup phase, also
	 * no need to interrupt as it will not stay out long... */
	if (unlikely(!p->thread.initial_state_set))
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

asmlinkage void l4x_user_dispatcher(void)
{
	struct task_struct *p = current;
	struct thread_struct *t = &p->thread;
	l4_umword_t data0;
	l4_umword_t data1;
	int error = 0;
	l4_threadid_t src_id;
	l4_msgdope_t dummydope;
	l4_utcb_t *utcb = l4_utcb_get_l4lx();
	void *msg_desc;
	int ret;

	utcb->rcv_size = L4_UTCB_EXCEPTION_REGS_SIZE;

	/* Start L4 activity */
restart_loop:
	l4x_start_thread_really();
	goto only_receive_IPC;

	while (1) {
		if (l4x_ispf(utcb)) {
			l4x_dispatch_page_fault(p, t, utcb, &data0, &data1, &msg_desc);
		} else {
			if ((ret = l4x_dispatch_exception(p, t, utcb))) {
				if (ret == 2)
					goto restart_loop;
				else
					goto only_receive_IPC;
			}

			msg_desc = L4_IPC_SHORT_MSG;
		}

		l4x_current_proc_run = current_thread_info();

		/*
		 * Actually we could use l4_ipc_call here but for our
		 * (asynchronous) hybrid apps we need to do an open wait.
		 */

		TBUF_LOG_DSP_IPC_IN(fiasco_tbuf_log_3val
		   ((msg_desc != L4_IPC_SHORT_FPAGE) ? "DSP-inM" : "DSP-inF",
		    TBUF_TID(current->thread.user_thread_id), data0, data1));
		/* send the reply message and wait for a new request. */
		error = l4_ipc_reply_and_wait(p->thread.user_thread_id,
		                              msg_desc, data0, data1,
		                              &src_id,
		                              L4_IPC_SHORT_MSG, &data0, &data1,
		                              L4_IPC_SEND_TIMEOUT_0,
		                              &dummydope);
after_IPC:
		l4x_current_proc_run = NULL;

		TBUF_LOG_DSP_IPC_OUT(fiasco_tbuf_log_3val("DSP-out",
		                     TBUF_TID(src_id),
		                     (error << 16) | utcb->exc.trapno,
		                     TBUF_TID(current->thread.user_thread_id)));
		TBUF_LOG_DSP_IPC_OUT(fiasco_tbuf_log_3val("DSP-val",
		                     TBUF_TID(src_id), data0, data1));

		if (unlikely(error == L4_IPC_SETIMEOUT)) {
			LOG_printf("IPC error SETIMEOUT (context) (to = "
			           PRINTF_L4TASK_FORM ", src = "
			           PRINTF_L4TASK_FORM ")\n",
			           PRINTF_L4TASK_ARG(p->thread.user_thread_id),
			           PRINTF_L4TASK_ARG(src_id));
			enter_kdebug("L4_IPC_SETIMEOUT?!");

only_receive_IPC:
			l4x_current_proc_run = current_thread_info();
			TBUF_LOG_DSP_IPC_IN(fiasco_tbuf_log_3val("DSP-in (O) ", TBUF_TID(current->thread.user_thread_id), TBUF_TID(src_id), 0));
			error = l4_ipc_wait(&src_id,
			                    L4_IPC_SHORT_MSG, &data0, &data1,
			                    L4_IPC_SEND_TIMEOUT_0, &dummydope);
			goto after_IPC;
		} else if (unlikely(error)) {
			LOG_printf("IPC error = 0x%x (context) (to = "
			           PRINTF_L4TASK_FORM ", src = "
			           PRINTF_L4TASK_FORM ")\n",
			           error,
			           PRINTF_L4TASK_ARG(p->thread.user_thread_id),
			           PRINTF_L4TASK_ARG(src_id));
			enter_kdebug("ipc error");
		}

		if (!l4_thread_equal(src_id, t->user_thread_id)) {
			if (unlikely(!l4_thread_equal(src_id, idler_thread)))
				l4x_hybrid_return(src_id, utcb, data0, data1);
			goto only_receive_IPC;
		}
	} /* endless loop */

	enter_kdebug("end of dispatch loop!?");
	l4x_deliver_signal(13, 0);
} /* l4x_user_dispatcher */
