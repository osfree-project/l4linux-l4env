
#ifndef __INCLUDED_FROM_L4LINUX_DISPATCH
#error Do NOT compile this file directly.
#endif

#include <l4/sys/cache.h>

DEFINE_PER_CPU(int, l4x_idle_running);

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
			l4x_pte_add_access_and_mapped(ptep);
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
				l4x_pte_add_access_mapped_and_dirty(ptep);
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
				l4x_print_regs(&p->thread);
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

			l4_sys_cache_clean_range
			    (fp.fp.page << L4_LOG2_PAGESIZE,
			     (fp.fp.page << L4_LOG2_PAGESIZE) + PAGE_SIZE);
		}
#ifdef ARCH_x86
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
#endif
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

/*
 * First phase of a L4 system call by the user program
 */
static int l4x_hybrid_begin(struct task_struct *p,
                            struct thread_struct *t)
{
	int ret;
	l4_msgdope_t dummydope;
	int intnr = l4x_l4syscall_get_nr(t->error_code, regs_pc(t));

	if (intnr == -1
	    || !l4x_syscall_guard(p, intnr)
	    || t->hybrid_sc_in_prog)
		return 0;

	TBUF_LOG_HYB_BEGIN(fiasco_tbuf_log_3val("hyb-beg", TBUF_TID(t->user_thread_id), regs_pc(t), intnr));

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
		l4x_do_signal(&t->regs, 0);

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
		if (!l4x_hybrid_check_after_syscall(utcb))
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
	           "%p, %lx, %lx, %d, %lx, %lx)!\n",
	           __func__, PRINTF_L4TASK_ARG(src_id),
	           h, l4_utcb_exc_typeval(utcb), utcb->exc.err,
	           l4x_l4syscall_get_nr(utcb->exc.err, l4_utcb_exc_pc(utcb)),
	           l4_utcb_exc_pc(utcb), tag.raw);
	LOG_printf("%s: Currently running user thread: " PRINTF_L4TASK_FORM
	           "  service: " PRINTF_L4TASK_FORM "\n",
	           __func__, PRINTF_L4TASK_ARG(current->thread.user_thread_id),
	           PRINTF_L4TASK_ARG(l4_myself()));
	enter_kdebug("hybrid_return failed");
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
		l4x_do_signal(&t->regs, 0);
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
	l4_thread_ex_regs_flags(idler_thread[cpu], ~0UL, ~0UL,
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
	l4_utcb_t *utcb = l4x_utcb_get(l4_myself());
	char s[9];

	snprintf(s, sizeof(s), "idler%d", cpu);
	s[sizeof(s) - 1] = 0;

	LOG_printf("idler%d: utcb=%p " PRINTF_L4TASK_FORM "\n",
	           cpu, utcb, PRINTF_L4TASK_ARG(l4_myself()));

	idler_thread[cpu] = l4lx_thread_create(idler_func, 0, NULL, NULL, 0,
	                                       CONFIG_L4_PRIO_IDLER, s);
	if (l4_is_invalid_id(idler_thread[cpu])) {
		LOG_printf("Could not create idler thread... exiting\n");
		l4x_exit_l4linux();
	}
	l4lx_thread_pager_change(idler_thread[cpu], l4_myself());
	idler_up[cpu] = 1;

	tick_nohz_stop_sched_tick();

	while (1) {
		per_cpu(l4x_current_proc_run, cpu) = current_thread_info();
		per_cpu(l4x_idle_running, cpu) = 1;
		l4x_dispatch_delete_polling_flag();

		if (need_resched()) {
			per_cpu(l4x_current_proc_run, cpu) = NULL;
			per_cpu(l4x_idle_running, cpu) = 0;
			l4x_dispatch_set_polling_flag();
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
		per_cpu(l4x_idle_running, cpu) = 0;
		l4x_dispatch_set_polling_flag();

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

			/* Paranoia */
			if (!l4_msgtag_is_exception(tag)
			    || !l4x_is_triggered_exception(l4_utcb_exc_typeval(l4x_utcb_get(l4_myself())))) {
				LOG_printf("idler%d: src=" PRINTF_L4TASK_FORM
				           " exc-val = 0x%lx (d0 = %lx, "
				           "d1 = %lx, tag = %lx)\n",
				           cpu, PRINTF_L4TASK_ARG(src_id),
				           l4_utcb_exc_typeval(l4x_utcb_get(l4_myself())),
				           data0, data1, l4_msgtag_label(tag));
				enter_kdebug("Uhh, no exc?!");
			}
		} else
			l4x_hybrid_return(src_id, l4x_utcb_get(l4_myself()), data0, data1, tag);
	}
}

static inline void l4x_dispatch_page_fault(struct task_struct *p,
                                           struct thread_struct *t,
                                           l4_umword_t *d0,
                                           l4_umword_t *d1,
                                           void **msg_desc)
{
	TBUF_LOG_USER_PF(fiasco_tbuf_log_3val("U-PF   ",
	                 TBUF_TID(p->thread.user_thread_id),
	                 l4x_l4pfa(t), regs_pc(t)));

	if (unlikely(l4x_handle_page_fault_with_exception(t))) {
		*msg_desc = L4_IPC_SHORT_MSG;
		return;
	}

	if (l4x_handle_page_fault(p, l4x_l4pfa(t),
	                          regs_pc(t), d0, d1)) {

		if (!signal_pending(p))
			force_sig(SIGSEGV, p);

		l4x_do_signal(&t->regs, 0);

		*msg_desc = L4_IPC_SHORT_MSG;

		return;
	}

	if (need_resched())
		schedule();

	*msg_desc = L4_IPC_SHORT_FPAGE;
}

/*
 * - Suspend thread
 */
void l4x_suspend_user(struct task_struct *p, int cpu)
{
	l4_threadid_t inv_id = L4_INVALID_ID;
	l4_umword_t o_efl, o_ip, o_sp;

	/* Do not suspend if it is still in the setup phase, also
	 * no need to interrupt as it will not stay out long... */
	//if (unlikely(!p->thread.initial_state_set))
	if (!test_bit(cpu, &p->thread.threads_up))
		return;

	l4_thread_ex_regs_sc
	  (l4_thread_ex_regs_reg0(p->thread.user_thread_id.id.lthread,
	                          p->thread.user_thread_id.id.task,
	                          L4_THREAD_EX_REGS_NO_CANCEL
	                          | L4_THREAD_EX_REGS_ALIEN
	                          | L4_THREAD_EX_REGS_RAISE_EXCEPTION),
	   ~0UL, ~0UL, &inv_id, &inv_id, &o_efl, &o_ip, &o_sp);
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
	else if (!l4_is_nil_id(t->cloner))
		pseudo_parent = t->cloner;

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

		l4x_arch_task_start_setup(p);

		if (l4_is_nil_id(t->cloner)) // this is a fork
			l4x_arch_do_syscall_trace(p, t);

		TBUF_LOG_START(fiasco_tbuf_log_3val("task start", TBUF_TID(t->user_thread_id), regs_pc(t), regs_sp(t)));

		if (signal_pending(p))
			l4x_do_signal(&t->regs, 0);

		t->initial_state_set = 1;
		t->is_hybrid = 0; /* cloned thread need to reset this */

	}

	l4x_arch_task_setup(t);
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
		thread_struct_to_utcb(t, l4x_utcb_get(l4_myself()),
		                      L4_UTCB_EXCEPTION_REGS_SIZE);

		per_cpu(l4x_current_proc_run, smp_processor_id()) = current_thread_info();

		/*
		 * Actually we could use l4_ipc_call here but for our
		 * (asynchronous) hybrid apps we need to do an open wait.
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

			if (src_id.id.task == l4x_kernel_taskno)
				goto only_receive_IPC;

			l4x_hybrid_return(src_id, l4x_utcb_get(l4_myself()),
			                  data0, data1, tag);

			goto only_receive_IPC;
		}

		// copy utcb now that we have made sure to have received
		// from t
		utcb_to_thread_struct(l4x_utcb_get(l4_myself()), t);
	} /* endless loop */

	enter_kdebug("end of dispatch loop!?");
	l4x_deliver_signal(13, 0);
} /* l4x_user_dispatcher */
