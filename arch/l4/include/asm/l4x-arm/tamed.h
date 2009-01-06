/*
 * Architecture specific handling for tamed mode for ARM.
 */
#ifndef __ASM_L4__L4X_ARM__TAMED_H__
#define __ASM_L4__L4X_ARM__TAMED_H__

#ifndef L4X_TAMED_LABEL
#error Only use from within tamed.c!
#endif

/* Do not use atomic.h functions here as they use the locking we try to
 * implement first here. */
static inline int l4x_atomic_inc(volatile long int *val)
{
	return l4_atomic_add(val, 1);
}

static inline int l4x_atomic_dec(volatile long int *val)
{
	return l4_atomic_add(val, -1);
}

static inline void l4x_tamed_sem_down(void)
{
	l4_umword_t d0, d1;
	l4_msgdope_t result;
	int error;

	while (1) {
		if (likely(l4x_atomic_dec(&tamed_per_nr(cli_lock,
		                          get_tamer_nr(smp_processor_id())).sem.counter)
		           >= 0))
			break;
#ifdef CONFIG_L4_DEBUG_TAMED_COUNT_INTERRUPT_DISABLE
		cli_taken++;
#endif
		error = l4_ipc_call(tamed_per_nr(cli_sem_thread_id,
		                                 get_tamer_nr(smp_processor_id())),
		                    L4_IPC_SHORT_MSG,
		                    1 /* L4SEMAPHORE_BLOCK */,
		                    l4x_stack_prio_get(),
		                    L4_IPC_SHORT_MSG, &d0, &d1,
		                    L4_IPC_NEVER, &result);
		if (unlikely(error)) {
			outstring("l4x_tamed_sem_down ipc failed: ");
			outhex32(error);
			outstring("\n");
		}
		if (d0 == 1)
			break;
	}
}


static inline void l4x_tamed_sem_up(void)
{
	l4_umword_t d;
	l4_msgdope_t result;
	int error;

	if (unlikely(l4x_atomic_inc(&tamed_per_nr(cli_lock,
	                            get_tamer_nr(smp_processor_id())).sem.counter)
	             <= 0))
		if ((error = l4_ipc_call(tamed_per_nr(cli_sem_thread_id,
		                                      get_tamer_nr(smp_processor_id())),
		                L4_IPC_SHORT_MSG,
		                2 /* L4SEMAPHORE_RELEASE */,
		                l4x_stack_prio_get(),
		                L4_IPC_SHORT_MSG, &d, &d,
		                L4_IPC_NEVER, &result))) {
			outstring("l4x_tamed_sem_up ipc failed: ");
			outhex32(error);
			outstring("\n");
		}
}
#endif /* ! __ASM_L4__L4X_ARM__TAMED_H__ */
