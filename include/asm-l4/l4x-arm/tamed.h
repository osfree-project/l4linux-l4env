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

	while (1) {
		if (likely(l4x_atomic_dec(&cli_lock.sem.counter) >= 0))
			break;
#ifdef CONFIG_L4_DEBUG_TAMED_COUNT_INTERRUPT_DISABLE
		cli_taken++;
#endif
		if (l4_ipc_call(cli_sem_thread_id, L4_IPC_SHORT_MSG,
		                1 /* L4SEMAPHORE_BLOCK */,
		                l4x_stack_prio_get(),
				L4_IPC_SHORT_MSG, &d0, &d1,
		                L4_IPC_NEVER, &result))
			outstring("l4x_tamed_sem_down ipc failed\n");
		if (d0 == 1)
			break;
	}
}


static inline void l4x_tamed_sem_up(void)
{
	l4_umword_t d;
	l4_msgdope_t result;

	if (unlikely(l4x_atomic_inc(&cli_lock.sem.counter) <= 0))
		if (l4_ipc_call(cli_sem_thread_id, L4_IPC_SHORT_MSG,
		                2 /* L4SEMAPHORE_RELEASE */,
		                l4x_stack_prio_get(),
				L4_IPC_SHORT_MSG, &d, &d,
		                L4_IPC_NEVER, &result))
			outstring("l4x_tamed_sem_up ipc failed\n");
}
#endif /* ! __ASM_L4__L4X_ARM__TAMED_H__ */
