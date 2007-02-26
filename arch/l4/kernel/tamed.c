/*
 * Interrupt disable/enable implemented with a queue
 *
 * For deadlock reasons this file must _not_ use any Linux functionality!
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/stddef.h>

#include <l4/sys/syscalls.h>
#include <l4/sys/ipc.h>
#include <l4/sys/kdebug.h>
#include <l4/util/atomic.h>

#include <asm/l4lxapi/thread.h>
#include <asm/generic/stack_id.h>
#include <asm/generic/setup.h>
#include <asm/generic/tamed.h>

#ifdef CONFIG_L4_FERRET_TAMER_ATOMIC
#include <l4/ferret/sensors/list_producer_wrap.h>
#include <asm/generic/ferret.h>

#define FERRET_EVENT(m) ferret_list_post_1t(l4x_ferret_kernel,    \
                                            FERRET_L4LX_MAJOR, m, \
                                            0, __myself)
#else
#define FERRET_EVENT(m) do { } while (0)
#endif /* CONFIG_L4_FERRET_TAMER_ATOMIC */

#define L4X_TAMED_LABEL

#define MAX_WQ_ENTRIES	64

typedef struct _sem_wq {
	l4_threadid_t   thread;
	unsigned        prio;
	struct _sem_wq  *next;
} sem_wq_t;

typedef struct _cli_sem {
	volatile long counter;
	sem_wq_t      *queue;
} cli_sem_t;

typedef struct _cli_lock {
	cli_sem_t              sem;
	volatile l4_threadid_t owner;
} cli_lock_t;

static sem_wq_t wq_entries[MAX_WQ_ENTRIES];
static int      wq_len = 0;  /* track wait queue length here */
static int next_entry = 0;
static l4_threadid_t cli_sem_thread_id = L4_INVALID_ID;
static cli_lock_t cli_lock = { { 1, NULL } , L4_INVALID_ID };
static unsigned char stack_mem[2048];

#include <asm/l4x/tamed.h>

#ifdef CONFIG_L4_DEBUG_TAMED_COUNT_INTERRUPT_DISABLE
unsigned cli_sum;
unsigned cli_taken;
#endif

static inline sem_wq_t* __alloc_entry(void)
{
	int i = next_entry;

	/* find unused wait queue entry */
	do {
		if (l4_is_invalid_id(wq_entries[i].thread)) {
			next_entry = (i + 1) % MAX_WQ_ENTRIES;
			return wq_entries + i;
		}
		i = (i + 1) % MAX_WQ_ENTRIES;
	} while (i != next_entry);

	/* this cannot happen since we have only about 20 threads */
	enter_kdebug("no wait queue entry");
	return NULL;
}

static inline void __free_entry(sem_wq_t *wq)
{
	wq->thread = L4_INVALID_ID;
}

/* don't worry about priorities */
static inline void __enqueue_thread(l4_threadid_t t, unsigned prio)
{
	sem_wq_t *wq;

	/* insert thread into wait queue */
	wq = __alloc_entry();
	wq->thread = t;
	wq->prio = prio;
	wq->next = NULL;

	if (cli_lock.sem.queue == NULL)
		cli_lock.sem.queue = wq;
	else {
		wq->next = cli_lock.sem.queue;
		cli_lock.sem.queue = wq;
	}
	wq_len++;
}

static inline sem_wq_t* __prio_highest(void)
{
	sem_wq_t *wq_prio_highest = cli_lock.sem.queue;
	sem_wq_t *wp = wq_prio_highest->next;

	while (wp) {
		if (wp->prio > wq_prio_highest->prio)
			wq_prio_highest = wp;
		wp = wp->next;
	}

	return wq_prio_highest;
}

static inline void __wakeup_thread_without_switchto(l4_threadid_t t)
{
	int error;
	l4_msgdope_t result;

	error = l4_ipc_send(t,
	                    (void*)(L4_IPC_SHORT_MSG | L4_IPC_DECEIT), 0, 0,
	                    L4_IPC_SEND_TIMEOUT_0, &result);
	if (error)
		LOG_printf("cli thread: wakeup to %x.%02x failed (0x%02x)\n", 
		           t.id.task, t.id.lthread, error);
}

/** The main semaphore thread. We need this thread to ensure atomicity.
 * We assume that this thread is not preempted by any other thread.
 */
static void cli_sem_thread(void *data)
{
	l4_umword_t dw0;
	int i;
	int error;
	l4_umword_t operation, prio;
	l4_msgdope_t result;
	l4_threadid_t src;
#ifdef CONFIG_L4_FERRET_TAMER_ATOMIC
	l4_threadid_t __myself = l4_myself();
#endif

	(void)data;

	/* setup wait queue entry allocation */
	for (i = 0; i < MAX_WQ_ENTRIES; i++)
		__free_entry(wq_entries + i);

	/* semaphore thread loop */
no_reply:
	/* wait for request */
	error = l4_ipc_wait(&src,
	                    L4_IPC_SHORT_MSG, &operation, &prio,
	                    L4_IPC_NEVER, &result);
	for (;;) {
		if (unlikely(error)) {
			LOG_printf("cli thread: IPC error 0x%02x\n", error);
			goto no_reply;
		}

		if (unlikely(!l4_task_equal(cli_sem_thread_id, src))) {
			LOG_printf("cli thread: ignored request from other task "
			           "%x\n", src.id.task);
			goto no_reply;
		}

		FERRET_EVENT(FERRET_L4LX_ATOMIC_BEGIN);

		dw0 = 0;    /* return 0 in dw0 per default */
		switch (operation) {
			case 1:
				/* CLI (block thread, enqueue to semaphores wait queue) */
				/* Insert fancy explanation for this if: fixme MLP*/
				if (wq_len == -1 * cli_lock.sem.counter) {
					dw0 = 1;
					FERRET_EVENT(FERRET_L4LX_ATOMIC_END2);
					break;
				} else {
					__enqueue_thread(src, prio);
					FERRET_EVENT(FERRET_L4LX_ATOMIC_END1);
					goto no_reply;
				}
				break;

			case 2:
				/* STI */
				if (cli_lock.sem.queue) {
					/* wakeup all waiting threads and reply to the
					 * thread with the highest priority */
					sem_wq_t *wp, *wq_prio_highest;

					__enqueue_thread(src, prio);
					wq_prio_highest = __prio_highest();
					while ((wp = cli_lock.sem.queue)) {
						/* remove thread from wait queue */
						cli_lock.sem.queue = wp->next;
						if (wp != wq_prio_highest) {
							l4_threadid_t wakeup = wp->thread;
							l4util_atomic_inc(&cli_lock.sem.counter);
							wq_len--;
							__free_entry(wp);
							/* never switch to woken up thread since we have
							 * the higher priority (per definition) */
							__wakeup_thread_without_switchto(wakeup);
						}
					}

					src = wq_prio_highest->thread;
					wq_len--;
					__free_entry(wq_prio_highest);
				}
				break;

			default:
				LOG_printf("cli thread: invalid request\n");
		}
		FERRET_EVENT(FERRET_L4LX_ATOMIC_END2);
		error = l4_ipc_reply_and_wait(src, L4_IPC_SHORT_MSG, dw0, 0,
		                              &src, L4_IPC_SHORT_MSG, &operation, &prio,
		                              L4_IPC_SEND_TIMEOUT_0, &result);
	}
}

void l4x_global_cli(void)
{
	l4_threadid_t me = l4x_stack_id_get();

	if (unlikely(me.id.task != l4x_kernel_taskno)) {
		outhex32(me.id.task); outchar('.');
		outhex32(me.id.lthread); outchar('\n');
		me = l4_myself();
		outstring("failed CLI: ");
		outhex32(me.id.task); outchar('.');
		outhex32(me.id.lthread); outchar('\n');

		enter_kdebug("Unset id on stack (c)");
	}

#ifdef CONFIG_L4_DEBUG_TAMED_COUNT_INTERRUPT_DISABLE
	cli_sum++;
#endif
	if (l4_thread_equal(me, cli_lock.owner))
		/* we already are the owner of the lock */
		return;

	/* try to get the lock */
	l4x_tamed_sem_down();

	/* we have the lock */
	cli_lock.owner = me;
}
EXPORT_SYMBOL(l4x_global_cli);

void l4x_global_sti(void)
{
	l4_threadid_t me = l4x_stack_id_get();

	if (unlikely(me.id.task != l4x_kernel_taskno)) {
		outhex32(me.id.task); outhex32(me.id.lthread); outchar('\n');
		me = l4_myself();
		outstring("failed STI: ");
		outhex32(me.id.task); outchar('.'); outhex32(me.id.lthread);
		outchar('\n');

		enter_kdebug("Unset id on stack (s)");
	}

	if (!l4_thread_equal(me, cli_lock.owner)) {
		if (!l4_is_invalid_id(cli_lock.owner)) {
			LOG_printf("sti from %x.%02x but cli from %x.%02x\n",
			           me.id.task, me.id.lthread,
			           cli_lock.owner.id.task, cli_lock.owner.id.lthread);
			enter_kdebug("sti thread != cli thread");
		}
		return;
	}

	cli_lock.owner = L4_INVALID_ID;
	l4x_tamed_sem_up();
}
EXPORT_SYMBOL(l4x_global_sti);

unsigned long l4x_global_save_flags(void)
{
	return l4_thread_equal(cli_lock.owner,
	                       l4x_stack_id_get()) ? L4_IRQ_DISABLED : L4_IRQ_ENABLED;
}
EXPORT_SYMBOL(l4x_global_save_flags);

void l4x_global_restore_flags(unsigned long flags)
{
	switch (flags) {
		case L4_IRQ_ENABLED:
			l4x_global_sti();
			break;
		case L4_IRQ_DISABLED:
			l4x_global_cli();
			break;
		default:
			enter_kdebug("restore_flags wrong val");
	}
}
EXPORT_SYMBOL(l4x_global_restore_flags);

/** create our semaphore thread */
void l4x_tamed_init(void)
{
	/* the priority has to be higher than the prio of the omega0 server
	 * to ensure that the cli thread is not preempted! */
	/* Provide our own stack so that we do not need to use locking
	 * functions get one from l4lxlib */
	cli_sem_thread_id = l4lx_thread_create(cli_sem_thread,
	                                       stack_mem + sizeof(stack_mem),
	                                       NULL, 0,
	                                       0xa1, "tamer");

	LOG_printf("Using tamed mode.\n");
}

int l4x_tamed_print_cli_stats(char *buffer)
{
#ifdef CONFIG_L4_DEBUG_TAMED_COUNT_INTERRUPT_DISABLE
	return sprintf(buffer, "cli() called     : %u\n"
	                       "cli() contention : %u\n",
	                       cli_sum, cli_taken);
#else
	return sprintf(buffer, "<CONFIG_L4_CLI_DEBUG not enabled in config>\n");
#endif
}
