/*
 *
 * Implementation of the API defined in asm/l4lxapi/task.h
 * for l4env.
 *
 * $Id: task.c,v 1.5 2003/05/23 20:06:41 adam Exp $
 *
 */

#include <linux/kernel.h>
#include <linux/spinlock.h>

#include <asm/l4lxapi/task.h>
#include <asm/l4lxapi/generic/task_gen.h>
#include <asm/l4lxapi/thread.h>

#include <asm/api/config.h>
#include <asm/api/ids.h>
#include <asm/api/macros.h>

#include <l4/names/libnames.h>
#include <l4/generic_ts/generic_ts.h>
#include <l4/sys/kdebug.h>
#include <l4/sys/syscalls.h>

#include <asm/generic/kthreads.h>

/* We need to store the state of threads within address spaces. Coming up
 * with a sane data structure would be good... */
/* 4 * 4 * 8 == 128 == 2^7 threads per task for v2 */
#define THREAD_ARRAY_SIZE 4
#define THREAD_ARRAY_BITS 128
struct l4lx_task_state_task_struct {
	unsigned int  task;
	unsigned long thread_array[THREAD_ARRAY_SIZE];
};

/* The size is arbitrary, needs to be dynamic... */
#define NR_STATE_TASKS 10
static struct l4lx_task_state_task_struct thread_state[NR_STATE_TASKS];

static DEFINE_SPINLOCK(thread_state_lock);

void l4lx_task_init(void)
{
	if (!l4ts_connected())
		panic("Could not connect to task server!");
}

/*
 * Return true if the thread_area of a task is empty.
 *
 * idx has to be >= 0
 */
static inline int l4lx_task_thread_empty(unsigned int idx)
{
	return find_first_bit(thread_state[idx].thread_array, THREAD_ARRAY_BITS)
	         >= THREAD_ARRAY_BITS;
}


l4_threadid_t l4lx_task_number_allocate(void)
{
	l4_threadid_t task;

	if (l4ts_allocate_task2(0, &task))
		return L4_NIL_ID;

	return task;
}

/*
 * Returns index in thread_state for a task and -1 if it couldn't
 * be found.
 * thread_state needs to be locked already.
 */
static inline int get_idx(unsigned int taskno)
{
	unsigned int i;

	for (i = 0; i < NR_STATE_TASKS; i++)
		if (thread_state[i].task == taskno)
			return i;

	return -1;
}

/*
 * Get free entry from thread_state and initialize it.
 * thread_state needs to be locked already.
 */
static inline int get_free_idx(unsigned int taskno)
{
	unsigned int i;

	for (i = 0; i < NR_STATE_TASKS; i++)
		if (thread_state[i].task == 0) {
			set_bit(0, thread_state[i].thread_array);
			thread_state[i].task = taskno;
			return i;
		}

	return -1;
}

static l4_threadid_t l4lx_task_number_thread_get(l4_threadid_t parent)
{
	int idx, t;
	l4_threadid_t ret = L4_INVALID_ID;

	spin_lock(&thread_state_lock);

	if ((idx = get_idx(l4x_get_taskno(parent))) == -1)
		if ((idx = get_free_idx(l4x_get_taskno(parent))) == -1)
			goto out;

	t = find_first_zero_bit(thread_state[idx].thread_array,
	                        THREAD_ARRAY_BITS);
	if (t >= THREAD_ARRAY_BITS)
		goto out;

	set_bit(t, thread_state[idx].thread_array);

	ret            = parent;
	ret.id.lthread = t;
out:
	spin_unlock(&thread_state_lock);
	return ret;
}

int l4lx_task_number_free(l4_threadid_t task)
{
	int idx;

	spin_lock(&thread_state_lock);

	idx = get_idx(l4x_get_taskno(task));

	spin_unlock(&thread_state_lock);

	/* Delete task if all threads are gone */
	if (idx == -1 && l4ts_free2_task(&task))
		return -1;

	return 0;
}

int l4lx_task_get_new_task(l4_threadid_t parent_id,
                           l4_threadid_t *id)
{
	/*
	 * If the first task is full of threads we should use all threads
	 * of the seconds (and more) as well instead of creating new tasks.
	 *
	 * But this all causes so much pain (i.e. v2)... :(
	 */
	if (!l4_is_nil_id(parent_id)) {
		/* New thread with one existing address space */
		*id = l4lx_task_number_thread_get(parent_id);
		if (l4_is_invalid_id(*id))
			goto task_only;
	} else {
task_only:
		/* New address space */
		*id = l4lx_task_number_allocate();
		if (l4_is_nil_id(*id))
			return -1;
	}

	return 0;
}

/*
 * Set prio of a thread.
 *
 * This is quite dependent to v2, move it elsewhere.
 */
static void l4lx_task_prio_set(l4_threadid_t dest, unsigned prio)
{
	l4_sched_param_t p;
	l4_threadid_t dummy = L4_INVALID_ID;

	l4_thread_schedule(dest, L4_INVALID_SCHED_PARAM, &dummy, &dummy, &p);

	if (!l4_is_invalid_sched_param(p)) {
		p.sp.prio  = prio;
		p.sp.state = 0;
		l4_thread_schedule(dest, p, &dummy, &dummy, &p);
		if (!l4_is_invalid_sched_param(p))
			return;
	}

	printk("Could not set prio of " PRINTF_L4TASK_FORM "\n",
	       PRINTF_L4TASK_ARG(dest));
}

int l4lx_task_create_pager(l4_threadid_t dest, l4_threadid_t pager)
{
	int idx;

	idx = get_idx(l4x_get_taskno(dest));

	if (idx == -1 || l4lx_task_thread_empty(idx)
	    || dest.id.lthread == 0) {
		/* Create new address space */
#ifdef CONFIG_L4_USE_TS
		return !l4ts_create_task(&dest, 0, 0,
		                         L4_TASK_NEW_ALIEN
		                          | L4_TASK_NEW_RAISE_EXCEPTION,
		                         &pager, CONFIG_L4_PRIO_SERVER_PROC,
		                         "L4Linux task", 0);
#else
		l4_threadid_t n;
		n = l4_task_new(dest,
		                L4_TASK_NEW_ALIEN | L4_TASK_NEW_RAISE_EXCEPTION,
		                0, 0,
		                pager);

		if (n.raw != dest.raw)
			return 0;
		l4lx_task_prio_set(dest, CONFIG_L4_PRIO_SERVER_PROC);
#endif
	} else {
		/* Start new thread within existing address space */
		l4_umword_t o;
		l4_threadid_t invid = L4_INVALID_ID;

		l4_thread_ex_regs_sc
		  (l4_thread_ex_regs_reg0(dest.id.lthread,
		                          dest.id.task,
		                          L4_THREAD_EX_REGS_ALIEN
		                          | L4_THREAD_EX_REGS_RAISE_EXCEPTION),
		   0x54, 0x78, &invid, &pager, &o, &o, &o);

		l4lx_task_prio_set(dest, CONFIG_L4_PRIO_SERVER_PROC);
	}

	return 1;
}

int l4lx_task_delete(l4_threadid_t task, unsigned option)
{
	int idx;

	spin_lock(&thread_state_lock);

	idx = get_idx(l4x_get_taskno(task));

	if (idx >= 0 && !test_and_clear_bit(task.id.lthread,
		                            thread_state[idx].thread_array)) {
		printk("thread: " PRINTF_L4TASK_FORM " idx=%d\n",
		       PRINTF_L4TASK_ARG(task), idx);
		enter_kdebug("Freeing nonexisting thread");
		return 0;
	}

	if (idx == -1 || l4lx_task_thread_empty(idx)) {
#ifdef CONFIG_L4_USE_TS
		int kill_flags = L4TS_KILL_SYNC;
#else
		l4_threadid_t r;
#endif

		if (idx >= 0)
			thread_state[idx].task = 0;
		spin_unlock(&thread_state_lock);
#ifdef CONFIG_L4_USE_TS
		if (!option)
			kill_flags |= L4TS_KILL_NOEV;
		return !l4ts_kill_task(task, kill_flags);
#else
		r = l4_task_new(task, l4_myself().raw, 0, 0, L4_NIL_ID);
		if (l4_is_nil_id(r))
			return 0;
		return L4LX_TASK_DELETE_SPACE;
#endif
	}

	spin_unlock(&thread_state_lock);
	return L4LX_TASK_DELETE_THREAD;
}

