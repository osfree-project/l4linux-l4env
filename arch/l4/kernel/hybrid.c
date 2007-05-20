/*
 * Some code for handling hybrid tasks.
 */

/*
 * Hybrid tasks come in asynchronous, so we have to map from an L4 ID to a
 * struct task_struct pointer.
 */

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <asm/generic/hybrid.h>
#include <asm/generic/upage.h>
#include <asm/api/macros.h>

#include <l4/sys/kdebug.h>
#include <l4/sys/syscalls.h>

struct l4x_hybrid_list_task {
	struct list_head list;         /* List of tasks */
	struct list_head threads;      /* List of threads in a task */
	l4_threadid_t id;              /* Task ID and first thread (=0) */
	struct task_struct *task;      /* task_struct of thread-0 */
};

struct l4x_hybrid_list_thread {
	struct list_head list;         /* List of threads */
	l4_threadid_t id;              /* Thread ID of thread */
	struct task_struct *task;      /* Corresponding task struct */
};

static struct l4x_hybrid_list_task l4x_hybrid_list_head = {
	.list    = LIST_HEAD_INIT(l4x_hybrid_list_head.list),
};

static DEFINE_SPINLOCK(list_lock);

static struct l4x_hybrid_list_task *task_get(l4_threadid_t id)
{
	struct l4x_hybrid_list_task *e;

	list_for_each_entry(e, &l4x_hybrid_list_head.list, list)
		if (e->id.id.task == id.id.task)
			return e;

	return NULL;
}

static inline struct l4x_hybrid_list_thread *thread_get(l4_threadid_t id,
                                                        struct l4x_hybrid_list_task *n)
{
	struct l4x_hybrid_list_thread *e;

	list_for_each_entry(e, &n->threads, list)
		if (e->id.id.lthread == id.id.lthread)
			return e;

	return NULL;
}

/*
 * Add a new entry.
 *
 * \param id     id to add
 * \param task   task structure to add
 */
void l4x_hybrid_list_add(l4_threadid_t id, struct task_struct *task)
{
	struct l4x_hybrid_list_task *n;

	spin_lock(&list_lock);

	n = task_get(id);

	if (!n) {
		/* Allocate new node if node for id does not exist yet */
		n = kmalloc(sizeof(*n), GFP_KERNEL);
		BUG_ON(!n);

		n->task          = NULL;
		n->id            = id;
		n->id.id.lthread = 0;

		INIT_LIST_HEAD(&n->threads);
		list_add_tail(&n->list, &l4x_hybrid_list_head.list);
	}

	if (likely(!id.id.lthread)) {
		/* Set node data */
		n->id   = id;
		n->task = task;

	} else {
		/* New thread within existing task */
		struct l4x_hybrid_list_thread *t;

		t = thread_get(id, n);

		if (!t) {
			t = kmalloc(sizeof(*t), GFP_KERNEL);
			BUG_ON(!t);
		}
		t->id   = id;
		t->task = task;

		list_add_tail(&t->list, &n->threads);
	}

	spin_unlock(&list_lock);
}

/*
 * Query a task structure by id.
 *
 * \param id    id to query
 *
 * \return task structure for id, NULL if not found
 */
struct task_struct *l4x_hybrid_list_get(l4_threadid_t id)
{
	struct l4x_hybrid_list_task *n;
	struct l4x_hybrid_list_thread *t;
	struct task_struct *ret = NULL;

	spin_lock(&list_lock);

	if (!(n = task_get(id)))
		goto out;

	if (id.id.lthread == 0) {
		ret = n->task;
		goto out;
	}

	if ((t = thread_get(id, n))) {
		ret = t->task;
		goto out;
	}

out:
	spin_unlock(&list_lock);
	return ret;
}

/*
 * Query whether a task exists.
 *
 * \param id   id to query
 *
 * \return 1 if id exists in list, 0 if id does not exist in list
 */
int l4x_hybrid_list_task_exists(l4_threadid_t id)
{
	int ret;

	spin_lock(&list_lock);
	ret = !!task_get(id);
	spin_unlock(&list_lock);

	return ret;
}

/*
 * Remove a whole node including all threads.
 *
 * \param  id  id to delete
 *
 * \return 1 if node was deleted
 *         0 if id wasn't found in the list
 */
int l4x_hybrid_list_task_remove(l4_threadid_t id)
{
	struct l4x_hybrid_list_task *n;
	struct l4x_hybrid_list_thread *t, *ntmp;

	spin_lock(&list_lock);

	if (!(n = task_get(id))) {
		spin_unlock(&list_lock);
		return 0;
	}

	/* Remove thread entries */
	list_for_each_entry_safe(t, ntmp, &n->threads, list) {
		list_del(&t->list);
		kfree(t);
	}

	/* Remove task node */
	list_del(&n->list);
	kfree(n);

	spin_unlock(&list_lock);
	return 1;
}

/*
 * Remove a single thread from a specific task. The node itself is preserved
 * if there's no entry left.
 *
 * \param  id    id to delete
 *
 * \return 1 if something was found and deleted,
 *         0 if id was not found (and nothing was deleted from the list)
 */
int l4x_hybrid_list_thread_remove(l4_threadid_t id)
{
	struct l4x_hybrid_list_task *n;
	struct l4x_hybrid_list_thread *t;
	int ret = 0;

	spin_lock(&list_lock);

	if (!(n = task_get(id)))
		goto out;

	/* 'Remove' thread-0? */
	if (!id.id.lthread && n->task) {
		n->task = NULL;
		ret = 1;
		goto out;
	}

	/* Go look for other threads */
	list_for_each_entry(t, &n->threads, list)
		if (id.id.lthread == t->id.id.lthread) {
			list_del(&t->list);
			kfree(t);
			ret = 1;
			goto out;
		}

out:
	spin_unlock(&list_lock);
	return ret;
}

/*
 * seq_file debugging
 */
int l4x_hybrid_list_seq_show(struct seq_file *m, void *v)
{
	struct l4x_hybrid_list_task *n;
	struct l4x_hybrid_list_thread *t;

	spin_lock(&list_lock);

	list_for_each_entry(n, &l4x_hybrid_list_head.list, list) {
		int empty = !n->task;
		if (n->task)
			seq_printf(m, PRINTF_L4TASK_FORM ": %5d (%s)\n",
				   PRINTF_L4TASK_ARG(n->id),
				   n->task->pid, n->task->comm);

		list_for_each_entry(t, &n->threads, list) {
			seq_printf(m, PRINTF_L4TASK_FORM ": %5d (%s)\n",
				   PRINTF_L4TASK_ARG(t->id),
				   t->task->pid, t->task->comm);
			empty = 0;
		}
		if (empty)
			seq_printf(m, "%02x   : empty\n", t->id.id.task);
	}

	spin_unlock(&list_lock);
	return 0;
}

/* -------------------------------------------- */

static void l4x_hybrid_wakeup_task(struct task_struct *p)
{
	l4_threadid_t pager_id = L4_INVALID_ID, preempter_id = L4_INVALID_ID;
	l4_umword_t dummy;

	l4_inter_task_ex_regs(p->thread.user_thread_id, ~0UL, ~0UL,
	                      &preempter_id, &pager_id,
	                      &dummy, &dummy, &dummy,
	                      L4_THREAD_EX_REGS_ALIEN
	                       | L4_THREAD_EX_REGS_RAISE_EXCEPTION);
}

/* Only works for the first 32/64 sigs because of the usage of
 * sigtestsetmask but this is ok for our usage with only
 * SIGINT, SIGTERM and SIGKILL */
static const unsigned long sigs_for_interrupt
	= sigmask(SIGINT) | sigmask(SIGTERM) | sigmask(SIGKILL);

static inline void l4x_hybrid_check_task(struct task_struct *p)
{
	if (p && signal_pending(p) && p->thread.hybrid_sc_in_prog
	    && (sigtestsetmask(&p->pending.signal, sigs_for_interrupt)
		|| sigtestsetmask(&p->signal->shared_pending.signal,
		                  sigs_for_interrupt)))
		l4x_hybrid_wakeup_task(p);
}

/*
 * Scan through all hybrid threads and wake any up that have a signal
 * pending.
 */
void l4x_hybrid_scan_signals(void)
{
	struct l4x_hybrid_list_task *n;
	struct l4x_hybrid_list_thread *t;

	spin_lock(&list_lock);

	list_for_each_entry(n, &l4x_hybrid_list_head.list, list) {
		l4x_hybrid_check_task(n->task);
		list_for_each_entry(t, &n->threads, list)
			l4x_hybrid_check_task(t->task);
	}

	spin_unlock(&list_lock);
}
