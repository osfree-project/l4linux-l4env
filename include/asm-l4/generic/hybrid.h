/*
 * Header file for hybrid functions.
 */
#ifndef __ASM_L4__GENERIC__HYBRID_H__
#define __ASM_L4__GENERIC__HYBRID_H__

#include <linux/sched.h>
#include <linux/seq_file.h>

#include <l4/sys/types.h>

void                l4x_hybrid_list_add(l4_threadid_t id, struct task_struct *p);
struct task_struct *l4x_hybrid_list_get(l4_threadid_t id);
int                 l4x_hybrid_list_task_exists(l4_threadid_t id);
int                 l4x_hybrid_list_task_remove(l4_threadid_t id);
int                 l4x_hybrid_list_thread_remove(l4_threadid_t id);
int                 l4x_hybrid_list_seq_show(struct seq_file *m, void *v);

void                l4x_hybrid_scan_signals(void);

static inline void l4x_hybrid_do_regular_work(void)
{
	l4x_hybrid_scan_signals();
}

#endif /* ! __ASM_L4__GENERIC__HYBRID_H__ */
