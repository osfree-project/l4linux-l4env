#ifndef __ASM_L4__GENERIC__DISPATCH_H__
#define __ASM_L4__GENERIC__DISPATCH_H__

#include <linux/linkage.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/thread_info.h>

void l4x_idle(void);
void l4x_suspend_user(struct task_struct *p, int cpu);
void l4x_wakeup_idler(int cpu);
void l4x_setup_user_dispatcher_after_fork(struct task_struct *p);
asmlinkage void l4x_user_dispatcher(void);

int l4_kernelinternal_execve(char * file, char ** argv, char ** envp);

#ifdef CONFIG_L4_DEBUG_SEGFAULTS
void l4x_print_vm_area_maps(struct task_struct *p);
#endif

DECLARE_PER_CPU(struct thread_info *, l4x_current_proc_run);
DECLARE_PER_CPU(int, l4x_idle_running);

extern unsigned l4x_fiasco_nr_of_syscalls;

#endif /* ! __ASM_L4__GENERIC__DISPATCH_H__ */
