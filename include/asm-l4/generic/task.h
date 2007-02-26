#ifndef __ASM_L4__GENERIC__TASK_H__
#define __ASM_L4__GENERIC__TASK_H__

#include <linux/sched.h>
#include <linux/seq_file.h>

#include <l4/sys/types.h>

#include <asm/api/config.h>

/* Send SIGKILL to current */
void l4x_sig_current_kill(void);

#ifdef CONFIG_SMP
#warning l4x_idle_task(cpu) not SMP aware I guess
#endif
#define l4x_idle_task(cpu) (&init_task)

extern struct task_struct *l4x_current_process;

#endif /* ! __ASM_L4__GENERIC__TASK_H__ */
