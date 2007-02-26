#ifndef __ASM_L4__GENERIC__SYSCALL_GUARD_H__
#define __ASM_L4__GENERIC__SYSCALL_GUARD_H__

int l4x_syscall_guard(struct task_struct *p, l4_utcb_t *utcb, int sysnr);

#endif /* ! __ASM_L4__GENERIC__SYSCALL_GUARD_H__ */
