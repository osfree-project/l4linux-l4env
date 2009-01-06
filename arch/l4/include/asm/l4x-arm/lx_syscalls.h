#ifndef __ASM_L4__L4X__I386__LX_SYSCALLS_H__
#define __ASM_L4__L4X__I386__LX_SYSCALLS_H__

typedef asmlinkage int (*syscall_t)(long a0,...);
extern syscall_t sys_call_table[];

static inline int is_lx_syscall(int nr)
{
	extern char NR_syscalls[];
	return nr < (unsigned long)NR_syscalls;
}

#endif /* ! __ASM_L4__L4X__I386__LX_SYSCALLS_H__ */
