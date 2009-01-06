#ifndef __ASM_L4__L4X_ARM__SYSCALL_H__
#define __ASM_L4__L4X_ARM__SYSCALL_H__

/*
 * Return syscall nr, or -1 if process is not on a syscall.
 */
static inline int l4x_l4syscall_get_nr(unsigned long error_code,
                                       unsigned long ip)
{
	int syscall_nr = 0;
	unsigned long val = ~ip;

	if (val < 0x8
	    || val >= (l4x_fiasco_nr_of_syscalls * 4 + 8)
	    || ((val + 1) % 4))
		return -1;

	syscall_nr = (val >> 2) - 2;

	return syscall_nr;
}

#endif /* ! __ASM_L4__L4X_ARM__SYSCALL_H__ */
