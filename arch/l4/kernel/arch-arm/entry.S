
#include <linux/linkage.h>

	.global NR_syscalls
	.equ NR_syscalls,0
#define CALL(x) .equ NR_syscalls,NR_syscalls+1
#include "calls.S"
#undef CALL
#define CALL(x) .long x


#define ABI(native, compat) native
#define OBSOLETE(syscall) syscall

.type   sys_call_table, #object
ENTRY(sys_call_table)
#include "calls.S"
#undef ABI
#undef OBSOLETE

sys_mmap2:
	b	do_mmap2

/* ---- */
sys_fork_wrapper:
	b	sys_fork

sys_execve_wrapper:
	b	sys_execve

sys_vfork_wrapper:
	b	sys_vfork

sys_clone_wrapper:
	b	sys_clone

sys_sigaltstack_wrapper:
	b	do_sigaltstack

sys_fstatfs64_wrapper:
	b	sys_fstatfs64

sys_statfs64_wrapper:
	b	sys_statfs64
