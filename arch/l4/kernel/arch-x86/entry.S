/*
 *  linux/arch/l4/kernel/arch-i386/entry.S
 */

#include <linux/linkage.h>

.section .rodata,"a"
#include "syscall_table_32.S"

syscall_table_size=(.-sys_call_table)
.globl nr_syscalls
nr_syscalls=(.-sys_call_table)/4


#ifdef CONFIG_SMP
#include <asm/thread_info.h>
.data
ENTRY(stack_start)
	.long init_thread_union+THREAD_SIZE
	.long 0

.align 4
ENTRY(initial_code)
	.long 0

.previous
#endif
