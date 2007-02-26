/*
 *  linux/arch/l4/kernel/arch-i386/entry.S
 */

#include <linux/linkage.h>

.section .rodata,"a"
#include "syscall_table.S"

syscall_table_size=(.-sys_call_table)
.globl nr_syscalls
nr_syscalls=(.-sys_call_table)/4
