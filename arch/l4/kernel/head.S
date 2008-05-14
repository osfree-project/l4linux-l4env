/*
 *  This file is questionable as we also could define these memory areas
 *  in C files, on the other hand this "asm" code looks very portable...
 */
#include <linux/linkage.h>

#ifdef ARCH_x86
.section ".text"
	mov 0(%esi), %edi
	mov %edi, __l4_external_resolver
	mov $l4sys_utcb_get, %edi
	mov %edi, 4(%esi)
	jmp main
.previous
.section ".bss.page_aligned","w"
ENTRY(swapper_pg_dir)
	.fill 1024,4,0
ENTRY(empty_zero_page)
	.fill 4096,1,0
.previous
#endif

#ifdef ARCH_arm
.section .data.head, "wa"
.p2align 12
ENTRY(swapper_pg_dir)
	.fill 4096,4,0
#endif
