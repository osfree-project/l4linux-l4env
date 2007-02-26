	/* Must be on a separate page to be mapped */
	.p2align 12
	.globl _upage_start, _upage_end
_upage_start:
	.incbin "arch/l4/kernel/arch-i386/upage.so"
_upage_end:
	.p2align 12
