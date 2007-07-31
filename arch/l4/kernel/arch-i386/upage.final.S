	/* Must be on a separate page to be mapped */
	.p2align 12
	.globl vsyscall_int80_start, vsyscall_int80_end
	.globl vsyscall_sysenter_start, vsyscall_sysenter_end
	.globl _upage_start, _upage_end
vsyscall_int80_start:
vsyscall_sysenter_start:
_upage_start:
	.incbin "arch/l4/kernel/arch-i386/upage.so"
vsyscall_int80_end:
vsyscall_sysenter_end:
_upage_end:
	.globl SYSENTER_RETURN
SYSENTER_RETURN:
	ud2a
	.p2align 12
