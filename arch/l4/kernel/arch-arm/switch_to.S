#include <linux/linkage.h>

#include <asm/asm-offsets.h>

ENTRY(__switch_to)
                add     ip, r1, #TI_CPU_SAVE
		add	r2, r2, #TI_CPU_SAVE
                stmia   ip!, {r4 - sl, fp, sp, lr}      @ Store most regs on stack
                ldmia   r2, {r4 - sl, fp, sp, pc}       @ Load all regs saved previously
