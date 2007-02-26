/*
 * linux/include/asm-l4/arch-arm/arch/system.h
 */
#ifndef __ASM_L4__ARCH_ARM__ARCH__SYSTEM_H__
#define __ASM_L4__ARCH_ARM__ARCH__SYSTEM_H__

#include <linux/kernel.h>

static inline void arch_idle(void)
{
	cpu_do_idle();
}

static inline void arch_reset(char mode)
{
	printk("%s called.", __func__);
}
#endif /* ! __ASM_L4__ARCH_ARM__ARCH__SYSTEM_H__ */
