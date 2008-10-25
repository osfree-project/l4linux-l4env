/*
 *  linux/include/asm-l4/arch-arm/arch/irqs.h
 */
#ifndef __ASM_L4__ARCH_ARM__ARCH__IRQS_H__
#define __ASM_L4__ARCH_ARM__ARCH__IRQS_H__

#define NR_IRQS		100
#define NR_IRQS_HW	96

#define L4X_IRQ_CONS    99

#ifdef CONFIG_L4_ARM_PLATFORM_ISG
#include <asm/arch/irqs_isg.h>
#endif

#endif /* ! __ASM_L4__ARCH_ARM__ARCH__IRQS_H__ */
