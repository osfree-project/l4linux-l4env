#ifndef __ASM_L4__GENERIC__UPAGE_H__
#define __ASM_L4__GENERIC__UPAGE_H__

#include <linux/compiler.h>

#include <asm/api/config.h>

int l4x_peek_upage(unsigned long addr, unsigned long __user *datap, int *ret);

extern void _upage_start;
extern void _upage_end;


#endif /* ! __ASM_L4__GENERIC__UPAGE_H__ */
