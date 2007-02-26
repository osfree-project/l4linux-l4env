#ifndef __ASM_L4__ARCH_I386__FIXMAP_H__
#define __ASM_L4__ARCH_I386__FIXMAP_H__

#include <asm-i386/fixmap.h>

#include <asm/generic/upage.h>

/*
 * Have a slightly other version of fix_to_virt, leave everything in place
 * except intercept VDSO conversions.
 */
static inline unsigned long __l4x__fix_to_virt(const unsigned int x)
{
	if (x == FIX_VDSO)
		return (unsigned long)&_upage_start;

	/* Original __fix_to_virt macro code */
	return (FIXADDR_TOP - ((x) << PAGE_SHIFT));
}

#undef __fix_to_virt
#define __fix_to_virt(x) __l4x__fix_to_virt(x)

#endif /* ! __ASM_L4__ARCH_I386__FIXMAP_H__ */