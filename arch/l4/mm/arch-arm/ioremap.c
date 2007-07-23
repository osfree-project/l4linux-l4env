#include <linux/module.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/sizes.h>

#include <asm/generic/io.h>

#define __ARCH_IOREMAP_C_INCLUDED__
#include "../io.c"

void __check_kvm_seq(struct mm_struct *mm)
{
}

/*
 * Remap an arbitrary physical address space into the kernel virtual
 * address space. Needed when the kernel wants to access high addresses
 * directly.
 *
 * NOTE! We need to allow non-page-aligned mappings too: we will obviously
 * have to convert them into an offset in a page-aligned mapping, but the
 * caller shouldn't need to know that small detail.
 *
 * 'flags' are the extra L_PTE_ flags that you want to specify for this
 * mapping.  See include/asm-arm/proc-armv/pgtable.h for more information.
 */


void __iomem *
__ioremap(unsigned long phys_addr, size_t size, unsigned long flags)
{
	return __l4x_ioremap(phys_addr, size, flags);
}
EXPORT_SYMBOL(__ioremap);

void __iounmap(volatile void __iomem *addr)
{
	l4x_iounmap(addr);
}
EXPORT_SYMBOL(__iounmap);
