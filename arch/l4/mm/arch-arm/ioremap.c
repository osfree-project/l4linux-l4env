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

/*
 * Used by ioremap() and iounmap() code to mark (super)section-mapped
 * I/O regions in vm_struct->flags field.
 */
#define VM_ARM_SECTION_MAPPING	0x80000000

#include <asm/generic/memory.h>

#include <l4/sys/kdebug.h>
#include <l4/l4rm/l4rm.h>


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
	l4_addr_t virt_addr;
	l4_uint32_t rg;
	int error;

	size = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

	if ((error = l4rm_area_reserve(size, L4RM_LOG2_ALIGNED,
	                               &virt_addr, &rg)))
		goto fail_reserve;

	if (l4x_map_iomemory_from_sigma0(phys_addr, virt_addr, size))
		goto fail_map;

	return (void *)virt_addr;

fail_map:
	if (l4rm_area_release_addr((void *)virt_addr))
		printk("%s: l4rm_area_release_addr failed\n", __func__);
fail_reserve:
	return NULL;
}
EXPORT_SYMBOL(__ioremap);

void __iounmap(volatile void __iomem *addr)
{
	printk("__iounmap: unimplemented\n");
}
EXPORT_SYMBOL(__iounmap);

unsigned long find_ioremap_entry(unsigned long phys_addr)
{
	return 0;
}
