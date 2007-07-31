#include <linux/mm.h>
#include <linux/spinlock.h>

#include <asm/system.h>
#include <asm/segment.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>

#include <asm/api/config.h>

#include <asm/generic/memory.h>
#include <asm/generic/task.h>
#include <asm/generic/vmalloc.h>
#include <asm/generic/ioremap.h>

#include <asm/l4lxapi/memory.h>

#include <l4/sys/syscalls.h>

/* #define DEBUG */
#define SANITY
/* #define DEBUG */
/* #define PARANOIA */

void l4x_flush_page(unsigned long address, int size, unsigned long options)
{
	/* some checks:
	 * options & ALL_SPACES:	address >= high_memory
	 * otherwise:			address < high_memory
	 * address > 0x80000000UL:	no flush operation
	 */
	if (options & L4_FP_ALL_SPACES) {
		/* unmap page in all spaces, only allowed for vm pages */
		if (address < (unsigned long)high_memory) {
			printk("trying to flush physical page (%lx) "
				    "from linux server", address);
			enter_kdebug("phys + all_spaces");
		}
	} else if (address > 0x80000000UL) {
		unsigned long remap;
		remap = find_ioremap_entry(address);

		/* VU: it may happen, that memory is not remapped but mapped in
		 * user space, if a task mmaps /dev/mem but never accesses it.
		 * Therefore, we fail silently...
		 */
		if (!remap)
			return;

		address = remap;

	} else if ((address & PAGE_MASK) == 0)
		address = PAGE0_PAGE_ADDRESS;

#if 0
	/* only for debugging */
	else {
		if ((address >= (unsigned long)high_memory)
		    && (address < 0x80000000UL)) {
			printk("flushing non physical page (0x%lx)\n",
				    address);
			enter_kdebug("flush_page: non physical page");
		}
	}
#endif

	/* do the real flush */
	l4_fpage_unmap(l4_fpage(address & PAGE_MASK, size, 0, 0), options);
}

#ifdef ARCH_arm
#define _PAGE_MAPPED L_PTE_MAPPED
#endif

#define check_pte_mapped(old, newval)				\
do {								\
       if (pte_mapped(old) && !pte_mapped(newval)) {		\
		printk("set_pte: old mapped, new one not\n");	\
		enter_kdebug("set_pte");			\
		newval = __pte(pte_val(newval) | _PAGE_MAPPED); \
       }							\
} while (0)


unsigned long fastcall l4x_set_pte(pte_t old, pte_t pteval)
{
	/*
	 * Check if any invalidation is necessary
	 *
	 * Invalidation (flush) necessary if:
	 *   old page was present
	 *       new page is not present OR
	 *       new page has another physical address OR
	 *       new page has another protection OR
	 *       new page has other access attributes
	 */

	/* old was present && new not -> flush */
	int flush = L4_FP_FLUSH_PAGE;
#if 0
	if ((pte_val(old) & PAGE_MASK) != (pte_val(pteval) & PAGE_MASK))
		printk("spte %x->%x\n", pte_val(old), pte_val(pteval));
#endif
	if (pte_present(pteval)) {
		/* new page is present,
		 * now we have to find out what has changed */
		if (((pte_val(old) ^ pte_val(pteval)) & PAGE_MASK)
		    || (pte_young(old) && !pte_young(pteval))) {
			/* physical page frame changed
			 * || access attribute changed -> flush */
			/* flush is the default */
			//pteval.pte_low &= ~_PAGE_MAPPED;
			pteval = __pte(pte_val(pteval) & ~_PAGE_MAPPED);

		} else if ((pte_write(old) && !pte_write(pteval))
		           || (pte_dirty(old) && !pte_dirty(pteval))) {
			/* Protection changed from r/w to ro
			 * or page now clean -> remap */
			flush = L4_FP_REMAP_PAGE;
			check_pte_mapped(old, pteval);
		} else {
			/* nothing changed, simply return */
			check_pte_mapped(old, pteval);
			return pte_val(pteval);
		}
	}

	/* Ok, now actually flush or remap the page */
	l4x_flush_page(pte_val(old), PAGE_SHIFT, L4_FP_OTHER_SPACES | flush);
	return pte_val(pteval);
}

void fastcall l4x_pte_clear(pte_t pteval)
{
	/* Invalidate page */
	l4x_flush_page(pte_val(pteval), PAGE_SHIFT,
	               L4_FP_OTHER_SPACES | L4_FP_FLUSH_PAGE);
}





/* (Un)Mapping function for vmalloc'ed memory */

void l4x_vmalloc_map_vm_area(unsigned long address, unsigned long end)
{
	if (address & ~PAGE_MASK)
		enter_kdebug("map_vm_area: Unaligned address!");

	for (; address < end; address += PAGE_SIZE) {
		pte_t *ptep = lookup_pte(swapper_pg_dir, address);

		if (!ptep || !pte_present(*ptep) || !pte_write(*ptep)) {
			printk("%s: Bad PTE for %08lx?!"
			       " (ptep: %p, pte: %08lx\n",
			       __func__, address,
			       ptep, pte_val(*ptep));
			enter_kdebug("no PTE?!");
			continue;
		}
		l4x_virtual_mem_register(address, pte_val(*ptep));
		l4lx_memory_map_virtual_page(address, pte_val(*ptep));
	}
}


void l4x_vmalloc_unmap_vm_area(unsigned long address, unsigned long end)
{
	if (address & ~PAGE_MASK)
		enter_kdebug("unmap_vm_area: Unaligned address!");

	for (; address < end; address += PAGE_SIZE) {
		/* check whether we are really flushing a vm page */
		if (address < (unsigned long)high_memory) {
			printk("flushing wrong page, addr: %lx\n", address);
			enter_kdebug("l4_unmap_virtual_mem");
			continue;
		}
		l4x_virtual_mem_unregister(address);
		l4lx_memory_unmap_virtual_page(address);
	}
}
