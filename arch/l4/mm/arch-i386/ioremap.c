/*
 * arch/i386/mm/ioremap.c
 *
 * Re-map IO memory to kernel address space so that we can access it.
 * This is needed for high PCI addresses that aren't mapped in the
 * 640k-1MB IO memory area on PC's
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 */

#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <asm/fixmap.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#include <l4/generic_io/libio.h>

#define ISA_START_ADDRESS	0xa0000
#define ISA_END_ADDRESS		0x100000

/* L4Linux maintains a remap-table and maps the memory into the kernel */

#define MAX_IOREMAP_ENTRIES 20
struct ioremap_table {
	unsigned long real_map_addr;
	unsigned long ioremap_addr;
	unsigned long phys_addr;
	unsigned long size;
};

static struct ioremap_table io_table[MAX_IOREMAP_ENTRIES];
static int ioremap_table_initialized = 0;

static DEFINE_SPINLOCK(ioremap_lock);

static void reset_ioremap_entry_nocheck(int entry)
{
	io_table[entry] = (struct ioremap_table){0, 0, 0, 0};
}

static void init_ioremap_nocheck(void)
{
	int i;
	for (i = 0; i < MAX_IOREMAP_ENTRIES; i++)
		reset_ioremap_entry_nocheck(i);
	ioremap_table_initialized = 1;
}

static int set_ioremap_entry(unsigned long real_map_addr,
                             unsigned long ioremap_addr,
			     unsigned long phys_addr,
			     unsigned long size)
{
	int i;

	spin_lock(&ioremap_lock);

	if (!ioremap_table_initialized)
		init_ioremap_nocheck();

	for (i = 0; i < MAX_IOREMAP_ENTRIES; i++)
		if (io_table[i].real_map_addr == 0) {
			io_table[i] = (struct ioremap_table){real_map_addr,
			                                     ioremap_addr,
			                                     phys_addr,
			                                     size};
			spin_unlock(&ioremap_lock);
			return 0;
		}

	enter_kdebug("no free entry in ioremaptable");
	spin_unlock(&ioremap_lock);
	return 1;
}

static int __lookup_ioremap_entry_phys(unsigned long phys_addr)
{
	int i;

	if (!ioremap_table_initialized)
		return -1;

	spin_lock(&ioremap_lock);

	for (i = 0; i < MAX_IOREMAP_ENTRIES; i++)
		if ((io_table[i].phys_addr <= phys_addr) &&
		    io_table[i].phys_addr + io_table[i].size > phys_addr)
			break;

	spin_unlock(&ioremap_lock);
	return i == MAX_IOREMAP_ENTRIES ? -1 : i;
}

unsigned long find_ioremap_entry(unsigned long phys_addr)
{
	int i;
	if ((i = __lookup_ioremap_entry_phys(phys_addr)) == -1)
		return 0;

	return io_table[i].ioremap_addr + (phys_addr - io_table[i].phys_addr);
}

static int remove_ioremap_entry_phys(unsigned long phys_addr)
{
	int i;
	if ((i = __lookup_ioremap_entry_phys(phys_addr)) == -1)
		return -1;

	spin_lock(&ioremap_lock);
	reset_ioremap_entry_nocheck(i);
	spin_unlock(&ioremap_lock);
	return 0;
}

#ifdef CONFIG_L4_L4ENV
static unsigned long lookup_phys_entry(unsigned long ioremap_addr,
                                       unsigned long *size)
{
	int i;

	if (!ioremap_table_initialized)
		return 0;

	spin_lock(&ioremap_lock);

	for (i = 0; i < MAX_IOREMAP_ENTRIES; i++)
		if (io_table[i].ioremap_addr == ioremap_addr) {
			*size = io_table[i].size;
			spin_unlock(&ioremap_lock);
			return io_table[i].phys_addr;
		}

	spin_unlock(&ioremap_lock);
	return 0;
}

static inline unsigned long get_iotable_entry_size(int i)
{
	return io_table[i].size;
}

static inline unsigned long get_iotable_entry_ioremap_addr(int i)
{
	return io_table[i].ioremap_addr;
}

static inline unsigned long get_iotable_entry_phys(int i)
{
	return io_table[i].phys_addr;
}

#else

static unsigned long lookup_ioremap_entry(unsigned long ioremap_addr)
{
	int i;
	unsigned long result = 0;

	if (!ioremap_table_initialized)
		return 0;

	spin_lock(&ioremap_lock);

	for (i = 0; i < MAX_IOREMAP_ENTRIES; i++)
		if (io_table[i].ioremap_addr == ioremap_addr) {
			result = io_table[i].real_map_addr;
			break;
		}

	spin_unlock(&ioremap_lock);
	return result;
}

static inline void remap_area_pte(pte_t * pte, unsigned long address, unsigned long size,
	unsigned long phys_addr, unsigned long flags)
{
	unsigned long end;
	unsigned long pfn;

	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;
	if (address >= end)
		BUG();
	pfn = phys_addr >> PAGE_SHIFT;
	do {
		if (!pte_none(*pte)) {
			printk("remap_area_pte: page already exists\n");
			BUG();
		}
		set_pte(pte, pfn_pte(pfn, __pgprot(_PAGE_PRESENT | _PAGE_RW |
					_PAGE_DIRTY | _PAGE_ACCESSED | flags)));
		address += PAGE_SIZE;
		pfn++;
		pte++;
	} while (address && (address < end));
}

static inline int remap_area_pmd(pmd_t * pmd, unsigned long address, unsigned long size,
	unsigned long phys_addr, unsigned long flags)
{
	unsigned long end;

	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;
	phys_addr -= address;
	if (address >= end)
		BUG();
	do {
		pte_t * pte = pte_alloc_kernel(pmd, address);
		if (!pte)
			return -ENOMEM;
		remap_area_pte(pte, address, end - address, address + phys_addr, flags);
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address && (address < end));
	return 0;
}

static int remap_area_pages(unsigned long address, unsigned long phys_addr,
				 unsigned long size, unsigned long flags)
{
	int error;
	pgd_t * dir;
	unsigned long end = address + size;

	phys_addr -= address;
	dir = pgd_offset(&init_mm, address);
	flush_cache_all();
	if (address >= end)
		BUG();
	do {
		pud_t *pud;
		pmd_t *pmd;

		error = -ENOMEM;
		pud = pud_alloc(&init_mm, dir, address);
		if (!pud)
			break;
		pmd = pmd_alloc(&init_mm, pud, address);
		if (!pmd)
			break;
		if (remap_area_pmd(pmd, address, end - address,
					 phys_addr + address, flags))
			break;
		error = 0;
		address = (address + PGDIR_SIZE) & PGDIR_MASK;
		dir++;
	} while (address && (address < end));
	flush_tlb_all();
	return error;
}

#endif

/*
 * Generic mapping function (not visible outside):
 */

/*
 * Remap an arbitrary physical address space into the kernel virtual
 * address space. Needed when the kernel wants to access high addresses
 * directly.
 *
 * NOTE! We need to allow non-page-aligned mappings too: we will obviously
 * have to convert them into an offset in a page-aligned mapping, but the
 * caller shouldn't need to know that small detail.
 */
void __iomem * __ioremap(unsigned long phys_addr, unsigned long size, unsigned long flags)
{
	void __iomem * addr;
#ifndef CONFIG_L4_L4ENV
	struct vm_struct * area;
#else
	l4_umword_t reg_start;
	l4_size_t reg_len;
	int i;
#endif
	unsigned long last_addr;
	unsigned long offset;

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr)
		return NULL;

#ifndef CONFIG_L4_L4ENV
	/*
	 * Don't remap the low PCI/ISA area, it's always mapped..
	 */
	if (phys_addr >= ISA_START_ADDRESS && last_addr < ISA_END_ADDRESS)
		return (void __iomem *) phys_to_virt(phys_addr);

	/*
	 * Don't allow anybody to remap normal RAM that we're using..
	 */
	if (phys_addr <= virt_to_phys(high_memory - 1)) {
		char *t_addr, *t_end;
		struct page *page;

		t_addr = __va(phys_addr);
		t_end = t_addr + (size - 1);

		for(page = virt_to_page(t_addr); page <= virt_to_page(t_end); page++)
			if(!PageReserved(page))
				return NULL;
	}

	/*
	 * Mappings have to be page-aligned
	 */
	offset = phys_addr & ~PAGE_MASK;
	phys_addr &= PAGE_MASK;
	size = PAGE_ALIGN(last_addr+1) - phys_addr;

	/*
	 * Ok, go for it..
	 */
	/* We need an additional window of L4_DEV_PAGE_SIZE to be able
	 * to align our mapping according to the limitations of L4/x86 */
	area = get_vm_area(size + L4_DEV_PAGE_SIZE, VM_IOREMAP | (flags << 20));
	if (!area)
		return NULL;
	area->phys_addr = phys_addr;
	addr = (void __iomem *)L4_DEV_PAGE_ALIGN((unsigned long)area->addr);
	printk("remapping phys addr %lx to virt addr %lx, size: %lx\n",
	       phys_addr, addr, size);
	if (remap_area_pages((unsigned long) addr, phys_addr, size, flags)) {
		vunmap((void __force *) addr);
		return NULL;
	}

	set_ioremap_entry((unsigned long)area->addr,
	                  (unsigned long)((char *)addr + offset),
			  phys_addr,
			  size);
#else
	/*
	 * If userland applications like X generate page faults on
	 * I/O memory region we do not know how big the region really is.
	 * l4io is requesting at least 8M virtual address space for every
	 * l4io_request_mem_region call so that we cannot get a continuous
	 * region with multiple page faults to the same region and different
	 * pages. That's why we first request the size of the region and
	 * then request the whole region at once.
	 */
	printk("%s: Requested region at %08lx [0x%lx Bytes]\n", __func__, phys_addr, size);

	if ((i = __lookup_ioremap_entry_phys(phys_addr)) != -1) {
		/* Found already existing entry */
		offset = phys_addr - get_iotable_entry_phys(i);
		if (get_iotable_entry_size(i) - offset >= size)
			/* size is within this area, return */
			return (void __iomem *)
			   (get_iotable_entry_ioremap_addr(i) + offset);
	}

	if (l4io_search_mem_region(phys_addr, &reg_start, &reg_len)) {
		printk("l4io_search_mem_region for phys_addr = %lx\n", phys_addr);
		enter_kdebug("l4io_search_mem_region nope");
		return NULL;
	}

	//printk("%s: whole region %08lx - %08lx (%06x)\n", __func__, reg_start, reg_start + reg_len - 1, reg_len);

	if ((addr = (void *)l4io_request_mem_region(reg_start, reg_len,
	                                            0, &offset)) == 0) {
		enter_kdebug("l4io_request_mem_region error");
		return NULL;
	}

	/* Save whole region */
	set_ioremap_entry((unsigned long)addr,
	                  ((unsigned long)addr) + offset,
	                  reg_start,
	                  reg_len);

	offset += phys_addr - reg_start;

	printk("%s: Mapping physaddr %08lx [0x%lx Bytes, %08lx+%06x] to %08lx+%06lx\n",
	       __func__, phys_addr, size, reg_start, reg_len, (unsigned long)addr, offset);

#endif /* ! CONFIG_L4_L4ENV */

	return (void __iomem *) (offset + (char *)addr);
}
EXPORT_SYMBOL(__ioremap);


/**
 * ioremap_nocache     -   map bus memory into CPU space
 * @offset:    bus address of the memory
 * @size:      size of the resource to map
 *
 * ioremap_nocache performs a platform specific sequence of operations to
 * make bus memory CPU accessible via the readb/readw/readl/writeb/
 * writew/writel functions and the other mmio helpers. The returned
 * address is not guaranteed to be usable directly as a virtual
 * address.
 *
 * This version of ioremap ensures that the memory is marked uncachable
 * on the CPU as well as honouring existing caching rules from things like
 * the PCI bus. Note that there are other caches and buffers on many
 * busses. In particular driver authors should read up on PCI writes
 *
 * It's useful if some control registers are in such an area and
 * write combining or read caching is not desirable:
 *
 * Must be freed with iounmap.
 */

void __iomem *ioremap_nocache (unsigned long phys_addr, unsigned long size)
{
	unsigned long last_addr;
	void __iomem *p = __ioremap(phys_addr, size, _PAGE_PCD);
	if (!p)
		return p;

	/* Guaranteed to be > phys_addr, as per __ioremap() */
	last_addr = phys_addr + size - 1;

	/* Note: added a "- 1" and "=" there so that it's within the
	 *       memory region and not 1 byte behind (and cannot be found) */
	if (last_addr <= virt_to_phys(high_memory - 1)) {
		struct page *ppage = virt_to_page(__va(phys_addr));
		unsigned long npages;

		phys_addr &= PAGE_MASK;

		/* This might overflow and become zero.. */
		last_addr = PAGE_ALIGN(last_addr);

		/* .. but that's ok, because modulo-2**n arithmetic will make
		* the page-aligned "last - first" come out right.
		*/
		npages = (last_addr - phys_addr) >> PAGE_SHIFT;

		if (change_page_attr(ppage, npages, PAGE_KERNEL_NOCACHE) < 0) {
			iounmap(p);
			p = NULL;
		}
		global_flush_tlb();
	}

	return p;
}
EXPORT_SYMBOL(ioremap_nocache);

/**
 * iounmap - Free a IO remapping
 * @addr: virtual address from ioremap_*
 *
 * Caller must ensure there is only one unmapping for the same pointer.
 */
void iounmap(volatile void __iomem *addr)
{
#ifndef CONFIG_L4_L4ENV
	struct vm_struct *p;
	unsigned long real_vm_addr, real_map_addr;

	if ((void __force *) addr <= high_memory)
		return;

	real_vm_addr = lookup_ioremap_entry((unsigned long __force) addr);
	real_map_addr = L4_DEV_PAGE_ALIGN(real_vm_addr);

	p = remove_vm_area((void *) (PAGE_MASK & (unsigned long) addr));
	if (!p) {
		printk("__iounmap: bad address %p\n", addr);
		return;
	}

	if ((p->flags >> 20) && p->phys_addr < virt_to_phys(high_memory) - 1) {
		/* p->size includes the guard page, but cpa doesn't like that */
		change_page_attr(virt_to_page(__va(p->phys_addr)),
				 (p->size - PAGE_SIZE) >> PAGE_SHIFT,
				 PAGE_KERNEL);
		global_flush_tlb();
	}

	flush_page(real_map_addr, L4_LOG2_DEV_PAGE,
	           L4_FP_ALL_SPACES | L4_FP_FLUSH_PAGE);

	kfree(p);
#else
	unsigned long size;
	unsigned long phys_addr;

	if (addr <= high_memory)
		return;

	if ((phys_addr = lookup_phys_entry((unsigned long)addr, &size)) == 0) {
		printk("%s: Error unmapping addr %p\n", __func__, addr);
		return;
	}

	if (remove_ioremap_entry_phys(phys_addr) == -1)
		printk("%s: could not find address to unmap\n", __func__);

	if (l4io_release_mem_region(phys_addr, size))
		printk("iounmap: error calling l4io_release_mem_region, not freed");
#endif
}
EXPORT_SYMBOL(iounmap);

void __init *bt_ioremap(unsigned long phys_addr, unsigned long size)
{
	unsigned long offset, last_addr;
	unsigned int nrpages;
	enum fixed_addresses idx;

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr)
		return NULL;

	/*
	 * Don't remap the low PCI/ISA area, it's always mapped..
	 */
	if (phys_addr >= ISA_START_ADDRESS && last_addr < ISA_END_ADDRESS)
		return phys_to_virt(phys_addr);

	/*
	 * Mappings have to be page-aligned
	 */
	offset = phys_addr & ~PAGE_MASK;
	phys_addr &= PAGE_MASK;
	size = PAGE_ALIGN(last_addr) - phys_addr;

	/*
	 * Mappings have to fit in the FIX_BTMAP area.
	 */
	nrpages = size >> PAGE_SHIFT;
	if (nrpages > NR_FIX_BTMAPS)
		return NULL;

	/*
	 * Ok, go for it..
	 */
	idx = FIX_BTMAP_BEGIN;
	while (nrpages > 0) {
		set_fixmap(idx, phys_addr);
		phys_addr += PAGE_SIZE;
		--idx;
		--nrpages;
	}
	return (void*) (offset + fix_to_virt(FIX_BTMAP_BEGIN));
}

void __init bt_iounmap(void *addr, unsigned long size)
{
	unsigned long virt_addr;
	unsigned long offset;
	unsigned int nrpages;
	enum fixed_addresses idx;

	virt_addr = (unsigned long)addr;
	if (virt_addr < fix_to_virt(FIX_BTMAP_BEGIN))
		return;
	offset = virt_addr & ~PAGE_MASK;
	nrpages = PAGE_ALIGN(offset + size - 1) >> PAGE_SHIFT;

	idx = FIX_BTMAP_BEGIN;
	while (nrpages > 0) {
		clear_fixmap(idx);
		--idx;
		--nrpages;
	}
}
