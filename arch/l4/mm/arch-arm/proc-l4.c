/*
 * Some processor specific functions.
 *
 * Maybe we should define an L4 CPU type somewhere?
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>

#include <asm/elf.h>
#include <asm/page.h>
#include <asm/procinfo.h>
#include <asm/tlbflush.h>

#include <l4/sys/kdebug.h>

#include <asm/generic/setup.h>

void cpu_sa1100_dcache_clean_area(void *addr, int sz) {}
void cpu_v6_dcache_clean_area(void *addr, int sz) {}

void cpu_sa1100_switch_mm(unsigned long pgd_phys, struct mm_struct *mm) {}
void cpu_v6_switch_mm(unsigned long pgd_phys, struct mm_struct *mm) {}

extern unsigned long fastcall l4x_set_pte(struct mm_struct *mm, unsigned long addr, pte_t pteptr, pte_t pteval);
extern void          fastcall l4x_pte_clear(struct mm_struct *mm, unsigned long addr, pte_t ptep);

static inline void l4x_cpu_set_pte_ext(pte_t *pteptr, pte_t pteval,
                                       unsigned int ext)
{
	if ((pte_val(*pteptr) & (L_PTE_PRESENT | L_PTE_MAPPED)) == (L_PTE_PRESENT | L_PTE_MAPPED)) {
		if (pteval == __pte(0))
			l4x_pte_clear(NULL, 0, *pteptr);
		else
			pte_val(pteval) = l4x_set_pte(NULL, 0, *pteptr, pteval);
	}
	*pteptr = pteval;
}

void cpu_sa1100_set_pte_ext(pte_t *pteptr, pte_t pteval, unsigned int ext)
{ l4x_cpu_set_pte_ext(pteptr, pteval, ext); }
void cpu_v6_set_pte_ext(pte_t *pteptr, pte_t pteval, unsigned int ext)
{ l4x_cpu_set_pte_ext(pteptr, pteval, ext); }


/*
 * cpu_do_idle()
 * Cause the processor to idle
 */
int cpu_sa1100_do_idle(void)
{
	outstring("cpu_sa1100_do_idle\n");
	return 0;
}

void cpu_sa1100_proc_init(void)
{
	printk("cpu_sa1100_proc_init\n");
}

void cpu_v6_proc_init(void)
{
	printk("cpu_v6_proc_init\n");
}

/*
 * cpu_proc_fin()
 *
 * Prepare the CPU for reset:
 *  - Disable interrupts
 *  - Clean and turn off caches.
 */
void cpu_sa1100_proc_fin(void)
{
	local_irq_disable();
}
#ifdef CONFIG_SMP
void cpu_v6_proc_fin(void)
{
	local_irq_disable();
}
#endif

void  __attribute__((noreturn)) l4x_cpu_reset(unsigned long addr)
{
	printk("%s called.\n", __func__);
	l4x_exit_l4linux();
	while (1)
		;
}


void v4_mc_copy_user_page(void *dst, const void *src, unsigned long vaddr)
{
	copy_page(dst, src);
}

void v4_mc_clear_user_page(void *addr, unsigned long vaddr)
{
	clear_page(addr);
}

void v4wb_flush_user_tlb_range(unsigned long start, unsigned long end,
                               struct vm_area_struct *mm)
{}

#ifdef CONFIG_SMP
void v6wbi_flush_user_tlb_range(unsigned long start, unsigned long end,
                               struct vm_area_struct *mm)
{}
#endif

void v4wb_flush_user_cache_range(unsigned long start, unsigned long end,
                                 unsigned int flags)
{}

void v4wb_flush_user_cache_all(void)
{}

void v4wb_flush_kern_tlb_range(unsigned long start, unsigned long end)
{}

#ifdef CONFIG_SMP
void v6wbi_flush_kern_tlb_range(unsigned long start, unsigned long end)
{}
#endif

void v4wb_flush_kern_cache_all(void)
{}

void v4wb_coherent_kern_range(unsigned long start, unsigned long end)
{
}

void v4wb_coherent_user_range(unsigned long start, unsigned long end)
{
}

void v4wb_flush_kern_dcache_page(void *x)
{
}

void update_mmu_cache(struct vm_area_struct *vma, unsigned long addr, pte_t pte)
{
	//outstring("update_mmu_cache\n");
}

static void __data_abort(unsigned long pc)
{
	printk("%s called.\n", __func__);
}

static void l4x_dma_cache_foo_range(const void *start, const void *stop)
{
}

/*
 * Could be that we need at least some of the definitions in MULTI only?.
 * That's why we just include this multi32.h file down here.
 */

#undef cpu_proc_init
#undef cpu_proc_fin
#undef cpu_reset
#undef cpu_do_idle
#undef cpu_dcache_clean_area
#undef cpu_set_pte_ext
#undef cpu_do_switch_mm
#include <asm/cpu-multi32.h>
#include <asm/cacheflush.h>

static struct processor l4_proc_fns = {
	._data_abort         = __data_abort,
	._proc_init          = cpu_sa1100_proc_init,
	._proc_fin           = cpu_sa1100_proc_fin,
	.reset               = l4x_cpu_reset,
	._do_idle            = cpu_sa1100_do_idle,
	.dcache_clean_area   = cpu_sa1100_dcache_clean_area,
	.switch_mm           = cpu_sa1100_switch_mm,
	.set_pte_ext         = cpu_sa1100_set_pte_ext,
};

static struct cpu_tlb_fns l4_tlb_fns = {
	.flush_user_range    = v4wb_flush_user_tlb_range,
	.flush_kern_range    = v4wb_flush_kern_tlb_range,
	.tlb_flags           = 0,
};

static struct cpu_user_fns l4_cpu_user_fns = {
	.cpu_clear_user_page = v4_mc_clear_user_page,
	.cpu_copy_user_page  = v4_mc_copy_user_page,
};

static struct cpu_cache_fns l4_cpu_cache_fns = {
	.flush_kern_all         = v4wb_flush_kern_cache_all,
	.flush_user_all         = v4wb_flush_user_cache_all,
	.flush_user_range       = v4wb_flush_user_cache_range,
	.coherent_kern_range    = v4wb_coherent_kern_range,
	.coherent_user_range    = v4wb_coherent_user_range,
	.flush_kern_dcache_page = v4wb_flush_kern_dcache_page,
	.dma_inv_range          = l4x_dma_cache_foo_range,
	.dma_clean_range        = l4x_dma_cache_foo_range,
	.dma_flush_range        = l4x_dma_cache_foo_range,
};

#ifndef CONFIG_SMP
static struct proc_info_list l4_proc_info_v4 __attribute__((__section__(".proc.info.init"))) = {
	.cpu_val         = 0,
	.cpu_mask        = 0,
	.__cpu_mm_mmu_flags = 0,
	.__cpu_io_mmu_flags = 0,
	.__cpu_flush     = 0,
	.arch_name       = "armv4",
	.elf_name        = "v4",
	.elf_hwcap       = HWCAP_SWP | HWCAP_HALF | HWCAP_26BIT | HWCAP_FAST_MULT,
	.cpu_name        = "Fiasco",
	.proc            = &l4_proc_fns,
	.tlb             = &l4_tlb_fns,
	.user            = &l4_cpu_user_fns,
	.cache           = &l4_cpu_cache_fns,
};
#endif


#ifdef CONFIG_SMP
static struct proc_info_list l4_proc_info_v6 __attribute__((__section__(".proc.info.init"))) = {
	.cpu_val         = 0,
	.cpu_mask        = 0,
	.__cpu_mm_mmu_flags = 0,
	.__cpu_io_mmu_flags = 0,
	.__cpu_flush     = 0,
	.arch_name       = "armv6",
	.elf_name        = "v6",
	.elf_hwcap       = HWCAP_SWP | HWCAP_HALF | HWCAP_26BIT | HWCAP_FAST_MULT,
	.cpu_name        = "Fiasco",
	.proc            = &l4_proc_fns,
	.tlb             = &l4_tlb_fns,
	.user            = &l4_cpu_user_fns,
	.cache           = &l4_cpu_cache_fns,
};
#endif


/*
 * This is the only processor info for now, so keep lookup_processor_type
 * simple.
 */
struct proc_info_list *lookup_processor_type(void);
struct proc_info_list *lookup_processor_type(void)
{
#ifdef CONFIG_SMP
	return &l4_proc_info_v6;
#else
	return &l4_proc_info_v4;
#endif
}
