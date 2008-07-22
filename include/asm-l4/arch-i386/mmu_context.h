#ifndef __I386_SCHED_H
#define __I386_SCHED_H

#include <asm/desc.h>
#include <asm/atomic.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/paravirt.h>
#ifndef CONFIG_PARAVIRT
#ifdef L4LINUX_USES_the_MM_HOOKS__
#include <asm-generic/mm_hooks.h>
#endif

static inline void paravirt_activate_mm(struct mm_struct *prev,
					struct mm_struct *next)
{
}
#endif	/* !CONFIG_PARAVIRT */

#include <asm/generic/memory.h>
static inline void arch_dup_mmap(struct mm_struct *oldmm,
                                 struct mm_struct *mm)
{}

static inline void arch_exit_mmap(struct mm_struct *mm)
{
	mm->context.l4x_unmap_mode = L4X_UNMAP_MODE_SKIP;
}

/*
 * Used for LDT copy/destruction.
 */
int init_new_context(struct task_struct *tsk, struct mm_struct *mm);
void destroy_context(struct mm_struct *mm);


static inline void enter_lazy_tlb(struct mm_struct *mm, struct task_struct *tsk)
{
#ifdef L4LINUX_DOES_NOT_HANDLE_TLB____CONFIG_SMP
	unsigned cpu = smp_processor_id();
	if (per_cpu(cpu_tlbstate, cpu).state == TLBSTATE_OK)
		per_cpu(cpu_tlbstate, cpu).state = TLBSTATE_LAZY;
#endif
}

static inline void switch_mm(struct mm_struct *prev,
			     struct mm_struct *next,
			     struct task_struct *tsk)
{
#ifdef __L4LINUX_DOES_NOT_SWITCH_CONTEXTS__
	int cpu = smp_processor_id();

	if (likely(prev != next)) {
		/* stop flush ipis for the previous mm */
		cpu_clear(cpu, prev->cpu_vm_mask);
#ifdef CONFIG_SMP
		per_cpu(cpu_tlbstate, cpu).state = TLBSTATE_OK;
		per_cpu(cpu_tlbstate, cpu).active_mm = next;
#endif
		cpu_set(cpu, next->cpu_vm_mask);

		/* Re-load page tables */
		load_cr3(next->pgd);

		/*
		 * load the LDT, if the LDT is different:
		 */
		if (unlikely(prev->context.ldt != next->context.ldt))
			load_LDT_nolock(&next->context);
	}
#ifdef CONFIG_SMP
	else {
		per_cpu(cpu_tlbstate, cpu).state = TLBSTATE_OK;
		BUG_ON(per_cpu(cpu_tlbstate, cpu).active_mm != next);

		if (!cpu_test_and_set(cpu, next->cpu_vm_mask)) {
			/* We were in lazy tlb mode and leave_mm disabled
			 * tlb flush IPI delivery. We must reload %cr3.
			 */
			load_cr3(next->pgd);
			load_LDT_nolock(&next->context);
		}
	}
#endif
#endif
}

#define deactivate_mm(tsk, mm)			\
	asm("movl %0,%%gs": :"r" (0));

#define activate_mm(prev, next)			\
do {						\
	paravirt_activate_mm((prev), (next));	\
	switch_mm((prev), (next), NULL);	\
} while (0);

#endif
