#ifndef _ASM_X86_MMU_H
#define _ASM_X86_MMU_H

#include <linux/spinlock.h>
#include <linux/mutex.h>

#include <asm/generic/mmu.h>

/*
 * The x86 doesn't have a mmu context, but
 * we put the segment information here.
 *
 * cpu_vm_mask is used to optimize ldt flushing.
 */
typedef struct {
	void *ldt;
#ifdef CONFIG_X86_64
	rwlock_t ldtlock;
#endif
	int size;
	struct mutex lock;
	void *vdso;

	int l4x_task_id;
	enum l4x_unmap_mode_enum l4x_unmap_mode;
} mm_context_t;

#ifdef CONFIG_SMP
void leave_mm(int cpu);
#else
static inline void leave_mm(int cpu)
{
}
#endif

#endif /* _ASM_X86_MMU_H */
