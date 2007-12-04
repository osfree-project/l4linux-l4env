#ifndef __ASM_L4__GENERIC__SMP_H__
#define __ASM_L4__GENERIC__SMP_H__

#ifdef CONFIG_SMP

#include <linux/sched.h>
#include <linux/bitops.h>

#include <l4/sys/types.h>

#define SPURIOUS_APIC_VECTOR    1
#define ERROR_APIC_VECTOR       2
#define INVALIDATE_TLB_VECTOR   3
#define RESCHEDULE_VECTOR       4
#define CALL_FUNCTION_VECTOR    5
#define L4X_TIMER_VECTOR	9

extern unsigned int l4x_nr_cpus;

void do_l4x_smp_process_IPI(int vector, struct pt_regs *regs);

void l4x_cpu_spawn(int cpu, struct task_struct *idle);
void l4x_cpu_release(int cpu);
l4_threadid_t l4x_cpu_thread_get(int cpu);
struct task_struct *l4x_cpu_idle_get(int cpu);
void l4x_smp_broadcast_timer(void);
void l4x_send_IPI_mask_bitmask(unsigned long, int);

void l4x_smp_update_task(struct task_struct *p, int cpu);

unsigned l4x_cpu_physmap_get(unsigned lcpu);

void l4x_cpu_ipi_thread_start(unsigned cpu);

#ifdef ARCH_x86
void l4x_load_percpu_gdt_descriptor(struct desc_struct *gdt);
#endif

#else
/* UP Systems */

#include <asm/generic/kthreads.h>

static inline l4_threadid_t l4x_cpu_thread_get(int _cpu)
{
	return linux_server_thread_id;
}

static inline int l4x_IPI_pending_tac(int cpu)
{
	return 0;
}

static inline int l4x_IPI_is_ipi_message(l4_umword_t d0)
{
	return 0;
}

static inline void l4x_smp_process_IPI(void)
{
}

static inline void l4x_smp_broadcast_timer(void)
{
}

static inline unsigned l4x_cpu_physmap_get(unsigned lcpu)
{
	return 0;
}

#endif

#endif /* ! __ASM_L4__GENERIC__SMP_H__ */
