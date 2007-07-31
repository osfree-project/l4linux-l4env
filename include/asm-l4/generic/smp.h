#ifndef __ASM_L4__GENERIC__SMP_H__
#define __ASM_L4__GENERIC__SMP_H__

#ifdef CONFIG_SMP

#include <linux/sched.h>
#include <linux/bitops.h>

#include <l4/sys/types.h>

#define L4X_IPI_MESSAGE         0x993

#define SPURIOUS_APIC_VECTOR    1
#define ERROR_APIC_VECTOR       2
#define INVALIDATE_TLB_VECTOR   3
#define RESCHEDULE_VECTOR       4
#define CALL_FUNCTION_VECTOR    5
#define L4X_TIMER_VECTOR	9

extern unsigned long l4x_IPI_pending_mask;
extern unsigned int l4x_nr_cpus;

static inline void l4x_IPI_pending_set(int cpu)
{
	set_bit(cpu, &l4x_IPI_pending_mask);
}

static inline int l4x_IPI_pending_tac(int cpu)
{
	return test_and_clear_bit(cpu, &l4x_IPI_pending_mask);
}

static inline int l4x_IPI_is_ipi_message(l4_umword_t d0)
{
	return d0 == L4X_IPI_MESSAGE;
}

void do_l4x_smp_process_IPI(void);

static inline void l4x_smp_process_IPI(void)
{
#ifndef ARCH_arm
	if (l4x_IPI_pending_tac(smp_processor_id()))
#endif
		do_l4x_smp_process_IPI();
}

void l4x_cpu_spawn(int cpu, struct task_struct *idle);
void l4x_cpu_release(int cpu);
l4_threadid_t l4x_cpu_thread_get(int cpu);
struct task_struct *l4x_cpu_idle_get(int cpu);
void l4x_smp_broadcast_timer(void);
void l4x_send_IPI_mask_bitmask(unsigned long, int);

void l4x_smp_update_task(struct task_struct *p, int cpu);

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

#endif

#endif /* ! __ASM_L4__GENERIC__SMP_H__ */
