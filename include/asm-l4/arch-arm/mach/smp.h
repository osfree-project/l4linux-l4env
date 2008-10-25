#ifndef ASMARM_ARCH_SMP_H
#define ASMARM_ARCH_SMP_H

l4_threadid_t l4x_cpu_ipi_thread_get(unsigned cpu);
int l4x_cpu_cpu_get(void);

#define hard_smp_processor_id() (l4x_cpu_cpu_get())

/*
 * Send IPI.
 */
static inline void smp_cross_call(cpumask_t callmap)
{
	int cpu, error;
	l4_msgdope_t dope;

	for_each_cpu_mask(cpu, callmap) {
		error = l4_ipc_send(l4x_cpu_ipi_thread_get(cpu),
		                    L4_IPC_SHORT_MSG_NODONATE, 0, 0,
		                    L4_IPC_BOTH_TIMEOUT_0, &dope);
		if (error && error != 0x30)
			LOG_printf("%s: IPC error %x\n", __func__, error);
	}
}

/*
 * Do nothing here.
 */
static inline void smp_cross_call_done(cpumask_t callmap)
{
}

#endif
