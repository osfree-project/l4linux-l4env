/*
 * Multi IRQ implementation. We only use one single IRQ thread.
 */

#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/interrupt.h>

#include <l4/sys/ipc.h>
#include <l4/sigma0/kip.h>
#include <l4/log/l4log.h>

#include <asm/api/config.h>
#include <asm/api/macros.h>

#include <asm/l4lxapi/irq.h>
#include <asm/l4lxapi/thread.h>

#include <asm/generic/setup.h>
#include <asm/generic/do_irq.h>

#define d_printk(format, args...)  printk(format , ## args)
//#define dd_printk(format, args...) printk(format , ## args)
#define dd_printk(format, args...)

enum irq_cmd {
	IRQ_CMD_ACK = 0,
	IRQ_CMD_DEASSOCIATE = 1,
};

enum irq_snd_msg {
	IRQ_SND_MSG_ATTACH = 0x99998888,
	IRQ_SND_MSG_DETACH = 0x99998889,
};


static l4_threadid_t irq_ths[1];

/*
 * Return the priority of an interrupt thread.
 */
int l4lx_irq_prio_get(unsigned int irq)
{
	if (irq == 0)
		return CONFIG_L4_PRIO_IRQ_BASE + 1;

	return CONFIG_L4_PRIO_IRQ_BASE;
}


DEFINE_SPINLOCK(l4_irq_lock);

static void attach_to_IRQ(unsigned int irq)
{
	l4_umword_t dummy;
	l4_msgdope_t res;
	int code;
	l4_threadid_t irq_th;

	/* Make thread_id (irq+1, 0) */
	l4_make_taskid_from_irq(irq, &irq_th);

	/* Associate INTR */
	code = l4_ipc_receive(irq_th,
			      L4_IPC_SHORT_MSG,
			      &dummy, &dummy,
			      L4_IPC_RECV_TIMEOUT_0,
			      &res);

	if (code != L4_IPC_RETIMEOUT)
		printk("%s: can't register to irq %u: error 0x%x\n",
		       __func__, irq, (unsigned) code);
}

/*
 * Send a command to the interrupt thread.
 *
 * Note, this is not necessary for a real X.2 interface.
 */
static void send_msg_to_irq_thread(unsigned int irq, unsigned int cpu,
                                   enum irq_snd_msg cmd)
{
	int ret;

	if (l4lx_thread_equal(irq_ths[cpu], L4_NIL_ID)) {
		printk("%s: No interrupt thread?\n", __func__);
		return;
	}

	if (irq >= NR_IRQS) {
		printk("%s: IRQ %d is too big/not available.\n", __func__, irq);
		return;
	}

	do {
		l4_msgdope_t resdope;

		ret = l4_ipc_send(irq_ths[cpu], L4_IPC_SHORT_MSG,
		                  cmd, irq,
				  L4_IPC_RECV_TIMEOUT_0, &resdope);

		if (ret)
			printk("Failure while trying to send to irq thread,"
			       " retrying\n");

	} while (ret);
}

/*
 * Wait for an interrupt to arrive
 */
static inline unsigned int wait_for_irq_message(unsigned int irq_to_ack)
{
	l4_umword_t d1, d2 = 0;
	l4_msgdope_t dummydope;
	int code;
	l4_threadid_t id;

	d1 = IRQ_CMD_ACK;

	while (1) {
		if (irq_to_ack) {

			l4_make_taskid_from_irq(irq_to_ack, &id);

			code = l4_ipc_reply_and_wait(id, L4_IPC_SHORT_MSG,
						     d1, d2,
						     &id, L4_IPC_SHORT_MSG,
						     &d1, &d2,
						     L4_IPC_NEVER,
						     &dummydope);
		} else
			code = l4_ipc_wait(&id, L4_IPC_SHORT_MSG,
					   &d1, &d2,
					   L4_IPC_NEVER,
					   &dummydope);

		if (unlikely(code)) {
			printk("%s: IPC error (0x%x)\n", __func__, code);
			d1 = d2 = irq_to_ack = 0;
			continue;
		}

		/* Check sender */
		if (id.id.task == 0 && id.raw && id.raw < NR_IRQS + 1) {
			return id.raw - 1;
		} else if (id.id.task == l4x_kernel_taskno) {
			if (d1 == IRQ_SND_MSG_ATTACH) {
				attach_to_IRQ(d2);

				d1 = IRQ_CMD_ACK;
				irq_to_ack = d2;
			} else if (d1 == IRQ_SND_MSG_DETACH) {
				irq_to_ack = d2;
				d1 = IRQ_CMD_DEASSOCIATE;
			} else {
				printk("%s: Unknown cmd, skipping\n", __func__);
			}
		} else {
			printk("%s: Unknown sender " PRINTF_L4TASK_FORM "\n",
			       __func__, PRINTF_L4TASK_ARG(id));
		}
	}
} /* wait_for_irq_message */

/*
 * IRQ thread, here we sit in a loop waiting to handle
 * incoming interrupts
 */
static L4_CV void irq_thread(void *data)
{
	unsigned cpu = *(unsigned *)data;
	unsigned int irq = 0;
	struct thread_info *ctx = current_thread_info();

	l4x_prepare_irq_thread(ctx, 0);

	d_printk("%s: Starting IRQ thread on CPU %d\n", __func__, cpu);

	for (;;) {
		irq = wait_for_irq_message(irq);
		l4x_do_IRQ(irq, ctx);
	}
} /* irq_thread */

/* ############################################################# */

/*
 * Common stuff.
 */

void l4lx_irq_init(void)
{
	int cpu = smp_processor_id();
	char thread_name[11];

	l4lx_irq_max = NR_IRQS;
	printk("%s: l4lx_irq_max = %d\n", __func__, l4lx_irq_max);

	/* Check that kernel supports our IRQ mode */
	if (!l4sigma0_kip_kernel_has_feature("multi_irq")) {
		LOG_printf("Kernel does not support the \"multi_irq\" feature!\n");
		enter_kdebug("Missing 'multi_irq' kernel feature!");
	}

	/* Start IRQ thread */
	d_printk("%s: creating IRQ thread on cpu %d\n", __func__, cpu);

	snprintf(thread_name, sizeof(thread_name), "IRQ CPU%d", cpu);
	thread_name[sizeof(thread_name) - 1] = 0;
	irq_ths[cpu] = l4lx_thread_create(irq_thread, 0, NULL,
	                                  &cpu, sizeof(cpu),
	                                  l4lx_irq_prio_get(1),
	                                  thread_name);
	if (l4lx_thread_equal(irq_ths[cpu], L4_NIL_ID))
		enter_kdebug("Error creating IRQ-thread!");
}

/*******************************************
 * Hardware (device) interrupts.
 */

unsigned int l4lx_irq_dev_startup_hw(unsigned int irq)
{
	send_msg_to_irq_thread(irq, 0, IRQ_SND_MSG_ATTACH);
	return 1;
}

void l4lx_irq_dev_shutdown_hw(unsigned int irq)
{
	send_msg_to_irq_thread(irq, 0, IRQ_SND_MSG_DETACH);
}
