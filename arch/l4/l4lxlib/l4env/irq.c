/*
 * V2 device interrupt implementation.
 *
 */


#include <asm/io.h>

#include <linux/sched.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>

#include <l4/rmgr/librmgr.h>
#include <l4/sys/syscalls.h>
#include <l4/sys/ipc.h>

#include <asm/api/config.h>
#include <asm/api/macros.h>

#include <asm/l4lxapi/irq.h>
#include <asm/l4lxapi/thread.h>
#include <asm/l4lxapi/misc.h>

#include <asm/generic/sched.h>
#include <asm/generic/setup.h>
#include <asm/generic/task.h>
#include <asm/generic/do_irq.h>

#define d_printk(format, args...)  LOG_printf(format , ## args)
//#define dd_printk(format, args...) LOG_printf(format , ## args)
#define dd_printk(format, args...) do { } while (0)


static char do_irq_ack = 1;

/* There's a copy of this in l4lxlib/generic/irq_omega0.c
 * XXX: join this is a sane way! */
static char irq_prio[NR_IRQS] =
   /*  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f */
     { 1, 0,15, 6, 5, 4, 3, 2,14,13,12,11,10, 9, 8, 7};

static l4_umword_t irq_state[NR_IRQS];
static l4_umword_t irq_disable_cmd_state[NR_IRQS]; /* Make this a bitmask?! */

/*
 * Configure interrupt acknowledgement.
 *   Who is acknowledging interrupts?
 * Possible values for l4irqack:
 *    linux : L4Linux does it itself, e.g. needed for FIASCO UP
 *    l4    : L4 does it, e.g. needed for Hazelnut and FIASCO SMP
 *
 * Default is "l4"
 *
 *    FIXME: get this info from kernel info page
 */
static int __init l4_setup_interrupt_handling(char *str)
{
	if (!strncmp(str, "li", 2)) {
		do_irq_ack = 1;
	} else if (!strncmp(str, "l4", 2)) {
		do_irq_ack = 0;
	} else
		return 0;

	if (do_irq_ack)
		d_printk(KERN_INFO "l4irqack: L4Linux acknowledges IRQs itself\n");
	else
		d_printk(KERN_INFO "l4irqack: L4-kernel acknowledges IRQs\n");

	return 1;
}

__setup("l4irqack=", l4_setup_interrupt_handling);

/*
 * Return the priority of an interrupt thread.
 */
int l4lx_irq_prio_get(unsigned int irq)
{
	if (irq < NR_IRQS)
		return CONFIG_L4_PRIO_IRQ_OFFSET + irq_prio[irq];

	enter_kdebug("l4lx_irq_prio_get: wrong IRQ!");
	return -1;
}


DEFINE_SPINLOCK(l4_irq_lock);

/*
 * PIC handling routine: unblock/unmask PIC for a specific IRQ
 *                       IRQs can be delivered again
 */
static inline void l4_unmask_irq(unsigned int irq)
{
	unsigned char mask = ~(1 << (irq & 7));
	unsigned long flags;

	if (unlikely(irq == 2))
		return;

	spin_lock_irqsave(&l4lx_irq_pic_lock, flags);
	if (irq < 8)
		outb(inb(0x21) & mask, 0x21);
	else
		outb(inb(0xA1) & mask, 0xA1);
	spin_unlock_irqrestore(&l4lx_irq_pic_lock, flags);
}

/*
 * PIC handling routine: block/mask PIC for a specific IRQ
 *                       IRQs are blocked
 */
static inline void l4_mask_irq(unsigned int irq)
{
	unsigned char mask = 1 << (irq & 7);
	unsigned long flags;

	if (unlikely(irq == 2))
		return;

	spin_lock_irqsave(&l4lx_irq_pic_lock, flags);
	if (irq < 8)
		outb(inb(0x21) | mask, 0x21);
	else
		outb(inb(0xA1) | mask, 0xA1);
	spin_unlock_irqrestore(&l4lx_irq_pic_lock, flags);
}

/*
 * PIC handling routine: ack a specific IRQ
 */
static inline void l4_ack_irq(unsigned int irq)
{
	unsigned long flags;

	if (unlikely(irq == 2))
		return;

	spin_lock_irqsave(&l4lx_irq_pic_lock, flags);
	if (irq < 8)
		outb(0x60 + irq, 0x20);
	else {
		outb(0x60 + (irq & 7), 0xA0);
		outb(0x60 + 2, 0x20);
	}
	spin_unlock_irqrestore(&l4lx_irq_pic_lock, flags);
}

static inline void attach_to_irq(unsigned irq, l4_threadid_t *irq_th)
{
	l4_umword_t dummy;
	l4_msgdope_t dummydope;
	int code;

	/* Make thread_id (irq+1, 0) */
	l4_make_taskid_from_irq(irq, irq_th);

	/* Associate INTR */
	code = l4_ipc_receive(*irq_th,
			      0, /* receive descriptor */
			      &dummy, &dummy,
	                      L4_IPC_RECV_TIMEOUT_0,
			      &dummydope);

	if (code != L4_IPC_RETIMEOUT)
		dd_printk("%s: can't register to irq %u: error 0x%x\n",
		          __func__, irq, (unsigned) code);
}

/* attach current L4 thread to an interrupt source.  This is done
 * using the corresponding L4 kernel operation.  Before we try to do
 * that, however, we try to request ownership of that irq from the
 * resources manager we may be running under.
 */
static void init_irq_thread(unsigned irq, l4_threadid_t *irq_th)
{
	l4x_prepare_irq_thread(current_thread_info());
	attach_to_irq(irq, irq_th);
}

enum irq_cmds {
	CMD_IRQ_ENABLE  = 1,
	CMD_IRQ_DISABLE = 2,
};

static void attach_to_interrupt(unsigned irq, l4_threadid_t *irq_th)
{
	if (rmgr_get_irq(irq))
		dd_printk("%02d: Unable to attach to IRQ\n", irq);
	attach_to_irq(irq, irq_th);
	irq_state[irq] = 1;
}

static void detach_from_interrupt(unsigned irq)
{
	l4_umword_t dummy;
	l4_msgdope_t dummydope;

	l4_ipc_receive(L4_NIL_ID,
	               0, /* receive descriptor */
	               &dummy, &dummy,
	               L4_IPC_RECV_TIMEOUT_0,
	               &dummydope);

	if (rmgr_free_irq(irq))
		dd_printk("%02d: Unable to detach from IRQ\n", irq);
	irq_disable_cmd_state[irq] = irq_state[irq] = 0;
}

/*
 * Wait for an interrupt to arrive
 */
static inline void wait_for_irq_message(unsigned irq, l4_threadid_t irq_th,
                                        unsigned ack)
{
	l4_umword_t cmd1, cmd2;
	l4_msgdope_t dummydope;
	l4_threadid_t src_id;
	int err;

	while (1) {
		if (likely(ack && irq_state[irq]))
			l4_unmask_irq(irq);

		if (unlikely(irq_state[irq] && irq_disable_cmd_state[irq]))
			detach_from_interrupt(irq);

		err = l4_ipc_wait(&src_id,
				  0, /* receive descriptor */
				  &cmd1, &cmd2,
				  L4_IPC_NEVER,
				  &dummydope);

		if (unlikely(err)) {
			/* IPC error */
			d_printk("%s: IRQ %u (" PRINTF_L4TASK_FORM ") "
			         "receive failed, error = 0x%x\n",
			         __func__, irq, PRINTF_L4TASK_ARG(irq_th),
			         (unsigned) err);
			enter_kdebug("receive from intr failed");
		} else if (likely(l4_thread_equal(src_id, irq_th))) {
			/* Interrupt coming! */
			if (likely(irq_state[irq]))
				break;
			d_printk("Invalid message to IRQ thread %d\n", irq);
		} else if (unlikely(src_id.id.task == l4x_kernel_taskno)) {
			/* Non-IRQ message, handle */

			if (cmd1 == CMD_IRQ_ENABLE && !irq_state[irq])
				attach_to_interrupt(irq, &irq_th);
			else if (cmd1 == CMD_IRQ_DISABLE
			         && irq_state[irq]
			         && irq_disable_cmd_state[irq])
				detach_from_interrupt(irq);
		} else
			/* Message from remote, drop */
			d_printk(" Unknown message for IRQ %d\n", irq);
	}
} /* wait_for_irq_message */


/*
 * IRQ thread, here we sit in a loop waiting to handle
 * incoming interrupts
 */
static void irq_thread_hw(void *data)
{
	l4_threadid_t irq_th;
	unsigned irq = *(unsigned *)data;
	struct thread_info *ctx = current_thread_info();

	unsigned state;

	init_irq_thread(irq, &irq_th);

	dd_printk("%s: Started hw IRQ thread for IRQ %d\n", __func__, irq);

	l4_unmask_irq(irq);
	l4_ack_irq(irq);

	/*
	 * initialization complete -- now wait for irq messages and handle
	 * them appropriately
	 */

	for (;;) {
		state = 0;
		wait_for_irq_message(irq, irq_th, do_irq_ack);
		if (state)
			printk("nesting with irq %d\n", state);
		state = irq;

		l4x_do_IRQ(irq, ctx);
	}
} /* irq_thread_hw */

static void irq_thread_virt(void *data)
{
	l4_threadid_t irq_th;
	unsigned irq = *(unsigned *)data;
	struct thread_info *ctx = current_thread_info();

	init_irq_thread(irq, &irq_th);

	dd_printk("%s: Started virt IRQ thread for IRQ %d\n", __func__, irq);

	/*
	 * initialization complete -- now wait for irq messages and handle
	 * them appropriately
	 */

	for (;;) {
		wait_for_irq_message(irq, irq_th, 0);
		l4x_do_IRQ(irq, ctx);
	}
} /* irq_thread_hw */

/* ############################################################# */

/*
 * Common stuff.
 */

static void send_ipc(unsigned int irq, enum irq_cmds cmd)
{
	l4_msgdope_t dope;
	int ret;

	/* XXX: range checking */

	/* Disabling is not asynchronously to avoid dead locks with
	 * the Linux IRQ shutdown code in tamed mode */
	if (cmd == CMD_IRQ_DISABLE) {
		irq_disable_cmd_state[irq] = 1;
		ret = l4_ipc_send(irq_id[irq], L4_IPC_SHORT_MSG,
		                  cmd, 0,
		                  L4_IPC_SEND_TIMEOUT_0, &dope);
		if (ret && ret != L4_IPC_SETIMEOUT)
			LOG_printf("%s: dis-IPC failed with %x\n", __func__, ret);

	} else {
		ret = l4_ipc_send(irq_id[irq], L4_IPC_SHORT_MSG,
				  cmd, 0, L4_IPC_NEVER, &dope);

		if (ret)
			d_printk("%s: IPC failed with %x\n", __func__, ret);
	}
}

void l4lx_irq_init(void)
{
	l4lx_irq_max = NR_IRQS;
	printk("%s: l4lx_irq_max = %d\n", __func__, l4lx_irq_max);
}

/*******************************************
 * Hardware (device) interrupts.
 */

/*
 * There are two possible ways this funtion is called:
 * - from request_irq(...) and friends with properly set up
 *   environment (defined action)
 * - from probe_irq_on where no action is defined
 *   it's assumed that the code that calls probe_irq_on also calls
 *   probe_irq_off some time later (e.g. in the same routine)
 *
 * Autodetection from probe_irq_on needs special treatment since it
 * sets no irq handler for this irq and when the interrupt source delivers
 * many interrupts so that the irq thread (which has a higher priority than
 * other threads) gets all these interrupts no other thread in scheduled.
 * The system then hangs.... Anyone with a better solution?
 *
 * The implemented strategy hopefully prevents spinning IRQ threads when
 * devices cause IRQ storms in probes.
 *
 * Seems to be called with irq_desc[irq].lock held.
 */
static unsigned int do_l4lx_irq_dev_startup(unsigned int irq, int hw)
{
	l4_umword_t d1;
	char thread_name[7];

	/* first time? */
	if (!test_and_set_bit(irq, &irq_threads_started)) {

		/* register to the IRQ - get the IRQ from RMGR
		 */
		if (hw && (d1 = rmgr_get_irq(irq)) != 0) {
			/* the supervisor thread exists and
			 * sent a negative response */
			printk("irq_thread: RMGR denied IRQ %u: Code 0x%lx\n",
			       irq, d1);

			/* "reset" handler ... */
			irq_desc[irq].chip = &no_irq_type;

			/* ... and bail out  */
			return 0;
		}

		irq_state[irq] = 1;

		dd_printk("%s: creating IRQ thread for %d\n", __func__, irq);

		sprintf(thread_name, "IRQ%d", irq);
		irq_id[irq] = l4lx_thread_create(hw ? irq_thread_hw : irq_thread_virt,
						 NULL,
						 &irq, sizeof(irq),
						 l4lx_irq_prio_get(irq),
						 thread_name);
		if (l4lx_thread_equal(irq_id[irq], L4_NIL_ID))
			enter_kdebug("Error creating IRQ-thread!");
	}

	if (!irq_state[irq])
		send_ipc(irq, CMD_IRQ_ENABLE);

	/* We're in business (again), open interrupts... */
	/* This is needed... */
	if (hw)
		l4_unmask_irq(irq);

	return 1;
}

unsigned int l4lx_irq_dev_startup_hw(unsigned int irq)
{
	return do_l4lx_irq_dev_startup(irq, 1);
}

unsigned int l4lx_irq_dev_startup_virt(unsigned int irq)
{
	return do_l4lx_irq_dev_startup(irq, 0);
}

void l4lx_irq_dev_shutdown_hw(unsigned int irq)
{
	dd_printk("%s: %u\n", __func__, irq);
	l4lx_irq_dev_disable_hw(irq);
	/* ACK possible IRQs but only when auto probing so that
	 * no interrupt get lost in normal operation
	 *
	 * Checking for IRQ_AUTODETECT isn't possible here
	 * since the bit is already masked out by the calling code
	 */
	if (!irq_desc[irq].action)
		l4_ack_irq(irq);
}

void l4lx_irq_dev_shutdown_virt(unsigned int irq)
{
	dd_printk("%s: %u\n", __func__, irq);
	l4lx_irq_dev_disable_virt(irq);
}

static void do_l4lx_irq_dev_enable(unsigned int irq, int mask)
{
	dd_printk("%s: %u\n", __func__, irq);

	/* Only switch if IRQ thread already exists, not if we're running
	 * in the Linux server. */
	if (((1 << irq) & irq_threads_started))
		send_ipc(irq, CMD_IRQ_ENABLE);

	if (mask)
		l4_unmask_irq(irq);
}

static void do_l4lx_irq_dev_disable(unsigned int irq, int mask)
{
	dd_printk("%s: %u\n", __func__, irq);
	if (mask)
		l4_mask_irq(irq);

	if (((1 << irq) & irq_threads_started))
		send_ipc(irq, CMD_IRQ_DISABLE);
}

void l4lx_irq_dev_ack_hw(unsigned int irq)
{
	l4lx_irq_dbg_spin_wheel(irq);
	if (do_irq_ack)
		l4_ack_irq(irq);
}

void l4lx_irq_dev_mask_hw(unsigned int irq)
{
	if (do_irq_ack)
		l4_mask_irq(irq);
}

void l4lx_irq_dev_unmask_hw(unsigned int irq)
{
	if (do_irq_ack)
		l4_unmask_irq(irq);
}

void l4lx_irq_dev_end_hw(unsigned int irq)
{
	if (do_irq_ack &&
	    !(irq_desc[irq].status & (IRQ_DISABLED | IRQ_INPROGRESS)))
		l4_unmask_irq(irq);
}


void l4lx_irq_dev_enable_hw(unsigned int irq)
{
	do_l4lx_irq_dev_enable(irq, 1);
}

void l4lx_irq_dev_enable_virt(unsigned int irq)
{
	do_l4lx_irq_dev_enable(irq, 0);
}

void l4lx_irq_dev_disable_hw(unsigned int irq)
{
	do_l4lx_irq_dev_disable(irq, 1);
}

void l4lx_irq_dev_disable_virt(unsigned int irq)
{
	do_l4lx_irq_dev_disable(irq, 0);
}

void l4lx_irq_dev_ack_virt(unsigned int irq)
{}

void l4lx_irq_dev_mask_virt(unsigned int irq)
{}

void l4lx_irq_dev_unmask_virt(unsigned int irq)
{}

void l4lx_irq_dev_end_virt(unsigned int irq)
{}
