#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/timex.h>
#include <linux/list.h>
#include <linux/interrupt.h>
#include <linux/irq.h>

#include <asm/mach-types.h>

#include <asm/mach/arch.h>
#include <asm/mach/irq.h>
#include <asm/mach/time.h>

#include <asm/l4lxapi/irq.h>
#include <asm/api/config.h>
#include <asm/generic/irq.h>

void l4x_arm_devices_init(void);

void l4x_arm_isg_init(void);
void l4x_arm_isg_map_io(void);
void l4x_arm_isg_irq_init(void);



static void __init map_io_l4(void)
{
#ifdef CONFIG_L4_ARM_PLATFORM_ISG
	l4x_arm_isg_map_io();
#endif
}

static void __init fixup_l4(struct machine_desc *desc, struct tag *tags,
                            char **cmdline, struct meminfo *mi)
{
}


static void l4_irq_timer_ackmaskun(unsigned int irq)
{
}

static int l4_irq_timer_type(unsigned int irq, unsigned int type)
{
	return 0;
}

static int l4_irq_timer_wake(unsigned int irq, unsigned int type)
{
	return 0;
}

static void l4_irq_virt_unmask(unsigned int irq)
{
	l4lx_irq_dev_startup_virt(irq);
}

static void l4_irq_hw_unmask(unsigned int irq)
{
	l4lx_irq_dev_startup_hw(irq);
}


static struct irq_chip l4_irq_virt_chip = {
	.name           = "L4virt",
	.ack            = l4_irq_timer_ackmaskun,
	.mask           = l4lx_irq_dev_shutdown_virt,
	.unmask         = l4_irq_virt_unmask,
	.set_type       = l4_irq_timer_type,
	.set_wake       = l4_irq_timer_wake,
};

static struct irq_chip l4_irq_dev_chip = {
	.name           = "L4dev",
	.ack            = l4_irq_timer_ackmaskun,
	.mask           = l4lx_irq_dev_shutdown_hw,
	.unmask         = l4_irq_hw_unmask,
	.set_type       = l4_irq_timer_type,
	.set_wake       = l4_irq_timer_wake,
};

static struct irq_chip l4_irq_timer_chip = {
	.name           = "L4timer",
	.ack            = l4_irq_timer_ackmaskun,
	.mask           = l4_irq_timer_ackmaskun,
	.unmask         = l4_irq_timer_ackmaskun,
	.set_type       = l4_irq_timer_type,
	.set_wake       = l4_irq_timer_wake,
};

void __init l4x_setup_virt_irq(unsigned int irq)
{
	set_irq_chip   (irq, &l4_irq_virt_chip);
	set_irq_handler(irq, handle_simple_irq);
	set_irq_flags  (irq, IRQF_VALID);
}

void __init l4x_setup_dev_irq(unsigned int irq)
{
	set_irq_chip   (irq, &l4_irq_dev_chip);
	set_irq_handler(irq, handle_simple_irq);
	set_irq_flags  (irq, IRQF_VALID);
}

static void __init init_irq_l4(void)
{
	int i;
	/* Call our generic IRQ handling code */
	l4lx_irq_init();

	for (i = 1; i < NR_IRQS; i++)
		l4x_setup_virt_irq(i);

#ifdef CONFIG_L4_ARM_PLATFORM_ISG
	l4x_arm_isg_irq_init();
#endif
}

static irqreturn_t l4_timer_interrupt_handler(int irq, void *dev_id)
{
	write_seqlock(&xtime_lock);
	timer_tick();
	write_sequnlock(&xtime_lock);
	return IRQ_HANDLED;
}

static struct irqaction timer_irq = {
	.name		= "L4 Timer Tick",
	.flags		= IRQF_DISABLED | IRQF_TIMER,
	.handler	= l4_timer_interrupt_handler,
};

unsigned int fastcall do_IRQ(int irq, struct pt_regs *regs)
{
	extern asmlinkage void asm_do_IRQ(unsigned int irq, struct pt_regs *regs);
	asm_do_IRQ(irq, regs);
	return 0;
}

static void __init l4x_timer_init(void)
{
	set_irq_chip   (0, &l4_irq_timer_chip);
	set_irq_handler(0, handle_simple_irq);
	set_irq_flags  (0, IRQF_VALID);

	setup_irq(0, &timer_irq);

	l4lx_irq_timer_startup(0);
}

static void __init init_l4(void)
{
	l4x_arm_devices_init();

#ifdef CONFIG_L4_ARM_PLATFORM_ISG
	l4x_arm_isg_init();
#endif
}

struct sys_timer l4x_timer = {
	.init		= l4x_timer_init,
};

MACHINE_START(L4, "L4")
	.phys_io	= 0,
	.io_pg_offst	= 0,
	.boot_params	= 0x100,
	.fixup		= fixup_l4,
	.map_io		= map_io_l4,
	.init_irq	= init_irq_l4,
	.timer		= &l4x_timer,
	.init_machine	= init_l4,
MACHINE_END

/*
 * We only have one machine description for now, so keep lookup_machine_type
 * simple.
 */
const struct machine_desc *lookup_machine_type(unsigned int x)
{
	return &__mach_desc_L4;
}
