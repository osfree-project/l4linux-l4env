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

#include <l4/sys/cache.h>

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


static void l4x_irq_ackmaskun_empty(unsigned int irq)
{
}

static int l4x_irq_type_empty(unsigned int irq, unsigned int type)
{
	return 0;
}

static int l4x_irq_wake_empty(unsigned int irq, unsigned int type)
{
	return 0;
}

static void l4x_irq_startup(unsigned int irq)
{
	l4lx_irq_dev_startup_hw(irq);
}

static struct irq_chip l4_irq_chip = {
	.name           = "L4",
	.ack            = l4x_irq_ackmaskun_empty,
	.mask           = l4lx_irq_dev_shutdown_hw,
	.unmask         = l4x_irq_startup,
	.set_type       = l4x_irq_type_empty,
	.set_wake       = l4x_irq_wake_empty,
};

static struct irq_chip l4_irq_timer_chip = {
	.name           = "L4timer",
	.ack            = l4x_irq_ackmaskun_empty,
	.mask           = l4x_irq_ackmaskun_empty,
	.unmask         = l4x_irq_ackmaskun_empty,
	.set_type       = l4x_irq_type_empty,
	.set_wake       = l4x_irq_wake_empty,
};

void __init l4x_setup_irq(unsigned int irq)
{
	set_irq_chip   (irq, &l4_irq_chip);
	set_irq_handler(irq, handle_simple_irq);
	set_irq_flags  (irq, IRQF_VALID);
}

static void __init init_irq_l4(void)
{
	int i;
	/* Call our generic IRQ handling code */
	l4lx_irq_init();

	for (i = 1; i < NR_IRQS; i++)
		l4x_setup_irq(i);

#ifdef CONFIG_L4_ARM_PLATFORM_ISG
	l4x_arm_isg_irq_init();
#endif
}

static irqreturn_t l4_timer_interrupt_handler(int irq, void *dev_id)
{
	timer_tick();

	//l4_kprintf("%s: %d\n", __func__, smp_processor_id());
#if defined(CONFIG_SMP)  && !defined(CONFIG_LOCAL_TIMERS)
	smp_send_timer();
	update_process_times(user_mode(get_irq_regs()));
#endif

	return IRQ_HANDLED;
}

static struct irqaction timer_irq = {
	.name		= "L4 Timer Tick",
	.flags		= IRQF_DISABLED | IRQF_TIMER | IRQF_IRQPOLL,
	.handler	= l4_timer_interrupt_handler,
};

unsigned int do_IRQ(int irq, struct pt_regs *regs)
{
	extern asmlinkage void asm_do_IRQ(unsigned int irq, struct pt_regs *regs);
	asm_do_IRQ(irq, regs);
	return 0;
}

static void l4x_timer_init(void)
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



/* DMA functions */
void v4wb_dma_inv_range(const void *start, const void *end)
{
	l4_sys_cache_inv_range((unsigned long)start, (unsigned long)end);
}

void v4wb_dma_clean_range(const void *start, const void *end)
{
	l4_sys_cache_clean_range((unsigned long)start, (unsigned long)end);
}

void v4wb_dma_flush_range(const void *start, const void *end)
{
	l4_sys_cache_flush_range((unsigned long)start, (unsigned long)end);
}


#ifdef CONFIG_SMP

#include <linux/profile.h>

void __cpuinit local_timer_setup(unsigned int cpu)
{
}

void local_timer_interrupt(void)
{
	profile_tick(CPU_PROFILING);
	update_process_times(user_mode(get_irq_regs()));
}

#endif
