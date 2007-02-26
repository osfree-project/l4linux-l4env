/*
 * ARM Integrator platform specific code.
 */

#include <linux/platform_device.h>

#include <asm/generic/irq.h>

#define INTCP_PA_ETH_BASE		0xc8000000
#define INTCP_ETH_SIZE			0x10

#define IRQ_CP_ETHINT			27

static struct resource smc91x_resources[] = {
	[0] = {
		.start  = INTCP_PA_ETH_BASE,
		.end    = INTCP_PA_ETH_BASE + INTCP_ETH_SIZE - 1,
		.flags  = IORESOURCE_MEM,
	},
	[1] = {
		.start  = IRQ_CP_ETHINT,
		.end    = IRQ_CP_ETHINT,
		.flags  = IORESOURCE_IRQ,
	},
};

static struct platform_device smc91x_device = {
	.name           = "smc91x",
	.id             = 0,
	.num_resources  = ARRAY_SIZE(smc91x_resources),
	.resource       = smc91x_resources,
};

static struct platform_device *intcp_devs[] __initdata = {
	&smc91x_device,
};

void __init l4x_arm_integrator_init(void)
{
	platform_add_devices(intcp_devs, ARRAY_SIZE(intcp_devs));
}

void __init l4x_arm_integrator_map_io(void)
{
}

void __init l4x_arm_integrator_irq_init(void)
{
	int i;
	for (i = 1; i < NR_IRQS; i++)
		l4x_setup_virt_irq(i);
}
