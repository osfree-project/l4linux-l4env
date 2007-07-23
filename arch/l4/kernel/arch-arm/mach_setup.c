/*
 * Device specific code.
 */

#include <linux/platform_device.h>
#include <asm/generic/io.h>

static struct resource l4x_net_resource[2];
static struct platform_device l4x_net_device;
static char *nic_SMSC911x = "smsc911x";
static char *nic_SMC91x   = "smc91x";

static int lookup(struct platform_device *d, struct resource *r,
                  const char *name)
{
	l4io_desc_device_t *l4dev;
	int i;

	if (!l4x_l4io_info_page())
		return 0;

	if ((l4dev = l4io_desc_lookup_device(name, l4x_l4io_info_page())) == NULL)
		return 0;

	if ((i = l4io_desc_lookup_resource(l4dev, L4IO_RESOURCE_MEM, 0)) == -1)
		return 0;
	r[0].flags = IORESOURCE_MEM;
	r[0].start = l4dev->resources[i].start;
	r[0].end   = l4dev->resources[i].end;

	if ((i = l4io_desc_lookup_resource(l4dev, L4IO_RESOURCE_IRQ, 0)) == -1)
		return 0;
	r[1].flags = IORESOURCE_IRQ;
	r[1].start = l4dev->resources[i].start;
	r[1].end   = l4dev->resources[i].end;

	// all ok
	d->resource      = r;
	d->num_resources = 2;
	d->name          = name;

	return 1;
}

void __init l4x_arm_devices_init(void)
{
	// Query NIC configuration from l4io
	if (lookup(&l4x_net_device, l4x_net_resource, nic_SMSC911x)
	    || lookup(&l4x_net_device, l4x_net_resource, nic_SMC91x)) {
		printk("Configured '%s' network controller\n",
		       l4x_net_device.name);
		platform_device_register(&l4x_net_device);
	}
}
