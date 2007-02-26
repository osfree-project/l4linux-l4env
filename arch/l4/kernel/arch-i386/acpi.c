/*
 * Basic ACPI setup for booting
 */

#include <linux/init.h>
#include <linux/acpi.h>

int acpi_ht __initdata;
int acpi_pci_disabled __initdata = 1;
int acpi_noirq __initdata = 1;
int acpi_strict;
acpi_interrupt_flags acpi_sci_flags __initdata;

int __init acpi_boot_init(void)
{
	return 1; /* Failure */
}

char *__acpi_map_table(unsigned long phys, unsigned long size)
{
	return 0;
}

unsigned long __init acpi_find_rsdp(void)
{
	return 0;
}
