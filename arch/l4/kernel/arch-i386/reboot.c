/*
 *  linux/arch/l4/kernel/reboot.c
 */

#include <linux/module.h>

#include <asm/generic/memory.h>
#include <asm/generic/setup.h>

#include <asm/reboot.h>


void machine_halt(void)
{
	local_irq_disable();
	l4x_exit_l4linux();
}

void machine_emergency_restart(void)
{
	machine_halt();
}

void machine_restart(char *__unused)
{
	machine_halt();
}

void machine_power_off(void)
{
	machine_halt();
}

struct machine_ops machine_ops = {
	.power_off = machine_power_off,
	.shutdown =  machine_halt,
	.emergency_restart = machine_emergency_restart,
	.restart = machine_restart,
	.halt = machine_halt,
};
