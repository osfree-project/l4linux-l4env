#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/ioport.h>

/* Just to make the linker happy */

asmlinkage int sys_vm86(void)
{
	printk("sys_vm86() called\n");
	return -EPERM;
}
asmlinkage int sys_vm86old(void)
{
	printk("sys_vm86old() called\n");
	return -EPERM;
}

