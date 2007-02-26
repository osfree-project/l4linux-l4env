
#include <linux/kernel.h>

#include <asm/io.h>

static void print_warning(void)
{
	printk(KERN_WARNING "ins?/outs? not implemented on this architecture\n");
}

void insl(unsigned int port, void *to, int len)
{
	print_warning();
}

void insw(unsigned int port, void *to, int len)
{
	print_warning();
}

void insb(unsigned int port, void *to, int len)
{
	print_warning();
}

int inb(unsigned int port)
{
	print_warning();
	return 0;
}

int inw(unsigned int port)
{
	print_warning();
	return 0;
}

int inl(unsigned int port)
{
	print_warning();
	return 0;
}


void outsl(unsigned int port, const void *from, int len)
{
	print_warning();
}

void outsw(unsigned int port, const void *from, int len)
{
	print_warning();
}

void outsb(unsigned int port, const void *from, int len)
{
	print_warning();
}

void outb(void *addr, unsigned long val)
{
	print_warning();
}

void outw(void *addr, unsigned long val)
{
	print_warning();
}

void outl(void *addr, unsigned long val)
{
	print_warning();
}
