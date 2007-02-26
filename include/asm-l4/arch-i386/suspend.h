/*
 * Copyright 2001-2002 Pavel Machek <pavel@suse.cz>
 * Based on code
 * Copyright 2001 Patrick Mochel <mochel@osdl.org>
 */
#include <asm/desc.h>
#include <asm/i387.h>

int arch_prepare_suspend(void);

static inline int
arch_prepare_suspend_orig_i386(void)
{
	/* If you want to make non-PSE machine work, turn off paging
           in swsusp_arch_suspend. swsusp_pg_dir should have identity mapping, so
           it could work...  */
	if (!cpu_has_pse) {
		printk(KERN_ERR "PSE is required for swsusp.\n");
		return -EPERM;
	}
	return 0;
}

/* image of the saved processor state */
struct saved_context {
  	u16 es, fs, gs, ss;
	unsigned long cr0, cr2, cr3, cr4;
	u16 gdt_pad;
	u16 gdt_limit;
	unsigned long gdt_base;
	u16 idt_pad;
	u16 idt_limit;
	unsigned long idt_base;
	u16 ldt;
	u16 tss;
	unsigned long tr;
	unsigned long safety;
	unsigned long return_address;
} __attribute__((packed));

#ifdef CONFIG_ACPI_SLEEP
extern unsigned long saved_eip;
extern unsigned long saved_esp;
extern unsigned long saved_ebp;
extern unsigned long saved_ebx;
extern unsigned long saved_esi;
extern unsigned long saved_edi;

static inline void acpi_save_register_state(unsigned long return_point)
{
	saved_eip = return_point;
	asm volatile ("movl %%esp,%0" : "=m" (saved_esp));
	asm volatile ("movl %%ebp,%0" : "=m" (saved_ebp));
	asm volatile ("movl %%ebx,%0" : "=m" (saved_ebx));
	asm volatile ("movl %%edi,%0" : "=m" (saved_edi));
	asm volatile ("movl %%esi,%0" : "=m" (saved_esi));
}

#define acpi_restore_register_state()  do {} while (0)

/* routines for saving/restoring kernel state */
extern int acpi_save_state_mem(void);
#endif