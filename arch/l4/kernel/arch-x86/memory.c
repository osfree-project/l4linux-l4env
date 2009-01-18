#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/thread_info.h>
#include <linux/mm.h>
#include <linux/bootmem.h>

#include <asm-generic/sections.h>
#include <asm/e820.h>

#include <asm/generic/setup.h>


#include <l4/sys/kdebug.h>
#include <l4/log/l4log.h>

char * __init memory_setup(void)
{
	unsigned long mem_start, mem_size, isa_start, isa_size;
	extern unsigned long init_pg_tables_end;

	LOG_printf("memory_setup: %s\n", boot_command_line);

	setup_l4env_memory(boot_command_line, &mem_start, &mem_size,
	                   &isa_start, &isa_size);

	init_pg_tables_end = mem_start + mem_size;
        max_pfn_mapped = init_pg_tables_end >> PAGE_SHIFT;

        /* minimum 2 pages required */
        e820_add_region(0, PAGE_SIZE, E820_RAM);
	if (isa_size)
		e820_add_region(isa_start, isa_size, E820_RAM);
	e820_add_region(mem_start, mem_size, E820_RAM);

	LOG_printf("memory_setup done\n");
	return "L4Lx-Memory";
}
