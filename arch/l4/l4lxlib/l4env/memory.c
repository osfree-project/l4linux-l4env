/*
 * Implementation of include/asm-l4/l4lxapi/memory.h
 * for L4Env.
 */

#include <linux/kernel.h>

#include <asm/page.h>
#include <asm/l4lxapi/memory.h>
#include <asm/api/api.h>

#include <l4/l4rm/l4rm.h>
#include <l4/env/errno.h>

static inline l4_uint32_t get_area_id(unsigned long address)
{
#ifdef ARCH_arm
	if (address >= MODULES_VADDR && address < MODULES_END)
		return l4env_modules_areaid;
#endif
	return l4env_vmalloc_areaid;
}

int l4lx_memory_map_virtual_page(unsigned long address, unsigned long page)
{
	int res;
	l4dm_dataspace_t ds;
	l4_offs_t off;
	l4_addr_t map_addr;
	l4_size_t map_size;
	l4_threadid_t dthr;

	res = l4rm_lookup((void *)page, &map_addr, &map_size, &ds, &off, &dthr);
	if (res != L4RM_REGION_DATASPACE) {
		printk("%s: Cannot get dataspace of %08lx: %s(%d).\n",
		       __func__, page, l4env_errstr(res), res);
		return -1;
	}

	if ((res = l4rm_area_attach_to_region
	             (&ds,                              /* dataspace */
	              get_area_id(address),             /* area id */
	              (void *)(address & PAGE_MASK),    /* address */
	              PAGE_SIZE,                        /* size */
	              (page & PAGE_MASK) - map_addr,    /* offset */
	              L4DM_RW | L4RM_MAP))) {
		printk("%s: Error from l4rm_attach_to_region(%lx, %lx): %s(%d)\n",
		       __func__, address, page, l4env_errstr(res), res);
		enter_kdebug("l4rm_attach_to_region failed");
		return -1;
	}
	return 0;
}

int l4lx_memory_unmap_virtual_page(unsigned long address)
{
	int res;

	if ((res = l4rm_detach((void *)address))) {
		printk("%s: Error from l4rm_detach(%08lx): %s(%d)\n",
		       __func__, address, l4env_errstr(res), res);
		enter_kdebug("l4rm_detach failed!");
		return -1;
	}
	return 0;
}

int l4lx_memory_page_mapped(unsigned long address)
{
	l4dm_dataspace_t ds;
	l4_threadid_t dthr;
	l4_offs_t off;
	l4_addr_t map_addr;
	l4_size_t map_size;

	int ret = l4rm_lookup((void *)address, &map_addr, &map_size,
	                      &ds, &off, &dthr);
	return ret != -L4_ENOTFOUND;
}
