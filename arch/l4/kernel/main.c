/*
 * Misc. file.
 *
 * This file also contains code not suited anywhere else, it will get bigger
 * and needs to be split up then.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#ifdef CONFIG_BLK_DEV_INITRD
#include <linux/initrd.h>
#endif

#include <linux/kprobes.h>

#include <asm/page.h>
#include <asm/setup.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <asm/unistd.h>
#include <asm-generic/sections.h>

#include <l4/dm_phys/dm_phys.h>
#include <l4/dm_generic/types.h>
#include <l4/env/env.h>
#include <l4/env/errno.h>
#include <l4/generic_fprov/generic_fprov-client.h>
#include <l4/generic_io/libio.h>
#include <l4/generic_ts/generic_ts.h>
#include <l4/log/l4log.h>
#include <l4/log/log_printf.h>
#include <l4/semaphore/semaphore.h>
#include <l4/sys/kdebug.h>
#include <l4/sys/syscalls.h>
#include <l4/sys/utcb.h>
#include <l4/sigma0/kip.h>
#include <l4/sigma0/sigma0.h>
#include <l4/util/cpu.h>
#include <l4/util/mbi_argv.h>
#include <l4/util/l4_macros.h>

#include <asm/api/config.h>
#include <asm/api/macros.h>

#include <asm/l4lxapi/thread.h>
#include <asm/l4lxapi/misc.h>
#include <asm/l4lxapi/task.h>

#include <asm/generic/dispatch.h>
#include <asm/generic/ferret.h>
#include <asm/generic/kthreads.h>
#include <asm/generic/memory.h>
#include <asm/generic/setup.h>
#include <asm/generic/smp.h>
#include <asm/generic/stack_id.h>
#include <asm/generic/stats.h>
#include <asm/generic/tamed.h>
#include <asm/generic/task.h> /* for l4x_id2task */
#include <asm/generic/upage.h>

#include <asm/l4x/iodb.h>
#include <asm/l4x/exception.h>
#include <asm/l4x/lx_syscalls.h>

#ifdef ARCH_x86
#include <l4/rtc/rtc.h>
#endif

#ifdef CONFIG_L4_USE_L4VMM
#include <l4/vmm/vmm.h>
#endif

l4_utcb_t *l4_utcb_l4lx_server[NR_CPUS];

#ifdef ARCH_x86
struct desc_struct cpu_gdt_table[GDT_ENTRIES];
struct Xgt_desc_struct early_gdt_descr;

unsigned l4x_fiasco_gdt_entry_offset;
struct desc_struct boot_gdt;

#ifdef CONFIG_SMP
unsigned long io_apic_irqs;
unsigned char trampoline_data [1];
unsigned char trampoline_end  [1];
#endif

#endif
#ifdef ARCH_arm
unsigned long cr_alignment;
unsigned long cr_no_alignment;
#endif

#ifdef CONFIG_SMP
unsigned int  l4x_nr_cpus = 1;
#endif

unsigned l4x_fiasco_nr_of_syscalls = 7;

char LOG_tag[9] = "l4lx";

/* Configure place for the L4RM heap, put it above our main memory
 * dataspace, so that the address space below is small.
 */
const l4_addr_t l4rm_heap_start_addr = TASK_SIZE - (4 << 20);

/* Also put thread data at the end of the address space */
const l4_addr_t l4thread_stack_area_addr = TASK_SIZE - (256 << 20);
const l4_addr_t	l4thread_tcb_table_addr  = TASK_SIZE - (260 << 20);

extern asmlinkage void start_kernel(void);

l4_threadid_t linux_server_thread_id __nosavedata = L4_NIL_ID;
l4_threadid_t l4x_start_thread_id __nosavedata = L4_NIL_ID;
l4_threadid_t l4x_start_thread_pager_id __nosavedata = L4_NIL_ID;

l4dm_dataspace_t l4env_ds_mainmem __nosavedata;
l4dm_dataspace_t l4x_ds_isa_dma __nosavedata;
static void *l4x_main_memory_start;
static void *l4x_isa_dma_memory_start;
l4_uint32_t l4env_vmalloc_areaid __nosavedata;
unsigned long l4env_vmalloc_memory_start;
l4env_infopage_t *l4env_infopage;
l4_kernel_info_t *l4lx_kinfo;
unsigned int l4x_kernel_taskno __nosavedata;

int l4x_debug_show_exceptions;
int l4x_debug_show_ghost_regions;
#ifdef CONFIG_L4_DEBUG_STATS
struct l4x_debug_stats l4x_debug_stats_data;
#endif

struct l4env_phys_virt_mem {
	l4_addr_t phys; /* physical address */
	void    * virt; /* virtual address */
	l4_size_t size; /* size of chunk in Bytes */
};

#define L4ENV_PHYS_VIRT_ADDRS_MAX_ITEMS 10

/* Default memory size */
unsigned long l4env_mainmem_size = CONFIG_L4_L4ENV_MEMSIZE << 20;
unsigned long l4x_isa_dma_size   = 2 << 20;

/* Set max amount of threads which can be created, weak symbol from
 * thread library */
const int l4thread_max_threads = 128;

static struct l4env_phys_virt_mem l4env_phys_virt_addrs[L4ENV_PHYS_VIRT_ADDRS_MAX_ITEMS] __nosavedata;
int l4env_phys_virt_addr_items;

static const unsigned long required_kernel_abi_version = 8;
static const char *required_kernel_features[] =
  { "exception_ipc",
    "pagerexregs",
#ifdef CONFIG_L4_TAMED
    "deceit_bit_disables_switch",
#endif
#ifdef ARCH_x86
    "segments",
#endif
  };

/* Only needed for environment, the Linux kernel isn't using errno */
int errno;

static void l4x_server_loop(void);

void l4env_v2p_init(void)
{
	l4env_phys_virt_addr_items = 0;
}

void l4env_v2p_add_item(l4_addr_t phys, void *virt, l4_size_t size)
{
	if (l4env_phys_virt_addr_items == L4ENV_PHYS_VIRT_ADDRS_MAX_ITEMS)
		panic("v2p filled up!");

	l4env_phys_virt_addrs[l4env_phys_virt_addr_items++]
		= (struct l4env_phys_virt_mem){.phys = phys, .virt = virt, .size = size};
}

unsigned long l4env_virt_to_phys(volatile void * address)
{
	int i;

	for (i = 0; i < l4env_phys_virt_addr_items; i++) {
		if (l4env_phys_virt_addrs[i].virt <= address &&
		    address < l4env_phys_virt_addrs[i].virt
		              + l4env_phys_virt_addrs[i].size) {
			return (address - l4env_phys_virt_addrs[i].virt)
			       + l4env_phys_virt_addrs[i].phys;
		}
	}

	/* Whitelist: */

	/* Debugging check: don't miss a translation, can give nasty
	 *                  DMA problems */
	LOG_printf("%s: Could not translate virt. address %p\n",
	           __func__, address);
	enter_kdebug("Check this!");

	return __pa(address);
}
EXPORT_SYMBOL(l4env_virt_to_phys);


void *l4env_phys_to_virt(unsigned long address)
{
	int i;

	for (i = 0; i < l4env_phys_virt_addr_items; i++) {
		if (l4env_phys_virt_addrs[i].phys <= address &&
		    address < l4env_phys_virt_addrs[i].phys
		              + l4env_phys_virt_addrs[i].size) {
			return (address - l4env_phys_virt_addrs[i].phys)
			       + l4env_phys_virt_addrs[i].virt;
		}
	}

	/* Whitelist: */
	if (address < 0x1000 ||
	    address == 0xb8000 ||
	    address == 0xa0000 ||
	    address == 0xc0000)
		return __va(address);

	/* Debugging check: don't miss a translation, can give nasty
	 *                  DMA problems */
	LOG_printf("%s: Could not translate phys. address 0x%lx\n",
	           __func__, address);
	enter_kdebug("Check this!");

	return __va(address);
}
EXPORT_SYMBOL(l4env_phys_to_virt);

/* ---------------------------------------------------------------- */

typedef void (*at_exit_function_type)(void);

struct cxa_atexit_item {
	void (*f)(void *);
	void *arg;
	void *dso_handle;
};

static struct cxa_atexit_item at_exit_functions[10];
static const int at_exit_nr_of_functions
	= sizeof(at_exit_functions) / sizeof(at_exit_functions[0]);
static int __current_exititem;

static struct cxa_atexit_item *__next_atexit(void)
{
	if (__current_exititem >= at_exit_nr_of_functions) {
		LOG_printf("WARNING: atexit array overflow, increase!\n");
		return 0;
	}
	return &at_exit_functions[__current_exititem++];
}

int __cxa_atexit(void (*f)(void *), void *arg, void *dso_handle)
{
	struct cxa_atexit_item *h = __next_atexit();

	if (!h)
		return -1;

	h->f = f;
	h->arg = arg;
	h->dso_handle = dso_handle;

	return 0;
}

void __cxa_finalize(void *dso_handle)
{
	register int i = __current_exititem;
	while (i) {
		struct cxa_atexit_item *h = &at_exit_functions[--i];
		if (h->f && (dso_handle == 0 || h->dso_handle == dso_handle)) {
			//LOG_printf("Calling func %p\n", h->f);
			h->f(h->arg);
			//LOG_printf("done calling %p.\n", h->f);
			h->f = 0;
		}
	}
}


int atexit(void (*function)(void))
{
	return __cxa_atexit((void (*)(void*))function, 0, 0);
}

/* ---------------------------------------------------------------- */

/* ----------------------------------------------------- */
/* Needed for external stuff (also for dice generated code) */
/* Do not use kmalloc here, first because kmalloc may use current and
 * the stacks of external libraries are not Linux conformable (although
 * GFP_ATOMIC may solve this), secondly kmalloc only supports up to 128k
 * allocations, which may not be enough for a generic malloc.
 * Downside of using l4dm_mem_allocatate: granularity of pages, i.e. wastes
 * memory, I need to get malloc on DSs implementation from somewhere... */
void *malloc(unsigned long size)
{
	return l4dm_mem_allocate(size, 0);
}

void free(void *ptr)
{
	l4dm_mem_release(ptr);
}

unsigned long strtoul(const char *s, char **ep, int base)
{
	return simple_strtoul(s, ep, base);
}

char *strdup(const char *s)
{
	char *p = malloc(strlen(s) + 1);
	if (p)
		strcpy(p, s);
	return p;
}

static void l4x_forward_pf(l4_umword_t addr, l4_umword_t pc)
{
	int error;
	l4_umword_t dw0, dw1;
	l4_msgdope_t result;

	do {
		error = l4_ipc_call(l4x_start_thread_pager_id,
		                    L4_IPC_SHORT_MSG, addr, pc,
				    L4_IPC_MAPMSG(addr, L4_LOG2_PAGESIZE),
				    &dw0, &dw1, L4_IPC_NEVER, &result);
	} while (error == L4_IPC_SECANCELED || error == L4_IPC_SEABORTED);

	if (unlikely(error))
		LOG_printf("Error forwarding page fault: %d\n", error);
}


/* To get mmap of /dev/mem working, map address space before
 * start of mainmem with a ro page,
 * lets try with this... */
static void l4x_mbm_request_ghost(l4dm_dataspace_t *ghost_ds)
{
	unsigned int i;
	void *addr;
	int ret;
	char page_name[15];
	static unsigned int page_nr = 0;

	snprintf(page_name, sizeof(page_name), "Ghost page %d", ++page_nr);

	/* Get a page from our dataspace manager */
	if ((ret = l4dm_mem_open(L4DM_DEFAULT_DSM, L4_PAGESIZE, L4_PAGESIZE,
				 L4DM_PINNED,
				 page_name, ghost_ds))) {
		LOG_printf("%s: Can't get ghost page: %s(%d)!\n",
			   __func__, l4env_errstr(ret), ret);
		l4x_exit_l4linux();
	}

	/* Map page RW */
	if ((ret = l4rm_attach(ghost_ds, L4_PAGESIZE, 0,
	                       L4DM_RW | L4RM_MAP, &addr))) {
		LOG_printf("%s: Can't map ghost page: %s(%d)\n",
		           __func__, l4env_errstr(ret), ret);
		l4x_exit_l4linux();
	}

	/* Write a certain value in to the page so that we can
	 * easily recognize it */
	for (i = 0; i < L4_PAGESIZE; i += sizeof(i))
		*(unsigned long *)((unsigned long)addr + i) = 0xcafeface;

	/* Detach it again */
	if ((ret = l4rm_detach(addr))) {
		LOG_printf("%s: Can't unmap ghost page: %s(%d)\n",
		           __func__, l4env_errstr(ret), ret);
		l4x_exit_l4linux();
	}

}

static void l4x_map_below_mainmem_print_region(l4_addr_t s, l4_addr_t e)
{
	if (!l4x_debug_show_ghost_regions)
		return;
	if (s == ~0UL)
		return;

	LOG_printf("Ghost region: %08lx - %08lx [%4ld]\n", s, e, (e - s) >> 12);
}

static void l4x_map_below_mainmem(void)
{
	unsigned long i;
	l4dm_dataspace_t ds, ghost_ds;
	l4_threadid_t dthr;
	l4_offs_t off;
	l4_addr_t map_addr;
	l4_size_t map_size;
	int ret;
	unsigned long i_inc;
	int map_count = 0, map_count_all = 0;
	l4_addr_t reg_start = ~0UL;

	LOG_printf("Filling lower ptabs...\n");
	LOG_flush();

	/* Loop through free address space before mainmem */
	for (i = L4_PAGESIZE; i < (unsigned long)l4x_main_memory_start; i += i_inc) {
		ret = l4rm_lookup((void *)i, &map_addr, &map_size,
		                  &ds, &off, &dthr);
		if (ret > 0) {
			// success, something there
			if (i != map_addr)
				enter_kdebug("shouldn't be, hmm?");
			i_inc = map_size;
			l4x_map_below_mainmem_print_region(reg_start, i);
			reg_start = ~0UL;
			continue;
		}

		if (reg_start == ~0UL)
			reg_start = i;

		i_inc = L4_PAGESIZE;

		if (ret != -L4_ENOTFOUND) {
			LOG_printf("l4rm_lookup call failure: %s(%d)\n",
			           l4env_errstr(ret), ret);
			l4x_exit_l4linux();
		}

		if (!map_count) {
			/* Get new ghost page every 1024 mappings
			 * to overcome a Fiasco mapping db
			 * limitation. */
			l4x_mbm_request_ghost(&ghost_ds);
			map_count = 1014;
		}
		map_count--;
		map_count_all++;
		ret = l4rm_attach_to_region(&ghost_ds, (void *)i,
		                            L4_PAGESIZE, 0, L4DM_RO | L4RM_MAP);
		if (ret) {
			LOG_printf("%s: Can't attach to ghost page: %s(%d)!\n",
			           __func__, l4env_errstr(ret), ret);
			l4x_exit_l4linux();
		}
	}
	l4x_map_below_mainmem_print_region(reg_start, i);
	LOG_printf("Done (%d entries).\n", map_count_all);
	LOG_flush();

	/* Touch page so that we get the PF now */
	for (i = L4_PAGESIZE; i < (unsigned long)l4x_main_memory_start;
	     i += L4_PAGESIZE)
		l4x_forward_pf(i, 0);
}

/* map upage to UPAGE_USER_ADDRESS in linux server itself */
static void l4x_map_upage_myself(void)
{
	int ret;
	l4dm_dataspace_t ds;
	l4_offs_t off;
	l4_addr_t map_addr;
	l4_size_t map_size;
	l4_threadid_t dthr;

	if ((ret = l4rm_lookup((void *)&_upage_start,
		               &map_addr, &map_size, &ds, &off, &dthr))
	    != L4RM_REGION_DATASPACE) {
		LOG_printf("Cannot get dataspace of upage (%s(%d))",
		           l4env_errstr(ret), ret);
		enter_kdebug("get ds of upage");
	}

	if ((ret = l4rm_attach_to_region(&ds, (void *)UPAGE_USER_ADDRESS,
	                                 L4_PAGESIZE, off,
	                                 L4DM_RO | L4RM_MAP))) {
		LOG_printf("Cannot attach upage properly: (%s(%d))",
		           l4env_errstr(ret), ret);
		enter_kdebug("attach upage");
	}
}

static void l4env_register_region(void *start, l4_size_t size,
                                  int allow_noncontig, const char *tag)
{
	const int num_addrs = 8;
	l4dm_mem_addr_t phys_addrs[num_addrs];
	l4_size_t phys_addrs_size;
	l4_offs_t offset;
	int pas, i;

	LOG_printf("%15s: virt: %p to %p [%u KiB]\n",
	           tag, start, start + size - 1, size >> 10);

	if ((pas = l4dm_mem_phys_addr(start, size,
	                              phys_addrs, num_addrs,
	                              &phys_addrs_size)) < 0) {
		LOG_printf("Error getting physical addresses for \"%s\" "
		           "(err = %s(%d)!", tag, l4env_errstr(pas), pas);
		l4x_exit_l4linux();
	}

	/* Debugging msgs, handle this carefully */
	if (!allow_noncontig && pas > 1) {
		LOG_printf("Noncontiguous region for %s\n", tag);
		/* enter_kdebug("Noncontinuous region!"); */
	}
	if (pas == num_addrs) {
		LOG_printf("Probably region overflow for %s?!\n", tag);
		l4_sleep(10000);
	}


	LOG_printf("%15s: Number of physical regions: %d, %u Bytes\n",
	           tag, pas, phys_addrs_size);

	offset = 0;
	for (i = 0; i < pas; i++) {
		l4env_v2p_add_item(phys_addrs[i].addr,
		                   start + offset,
		                   phys_addrs[i].size);

		LOG_printf("%15s: %d: Phys: 0x%08lx to 0x%08lx, Size: %8u\n",
		           tag, i+1, phys_addrs[i].addr,
		           phys_addrs[i].addr + phys_addrs[i].size,
		           phys_addrs[i].size);
		//LOG_printf("%s: Offset to virtual: 0x%08x\n", tag,
		//	   phys_addrs[i].addr - (unsigned long)start);
		offset += phys_addrs[i].size;
	}
}

/*
 * Register program section(s) for virt_to_phys, at least initdata is used
 * as normal storage later (including DMA usage).
 *
 * Note: we just register the dataspace region where __init_begin is in for
 *       now
 * Note2:
 */
static void l4env_register_pointer_section(void *p_in_addr,
                                           int allow_noncontig,
                                           const char *tag)
{
	l4dm_dataspace_t ds;
	l4_offs_t off;
	l4_addr_t addr;
	l4_size_t size;
	l4_threadid_t dthr;
	int res;

	if ((res = l4rm_lookup(p_in_addr, &addr, &size, &ds, &off, &dthr))
	    != L4RM_REGION_DATASPACE) {
		LOG_printf("Cannot find dataspace at %p?!"
		           "(err = %s(%d))\n", p_in_addr,
		           l4env_errstr(res), res);
		enter_kdebug("l4rm_lookup failed");
		return;
	}

	LOG_printf("%s: addr = %08lx size = %d\n", __func__, addr, size);

	l4env_register_region((void *)addr, size, allow_noncontig, tag);
}

void setup_l4env_memory(char *cmdl,
                        unsigned long *main_mem_start,
                        unsigned long *main_mem_size,
                        unsigned long *isa_dma_mem_start,
                        unsigned long *isa_dma_mem_size)
{
	int res;
	char *memstr;
	unsigned long memory_area_size;
	l4_uint32_t memory_area_id;
	l4_addr_t memory_area_addr;
	l4_size_t poolsize, poolfree;
#ifdef ARCH_x86
	extern unsigned long init_pg_tables_end;
#endif
	l4_uint32_t dm_flags = L4DM_CONTIGUOUS | L4DM_PINNED;
	l4_uint32_t rm_flags = L4DM_RW;

	/* See if we find a mem=xxx option in the command line */
	if ((memstr = strstr(cmdl, "mem="))
	    && (res = memparse(memstr + 4, &memstr)))
		l4env_mainmem_size = res;

	/* Make sure that main memory starts at a new superpage. If dm_phys
	 * (accidently) allocates our memory starting at a superpage in his
	 * address space, we get L4_SUPERPAGE_SIZE mappings. */
	rm_flags |= L4RM_SUPERPAGE_ALIGNED;

	if ((l4env_mainmem_size % L4_SUPERPAGESIZE) == 0) {
		LOG_printf("%s: Forcing superpages for main memory\n", __func__);
		/* force dm_phys to allocate superpages */
		dm_flags |= L4DM_MEMPHYS_SUPERPAGES;
		rm_flags |= L4DM_MEMPHYS_SUPERPAGES;
	}

	/* Allocate main memory */
	if ((res = l4dm_mem_open(L4DM_DEFAULT_DSM, l4env_mainmem_size,
	                         L4_PAGESIZE, dm_flags,
	                         "L4Linux main memory", &l4env_ds_mainmem))) {
		LOG_printf("%s: Can't get main memory of %ldMB: %s(%d)!\n",
		           __func__, l4env_mainmem_size >> 20,
		           l4env_errstr(res), res);
		l4dm_memphys_show_pools();
		l4dm_ds_list_all(L4DM_DEFAULT_DSM);
		l4x_exit_l4linux();
	}

	/* if there's a '+' at the end of the mem=-option try to get
	 * more memory */
	if (memstr && *memstr == '+') {
		unsigned long chunksize = 64 << 20;

		while (chunksize > (4 << 20)) {
			if ((res = l4dm_mem_resize(&l4env_ds_mainmem,
						   l4env_mainmem_size
			                           + chunksize)))
				chunksize >>= 1; /* failed */
			else
				l4env_mainmem_size += chunksize;
		}
	}

	LOG_printf("Main memory size: %ldMB\n", l4env_mainmem_size >> 20);
	if (l4env_mainmem_size < (4 << 20)) {
		LOG_printf("Not enough main memory!\n");
		l4x_exit_l4linux();
	}

	memory_area_size = l4env_mainmem_size;

	/* Try to get ISA DMA memory */

	/* See if we find a memisadma=xxx option in the command line */
	if ((memstr = strstr(cmdl, "memisadma=")))
		l4x_isa_dma_size = memparse(memstr + 10, &memstr);

	/** In the default config dm_phys prints out messages if
	 ** the allocation fails, so query the size separately to
	 ** not disturb users with error messages */
	if (l4x_isa_dma_size
	    && (res = l4dm_memphys_poolsize(L4DM_MEMPHYS_ISA_DMA,
	                                    &poolsize, &poolfree))) {
		LOG_printf("Cannot query ISA DMA pool size: %s(%d)\n",
		           l4env_errstr(res), res);
		l4x_exit_l4linux();
	}
	if (l4x_isa_dma_size
	    && poolfree >= l4x_isa_dma_size
	    && !l4dm_memphys_open(L4DM_MEMPHYS_ISA_DMA,
	                          L4DM_MEMPHYS_ANY_ADDR,
	                          l4x_isa_dma_size, L4_PAGESIZE,
	                          L4DM_CONTIGUOUS, "L4Linux ISA DMA memory",
	                          &l4x_ds_isa_dma)) {
		LOG_printf("Got %lukB of ISA DMA memory.\n",
		           l4x_isa_dma_size >> 10);
		memory_area_size += l4_round_superpage(l4x_isa_dma_size);
	} else
		l4x_ds_isa_dma = L4DM_INVALID_DATASPACE;

	/* Get contiguous region in our virtual address space to put
	 * the dataspaces in */
	if (l4rm_area_reserve(memory_area_size, L4RM_SUPERPAGE_ALIGNED,
			      &memory_area_addr, &memory_area_id)) {
		LOG_printf("Error reserving memory area: %s(%d)\n",
		           l4env_errstr(res), res);
		l4x_exit_l4linux();
	}

	/* Attach data spaces to local address space */
	/** First: the ISA DMA memory */
	if (!l4dm_is_invalid_ds(l4x_ds_isa_dma)) {
		l4x_isa_dma_memory_start = (void *)memory_area_addr;
		l4x_main_memory_start =
			(void *)(l4x_isa_dma_memory_start
		                 + l4_round_superpage(l4x_isa_dma_size));
		if ((res = l4rm_area_attach_to_region(&l4x_ds_isa_dma,
	                                              memory_area_id,
	                                              l4x_isa_dma_memory_start,
	                                              l4x_isa_dma_size, 0,
	                                              L4DM_RW | L4RM_MAP))) {
			LOG_printf("Error attaching to ISA DMA memory: %s(%d)\n",
				   l4env_errstr(res), res);
			l4x_exit_l4linux();
		}
	} else
		l4x_main_memory_start = (void *)memory_area_addr;

	/** Second: the main memory */
	if ((res = l4rm_area_attach_to_region(&l4env_ds_mainmem,
	                                      memory_area_id,
	                                      l4x_main_memory_start,
	                                      l4env_mainmem_size, 0,
	                                      rm_flags | L4RM_MAP))) {
		LOG_printf("Error attaching to L4Linux main memory: %s(%d)\n",
		           l4env_errstr(res), res);
		l4x_exit_l4linux();
	}

	/* Release area ... make possible hole available again */
	if ((res = l4rm_area_release(memory_area_id))) {
		LOG_printf("Error releasing area: %s(%d)\n",
		           l4env_errstr(res), res);
		l4x_exit_l4linux();
	}

	*main_mem_start = (unsigned long)l4x_main_memory_start;
	*main_mem_size  = l4env_mainmem_size;

	if (l4dm_is_invalid_ds(l4x_ds_isa_dma))
		*isa_dma_mem_start = *isa_dma_mem_size = 0;
	else {
		*isa_dma_mem_start = (unsigned long)l4x_isa_dma_memory_start;
		*isa_dma_mem_size  = l4x_isa_dma_size;
	}

#ifdef ARCH_x86
	init_pg_tables_end = memory_area_addr;
#endif

	if (!l4dm_is_invalid_ds(l4x_ds_isa_dma))
		l4env_register_region(l4x_isa_dma_memory_start, l4x_isa_dma_size,
		                      0, "ISA DMA memory");
	l4env_register_region(l4x_main_memory_start, l4env_mainmem_size,
	                      0, "Main memory");

	/* Reserve some part of the virtual address space for vmalloc */
	if ((res = l4rm_area_reserve(
#ifdef ARCH_x86
	                             __VMALLOC_RESERVE,
#else
	                             VMALLOC_SIZE << 20,
#endif
	                             L4RM_LOG2_ALIGNED,
	                             (l4_addr_t *)&l4env_vmalloc_memory_start,
				     &l4env_vmalloc_areaid))) {
		LOG_printf("%s: Error reserving vmalloc memory: %s(%d)!\n",
		           __func__, l4env_errstr(res), res);
		l4x_exit_l4linux();
	}

	l4x_map_below_mainmem();
}

unsigned long l4x_get_isa_dma_memory_end(void)
{
	return (unsigned long)l4x_isa_dma_memory_start + l4x_isa_dma_size;
}

void l4x_setup_thread_stack(void)
{
	struct thread_info *ti = current_thread_info();

	// XXX only call on CPU0!
	BUG_ON(smp_processor_id());

	*ti = (struct thread_info) INIT_THREAD_INFO(init_task);
	ti->task->stack = ti;

	l4x_stack_setup(ti);
}

#ifdef CONFIG_SMP

static l4_threadid_t l4x_cpu_threads[NR_CPUS];
static struct task_struct *l4x_cpu_idler[NR_CPUS] = { &init_task, 0, };

l4_threadid_t l4x_cpu_thread_get(int cpu)
{
	BUG_ON(cpu >= NR_CPUS);
	return l4x_cpu_threads[cpu];
}

#ifdef ARCH_arm
int l4x_cpu_cpu_get(void)
{
	int i = 0;
	l4_threadid_t id = l4_myself();

	for (; i < NR_CPUS; i++)
		if (l4_thread_equal(id, l4x_cpu_threads[i]))
			return i;

	BUG();
}
#endif

static void l4x_cpu_thread_set(int cpu, l4_threadid_t tid)
{
	BUG_ON(cpu >= NR_CPUS);
	l4x_cpu_threads[cpu] = tid;
}

void l4x_smp_update_task(struct task_struct *p, int new_cpu)
{
	l4x_stack_struct_get(task_stack_page(p))->id
	  = l4x_cpu_thread_get(new_cpu);

	p->thread.user_thread_id = p->thread.user_thread_ids[new_cpu];
}

struct task_struct *l4x_cpu_idle_get(int cpu)
{
	BUG_ON(cpu >= NR_CPUS);
	return l4x_cpu_idler[cpu];
}

#ifdef ARCH_x86
void l4x_load_percpu_gdt_descriptor(struct desc_struct *gdt)
{
	fiasco_gdt_set(&gdt[GDT_ENTRY_PERCPU], 8, 0, l4_myself());
	asm("mov %0, %%fs"
	    : : "r" (l4x_fiasco_gdt_entry_offset * 8 + 3) : "memory");
}
#endif

static void __cpu_starter(void *x)
{
	l4_umword_t cpu;
	int error;
	l4_msgdope_t dope;

	error = l4_ipc_receive(l4x_cpu_thread_get(0), L4_IPC_SHORT_MSG,
	                       &cpu, &cpu, L4_IPC_NEVER, &dope);
	BUG_ON(error);

	l4lx_thread_pager_change(l4_myself(), l4x_start_thread_id);
	l4_utcb_set_l4lx(cpu, l4_utcb_get());
	l4_utcb_inherit_fpu(l4_utcb_get(), 1);

#ifdef ARCH_x86
	l4x_load_percpu_gdt_descriptor((struct desc_struct *)early_gdt_descr.address);
	asm volatile ("jmp initialize_secondary");
#endif
#ifdef ARCH_arm
	asm volatile ("b l4x_secondary_start_kernel");
#endif
	panic("CPU startup failed");
}

//static char smp_init_stack[L4LX_THREAD_STACK_SIZE];

void l4x_cpu_spawn(int cpu, struct task_struct *idle)
{
	char s[8];

	BUG_ON(cpu >= NR_CPUS);

	l4x_tamed_set_mapping(cpu, 0);

	snprintf(s, sizeof(s), "cpu%d", cpu);
	s[sizeof(s)-1] = 0;

	//LOG_printf("Launching %s at %p\n", s, __cpu_starter);
	l4x_cpu_threads[cpu] = l4lx_thread_create
		(__cpu_starter, NULL, NULL, 0, CONFIG_L4_PRIO_SERVER, s);

	l4x_cpu_idler[cpu] = idle;

	//LOG_printf("CPU%d is thread " l4util_idfmt " (%s(%d))\n",
	 //         cpu, l4util_idstr(l4x_cpu_threads[cpu]),
	//	   idle->comm, idle->pid);
}

void l4x_cpu_release(int cpu)
{
	int error;
	l4_msgdope_t dope;

	error = l4_ipc_send(l4x_cpu_thread_get(cpu), L4_IPC_SHORT_MSG,
	                    cpu, cpu, L4_IPC_NEVER, &dope);
	if (error)
		LOG_printf("Failed to release CPU%d; ipc error %d\n",
		           cpu, error);
}

unsigned long l4x_IPI_pending_mask;

static DEFINE_PER_CPU(unsigned long, l4x_ipi_vector_pending_mask);

void l4x_send_IPI_mask_bitmask(unsigned long mask, int vector)
{
	int cpu, error;
	l4_msgdope_t dope;

	// XXX NR_CPUS must be <= 32
	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		if (!(mask & (1 << cpu)))
			continue;

		l4x_IPI_pending_set(cpu);

		set_bit(vector, &per_cpu(l4x_ipi_vector_pending_mask, cpu));

		error = l4_ipc_send(l4x_cpu_thread_get(cpu), L4_IPC_SHORT_MSG,
		                    L4X_IPI_MESSAGE, 0,
		                    L4_IPC_BOTH_TIMEOUT_0, &dope);
		if (error && error != 0x30)
			LOG_printf("%s: IPC error %x\n", __func__, error);
	}
}

#ifdef ARCH_x86
void do_l4x_smp_process_IPI(void)
{
	int cpu = smp_processor_id();
	int done = 0;

	if (test_and_clear_bit(RESCHEDULE_VECTOR,
	                       &per_cpu(l4x_ipi_vector_pending_mask, cpu))) {
		extern fastcall void smp_reschedule_interrupt(struct pt_regs *regs);
		// actually this function is empty
		smp_reschedule_interrupt(NULL);
		done = 1;
	}

	if (test_and_clear_bit(CALL_FUNCTION_VECTOR,
	                       &per_cpu(l4x_ipi_vector_pending_mask, cpu))) {
		extern fastcall void smp_call_function_interrupt(struct pt_regs *);
		smp_call_function_interrupt(NULL);
		done = 1;
	}

	if (test_and_clear_bit(L4X_TIMER_VECTOR,
	                       &per_cpu(l4x_ipi_vector_pending_mask, cpu))) {
		extern void l4x_smp_timer_interrupt(void);
		l4x_smp_timer_interrupt();
		done = 1;
	}

	if (done)
		return;

	if (!per_cpu(l4x_ipi_vector_pending_mask, cpu)) {
		LOG_printf("No IPI pending on cpu%d\n", cpu);
		return;
	}
	LOG_printf("Received unknown IPI vector: %lx\n",
	           per_cpu(l4x_ipi_vector_pending_mask, cpu));
	enter_kdebug("unknown IPI vector");
}
#endif

void __cpuinit check_tsc_sync_source(int cpu)
{
	LOG_printf("%s(%d)\n", __func__, cpu);
}


//----------------------
// repnop start
l4_threadid_t l4x_repnop_id;

static char l4x_repnop_stack[L4LX_THREAD_STACK_SIZE];

static void l4x_repnop_thread(void *d)
{
	l4_threadid_t id;
	l4_umword_t data;
	l4_msgdope_t result;
	int error;

	error = l4_ipc_wait(&id,
	                    L4_IPC_SHORT_MSG, &data, &data,
	                    L4_IPC_SEND_TIMEOUT_0, &result);
	while (1) {
		outchar('@');
		if (error)
			LOG_printf("%s: IPC error = %x\n", __func__, error);

		l4_yield();

		error = l4_ipc_reply_and_wait(id, L4_IPC_SHORT_MSG_NODONATE,
		                              0, 0, &id,
		                              L4_IPC_SHORT_MSG,
		                              &data, &data,
		                              L4_IPC_SEND_TIMEOUT_0,
		                              &result);
	}
}

void l4x_rep_nop(void)
{
	l4_msgdope_t result;
	l4_umword_t d;
	int e;

	e = l4_ipc_call(l4x_repnop_id, L4_IPC_SHORT_MSG_NODONATE, 0, 0,
	                L4_IPC_SHORT_MSG, &d, &d, L4_IPC_NEVER, &result);
	BUG_ON(e);
}

static void l4x_repnop_init(void)
{
	l4x_repnop_id = l4lx_thread_create(l4x_repnop_thread,
	                                   l4x_repnop_stack
	                                     + sizeof(l4x_repnop_stack),
	                                   NULL, 0,
	                                   CONFIG_L4_PRIO_SERVER,
	                                   "nop");
}
// repnop end
// ---------------

#else
static inline void l4x_cpu_thread_set(int cpu, l4_threadid_t tid) {}
static inline void l4x_repnop_init(void) {}
#endif


#ifdef CONFIG_PCI
#ifdef CONFIG_X86_IO_APIC
void __init check_acpi_pci(void)
{}
#endif
#endif

/*
 * This is the panic blinking function, we misuse it to sleep forever.
 */
static long l4x_blink(long time)
{
	printk("panic: going to sleep forever, bye\n");
	LOG_printf("panic: going to sleep forever, bye\n");
	l4_sleep_forever();
	return 0;
}

static void l4env_linux_startup(void *data)
{
	l4_threadid_t caller_id = *(l4_threadid_t *)data;
	l4_msgdope_t result;
	l4_umword_t w;

	LOG_printf("%s thread %x.\n", __func__, l4_myself().id.lthread);

	/* Wait for start signal */
	l4_ipc_receive(caller_id, L4_IPC_SHORT_MSG,
	               &w, &w, L4_IPC_NEVER, &result);

	LOG_printf("main thread: received startup message.\n");

	linux_server_thread_id = l4_myself();

	l4lx_thread_pager_change(linux_server_thread_id, caller_id);

	l4_utcb_set_l4lx(0, l4_utcb_get());
	l4_utcb_inherit_fpu(l4_utcb_get(), 1);
#ifdef ARCH_x86
	asm volatile("movl %%ds,  %%eax \n"
	             "movl %%eax, %%fs  \n"  // fs == ds
		     "xorl %%eax, %%eax \n"
		     "movl %%eax, %%gs  \n"  // clear gs
		     : : : "eax", "memory");
#endif
	l4x_setup_thread_stack();

	panic_blink = l4x_blink;

	start_kernel();
}

static l4io_info_t _l4x_io_info_page;

l4io_info_t *l4x_l4io_info_page(void)
{
	return &_l4x_io_info_page;
}

void l4x_l4io_init(void)
{
	l4io_info_t *io_info_page = (void *)0;

	/* io clientlib flexpages into our BSS, if we rerequest mappings
	 * from our pager this mapping will disappear, as we only need the
	 * static data on the io page we just copy it */

	LOG_printf("Connecting to l4io server.\n");

	/* initialize IO lib */
	if (l4io_init(&io_info_page, L4IO_DRV_INVALID))
		enter_kdebug("Error calling l4io_init!");

	memcpy(&_l4x_io_info_page, io_info_page, sizeof(l4io_info_t));
}

#ifdef CONFIG_BLK_DEV_INITRD
static l4dm_dataspace_t l4env_initrd_ds;
static unsigned long l4env_initrd_mem_start;

/**
 * Get the RAM disk from the file provider!
 *
 * \param filename    File name in the form {(nd)}/path/to/file
 * \param *rd_start   Start of ramdisk
 * \param *rd_end     End of ramdisk
 *
 * \return 0 on succes, != 0 otherwise
 */
static int fprov_load_initrd(const char *filename,
                             unsigned long *rd_start,
                             unsigned long *rd_end)
{
	int error;
	l4_size_t size;
	DICE_DECLARE_ENV(env);

	if (l4_thread_equal(l4env_infopage->fprov_id, L4_INVALID_ID)) {
		LOG_printf("File provider not set!\n");
		enter_kdebug("ATT!");
		return 1;
	}

	/* load RAM disk to DS */
	if ((error = l4fprov_file_open_call
	              (&l4env_infopage->fprov_id,
	               filename,
	               &l4env_infopage->memserv_id,
	               L4DM_CONTIGUOUS,
	               &l4env_initrd_ds,
	               &size,
	               &env))) {
		LOG_flush();
		LOG_printf("Couldn't load RAM disk from fprov!\n");
		enter_kdebug("ATT");
		return error;
	}
	LOG_printf("INITRD: Size of RAMdisk is %dKiB\n", size >> 10);
	LOG_flush();

	/* attach DS to region mapper */
	if ((error = l4rm_attach(&l4env_initrd_ds,
	                         size,
	                         0,
	                         L4DM_RW,
	                         (void **)rd_start))) {
		LOG_flush();
		LOG_printf("Couldn't attach RAM disk memory! err=%d\n", error);
		enter_kdebug("ATT");
		return error;
	}

	l4env_initrd_mem_start = *rd_start;
	*rd_end = *rd_start + size;
	printk("INITRD: %08lx - %08lx\n", *rd_start, *rd_end);

	if (size * 2 > l4env_mainmem_size) {
		LOG_printf("WARNING: RAMdisk size of %dMB probably too big\n"
		           "for %ldMB main memory. Sleeping a bit...\n",
		           size >> 20, l4env_mainmem_size >> 20);
		l4_sleep(20000);
	}

	LOG_flush();

	return 0;
}

/**
 * Free InitRD memory.
 */
void l4env_free_initrd_mem(void)
{
	printk("INITRD: Freeing memory.\n"); LOG_flush();

	/* detach memory */
	if (l4rm_detach((void *)l4env_initrd_mem_start))
		enter_kdebug("Error detaching from initrd mem!");

	/* close DS and free mem */
	if (l4dm_close(&l4env_initrd_ds))
		enter_kdebug("Error closing initrd ds!");
}


#define L4ENV_MAX_RD_PATH 200
static char l4env_rd_path[L4ENV_MAX_RD_PATH];

void l4env_load_initrd(char *command_line)
{
	char *sa, *se;
	char param_str[] = "l4env_rd=";
	int i, b;

	sa = command_line;
	while (*sa) {
		for (i = 0, b = 1; param_str[i] && b; i++)
			b = sa[i] == param_str[i];
		if (b)
			break;
		sa++;
	}
	if (*sa) {
		sa += strlen(param_str);
		se = sa;

		while (*se && *se != ' ')
			se++;
		if (se - sa > L4ENV_MAX_RD_PATH) {
			enter_kdebug("l4env_rd_path > L4ENV_MAX_RD_PATH");
			return;
		}
		strncpy(l4env_rd_path, sa, se - sa);
		LOG_printf("l4env_rd_path: %s\n", l4env_rd_path);
	}

	if (l4env_rd_path && *l4env_rd_path) {
		LOG_printf("Loading: %s\n", l4env_rd_path);

		if (fprov_load_initrd(l4env_rd_path,
		                      &initrd_start,
		                      &initrd_end)) {
			LOG_flush();
			LOG_printf("Couldn't load ramdisk :(\n");
			return;
		}

		initrd_below_start_ok = 1;

		//reserve_bootmem(initrd_start, initrd_end - initrd_start);

		LOG_printf("RAMdisk from %08lx to %08lx [%ldKiB]\n",
		           initrd_start, initrd_end,
		           (initrd_end - initrd_start) >> 10);
	}
}
#endif /* CONFIG_BLK_DEV_INITRD */

static void get_initial_cpu_capabilities(void)
{
#ifdef ARCH_x86
	/* new_cpu_data is filled into boot_cpu_data in setup_arch */
	extern struct cpuinfo_x86 new_cpu_data;
	new_cpu_data.x86_capability[0] = l4util_cpu_capabilities();
#endif
}

#ifdef CONFIG_L4_USE_L4VMM
static l4vmm_config_t l4vmm_config = {
	.flags             = L4VMM_DEFAULT_FLAGS,
	.phys_to_virt_func = (l4_addr_t (*)(l4_addr_t))&l4env_phys_to_virt,
};
#endif

static void l4x_l4vmm_init(void)
{
#ifdef CONFIG_L4_USE_L4VMM
	char s[128];
	char *p;

	if ((p = strstr(boot_command_line, "l4vmm_config="))) {
		char *e;
		int l;

		p += 13;

		if ((e = strchr(p, ' ')))
			l = e - p;
		else
			l = strlen(p);

		if (l > sizeof(s) - 1) {
			LOG_printf("l4vmm: configuration path too long, "
			           "doing without config.\n");
		} else {
			memcpy(s, p, l);
			s[l] = 0;
			l4vmm_config.str = s;
			l4vmm_config.flags |= L4VMM_INIT_STR_FILE;
		}
	}

	l4vmm_init(&l4vmm_config);
#endif
}

int main(int argc, char **argv)
{
	l4_threadid_t main_id;
	l4_msgdope_t result;
	extern char _end[];
	extern char boot_command_line[];
	unsigned i;
	char *p;

	LOG_printf("\033[34;1m======> L4Linux 2.6 starting... <========\033[0m\n");
	LOG_printf("%s", linux_banner);
	LOG_printf("Binary name: %s\n", (*argv)?*argv:"NULL??");

	argv++;
	p = boot_command_line;
	while (*argv) {
		i = strlen(*argv);
		if (p - boot_command_line + i >= COMMAND_LINE_SIZE) {
			LOG_printf("Command line too long!");
			enter_kdebug("Command line too long!");
		}
		strcpy(p, *argv);
		p += i;
		if (*++argv)
			*p++ = ' ';
	}
	LOG_printf("Kernel command line (%d args): %s\n",
	           argc - 1, boot_command_line);

	if (strstr(boot_command_line, "noreplacement")) {
		LOG_printf("Do not use the 'noreplacement' option "
		           "or strange things may happen.\n");
		enter_kdebug("noreplacement option found");
	}

	/* See if we find a showpfexc=1 or showghost=1 in the command line */
	if ((p = strstr(boot_command_line, "showpfexc=")))
		l4x_debug_show_exceptions = simple_strtoul(p+10, NULL, 0);
	if ((p = strstr(boot_command_line, "showghost=")))
		l4x_debug_show_ghost_regions = simple_strtoul(p+10, NULL, 0);

	l4lx_kinfo = l4sigma0_kip_map(L4_INVALID_ID);

	for (i = 0; i < sizeof(required_kernel_features)
		          / sizeof(required_kernel_features[0]); i++) {
		if (!l4sigma0_kip_kernel_has_feature(required_kernel_features[i])) {
			LOG_printf("The running kernel does not have the\n"
			           "      %s\n"
			           "feature enabled!\n",
			           required_kernel_features[i]);
			enter_kdebug("kernel feature missing!");
		}
	}

	if (l4sigma0_kip_kernel_abi_version() < required_kernel_abi_version) {
		LOG_printf("The kernel ABI version is too low: kernel has %ld, "
		           "I need %ld\n",
		           l4sigma0_kip_kernel_abi_version(),
		           required_kernel_abi_version);
		enter_kdebug("Stop!");
	}

	if (l4sigma0_kip_kernel_has_feature("pl0_hack"))
		l4x_fiasco_nr_of_syscalls += 2;

	if ((l4env_infopage = l4env_get_infopage()) == NULL) {
		LOG_printf("Couldn't get L4Env info page!\n");
		enter_kdebug("Stop!");
		return 1;
	}

	if (l4env_infopage->magic != L4ENV_INFOPAGE_MAGIC) {
		LOG_printf("L4Env infopage invalid!\n");
		enter_kdebug("Stop!");
		return 1;
	}

#ifdef CONFIG_SMP
	if ((p = strstr(boot_command_line, "l4x_cpus="))) {
		l4x_nr_cpus = simple_strtoul(p + 9, NULL, 0);
		if (l4x_nr_cpus > NR_CPUS) {
			LOG_printf("Linux only configured for max. %d CPUs. Limited to %d.\n",
			           NR_CPUS, NR_CPUS);
			l4x_nr_cpus = NR_CPUS;
		}
	}
#endif

	l4x_l4vmm_init();

	LOG_printf("Image: %08lx - %08lx [%lu KiB].\n",
	           (unsigned long)_stext, (unsigned long)_end,
	           (unsigned long)(_end - _stext + 1) >> 10);

	LOG_printf("Areas: Text:     %08lx - %08lx [%ldkB] (a bit longer)\n",
	           (unsigned long)&_stext, (unsigned long)&_sdata,
	           ((unsigned long)&_sdata - (unsigned long)&_stext) >> 10);
	LOG_printf("       Data:     %08lx - %08lx [%ldkB]\n",
	           (unsigned long)&_sdata, (unsigned long)&_edata,
	           ((unsigned long)&_edata - (unsigned long)&_sdata) >> 10);
	LOG_printf("       Initdata: %08lx - %08lx [%ldkB]\n",
	           (unsigned long)&__init_begin, (unsigned long)&__init_end,
	           ((unsigned long)&__init_end - (unsigned long)&__init_begin) >> 10);
	LOG_printf("       BSS:      %08lx - %08lx [%ldkB]\n",
	           (unsigned long)&__bss_start, (unsigned long)&__bss_stop,
	           ((unsigned long)&__bss_stop - (unsigned long)&__bss_start) >> 10);

	/* Touch areas to avoid pagefaults
	 * Data needs to be touched rw, code ro
	 */
	l4_touch_ro(&_stext, (unsigned long)&_sdata - (unsigned long)&_stext);
	l4_touch_rw(&_sdata, (unsigned long)&_edata - (unsigned long)&_sdata);
	l4_touch_ro(&__init_begin,
	            (unsigned long)&__init_end - (unsigned long)&__init_begin);
	l4_touch_rw(&__bss_start,
	            (unsigned long)&__bss_stop - (unsigned long)&__bss_start);

	/* some things from head.S */
	get_initial_cpu_capabilities();

	/* This is not the final try to set linux_server_thread_id
	 * but l4lx_thread_create needs some initial data for the return
	 * value... */
	linux_server_thread_id = l4_myself();

	/* Init v2p list */
	l4env_v2p_init();

	l4x_start_thread_id = l4_myself();
	l4x_start_thread_pager_id = l4_thread_ex_regs_pager(l4x_start_thread_id);
	l4x_kernel_taskno = l4x_start_thread_id.id.task;

#ifdef CONFIG_L4_TAMED
	l4x_tamed_init(0);
#endif
	l4x_repnop_init();

#ifdef ARCH_x86
	if (l4sigma0_kip_kernel_has_feature("io_prot")) {
#ifndef CONFIG_L4_TAMED
		enter_kdebug("ioprot-kernel -> enable TAMED mode!");
#endif
		l4x_iodb_init();
	}

	/* Initialize GDT entry offset */
	l4x_fiasco_gdt_entry_offset = fiasco_gdt_get_entry_offset();

	l4env_v2p_add_item(0xa0000, (void *)0xa0000, 0xfffff - 0xa0000);

#ifdef CONFIG_L4_FERRET
	l4x_ferret_init();
#endif

	/* Make sure RTC is ready */
	{
		l4_uint32_t seconds;

		i = 10;
		while (--i && l4rtc_get_seconds_since_1970(&seconds))
			l4_sleep(100);
		if (i == 0)
			LOG_printf("WARNING: RTC server does not respond!\n");
	}

#endif /* ARCH_x86 */

	l4x_l4io_init();

	/* Set name of startup thread */
	l4lx_thread_name_set(l4x_start_thread_id, "l4env-start");

	/* fire up Linux server, will wait until start message */
	main_id = l4lx_thread_create(l4env_linux_startup,
	                             (char *)init_stack + sizeof(init_stack),
	                             &l4x_start_thread_id,
	                             sizeof(l4x_start_thread_id),
	                             CONFIG_L4_PRIO_SERVER,
	                             "cpu0");

	l4x_cpu_thread_set(0, main_id);

	LOG_printf("main thread will be " PRINTF_L4TASK_FORM "\n",
	           PRINTF_L4TASK_ARG(main_id));

	l4env_register_pointer_section(&__init_begin, 0, "sec-w-init");

	/* The next are not necessary as no-one has done virt_to_phys
	 * for these areas so far */
	//l4env_register_pointer_section(&_text,  1, "text");
	//l4env_register_pointer_section(&_edata, 0, "data");

	/* We do this here in the startup thread as we only have the right
	 * to do it here, if we want to do that in the main thread, we'd
	 * have to first share it here. */
	l4x_map_upage_myself();

	/* Send start message to main thread. */
	l4_ipc_send(main_id, L4_IPC_SHORT_MSG, 0, 0, L4_IPC_NEVER, &result);

	LOG_printf("Main thread running, waiting...\n");

	l4x_server_loop();

	return 0;
}

void
l4x_linux_main_exit(void)
{
	extern void exit(int);
	LOG_printf("Terminating L4Linux.\n");
	exit(0);
}


#ifdef ARCH_x86
static void l4x_setup_die_utcb(void)
{
	struct pt_regs regs;
	unsigned long regs_addr;
	extern void die(const char *msg, struct pt_regs *regs, int err);
	static char message[40];
	l4_utcb_t *utcb = l4_utcb_get();

	snprintf(message, sizeof(message), "Trap: %ld", utcb->exc.trapno);
	message[sizeof(message) - 1] = 0;

	utcb_to_ptregs(utcb, &regs);

	/* XXX: check stack boundaries, i.e. utcb->exc.esp & (THREAD_SIZE-1)
	 * >= THREAD_SIZE - sizeof(thread_struct) - sizeof(struct pt_regs)
	 * - ...)
	 */
	/* Copy pt_regs on the stack */
	utcb->exc.esp -= sizeof(struct pt_regs);
	*(struct pt_regs *)utcb->exc.esp = regs;
	regs_addr = utcb->exc.esp;

	/* Put arguments for die on stack */
	/* err */
	utcb->exc.esp -= sizeof(unsigned long);
	*(unsigned long *)utcb->exc.esp = utcb->exc.err;
	/* regs */
	utcb->exc.esp -= sizeof(unsigned long);
	*(unsigned long *)utcb->exc.esp = regs_addr;
	/* msg */
	utcb->exc.esp -= sizeof(unsigned long);
	*(unsigned long *)utcb->exc.esp = (unsigned long)message;

	utcb->exc.esp -= sizeof(unsigned long);
	*(unsigned long *)utcb->exc.esp = 0;
	/* Set PC to die function */
	utcb->exc.eip = (unsigned long)die;
}

asmlinkage static void l4x_do_intra_iret(struct pt_regs regs)
{
	asm volatile ("mov %%cs, %0" : "=r" (regs.xcs));
	asm volatile
	("movl %0, %%esp	\t\n"
	 "popl %%ebx		\t\n"
	 "popl %%ecx		\t\n"
	 "popl %%edx		\t\n"
	 "popl %%esi		\t\n"
	 "popl %%edi		\t\n"
	 "popl %%ebp		\t\n"
	 "popl %%eax		\t\n"
	 "addl $8, %%esp	\t\n" /* keep ds, es */
	 "popl %%fs		\t\n"
	 "addl $4, %%esp	\t\n" /* keep orig_eax */
	 "iret			\t\n"
	 : : "r" (&regs));

	panic("Intra game zombie walking!");
}

static void l4x_setup_stack_for_traps(l4_utcb_t *utcb, struct pt_regs *regs,
                                      fastcall void (*trap_func)(struct pt_regs *regs, long err))
{
	const int l4x_intra_regs_size
		= sizeof(struct pt_regs) - 2 * sizeof(unsigned long);

	/* Copy pt_regs on the stack but omit last to two dwords,
	 * an intra-priv exception/iret doesn't have those, and native
	 * seems to do it the same, with the hope that nobody touches
	 * there in the pt_regs */
	utcb->exc.esp -= l4x_intra_regs_size;
	memcpy((void *)utcb->exc.esp, regs, l4x_intra_regs_size);

	/* do_<exception> functions are fastcall, arguments go in regs */
	utcb->exc.eax = utcb->exc.esp;
	utcb->exc.ebx = utcb->exc.err;

	/* clear TF */
	utcb->exc.eflags &= ~256;

	utcb->exc.esp -= sizeof(unsigned long);
	*(unsigned long *)utcb->exc.esp = 0; /* Return of l4x_do_intra_iret */
	utcb->exc.esp -= sizeof(unsigned long);
	*(unsigned long *)utcb->exc.esp = (unsigned long)l4x_do_intra_iret;

	/* Set PC to trap function */
	utcb->exc.eip = (unsigned long)trap_func;
}

#ifdef CONFIG_KPROBES
static int l4x_handle_kprobes(void)
{
	extern fastcall void do_int3(struct pt_regs *regs, long err);
	struct pt_regs regs;

	// XXX need to check other thread!!
	//if (kprobe_running())
	//	return 1; /* Not handled */

	if (l4_utcb_exc_pc(l4_utcb_get()) < PAGE_SIZE)
		return 1; /* Can not handle */

	/* check for kprobes break instruction */
	if (*(unsigned char *)l4_utcb_exc_pc(l4_utcb_get()) != BREAKPOINT_INSTRUCTION)
		return 1; /* Not handled */

	utcb_to_ptregs(l4_utcb_get(), &regs);
	l4x_set_kernel_mode(&regs);

	/* Set after breakpoint instruction as for HLT pc is on the
	 * instruction and for INT3 after the instruction */
	regs.eip++;

	l4x_setup_stack_for_traps(l4_utcb_get(), &regs, do_int3);
	return 0;
}
#else
static inline int l4x_handle_kprobes(void)
{
	return 1; /* Not handled */
}
#endif

static int l4x_handle_int1(void)
{
	struct pt_regs regs;
	extern fastcall void do_debug(struct pt_regs *regs, long err);

	if (l4_utcb_get()->exc.trapno != 1)
		return 1; /* Not handled */

	utcb_to_ptregs(l4_utcb_get(), &regs);
	l4x_setup_stack_for_traps(l4_utcb_get(), &regs, do_debug);
	return 0;
}

static int l4x_handle_clisti(void)
{
	unsigned char opcode = *(unsigned char *)l4_utcb_exc_pc(l4_utcb_get());
	extern void exit(int);

	/* check for cli or sti instruction */
	if (opcode != 0xfa && opcode != 0xfb)
		return 1; /* not handled if not those instructions */

	/* If we trap those instructions it's most likely a configuration
	 * error and quite early in the boot-up phase, so just quit. */
	LOG_printf("Aborting L4Linux due to unexpected CLI/STI instructions"
	           " at %lx.\n", l4_utcb_exc_pc(l4_utcb_get()));
	enter_kdebug("abort");
	exit(0);

	return 0;
}

void in_kernel_int80_set_kernel(void)
{ set_fs(KERNEL_DS); }

void in_kernel_int80_set_user(void)
{ set_fs(USER_DS); }

asm(
"in_kernel_int80_helper: \n\t"
"	pushl %eax	\n\t"	/* store eax */
"	call in_kernel_int80_set_kernel \n\t"
"	popl  %eax	\n\t"	/* restore eax */
"	call *%eax	\n\t"	/* eax has the sys_foo function we are calling */
"	movl %eax,24(%esp) \n\t"	/* store return value from sys_foo */
"	call in_kernel_int80_set_user\n\t"
"	call l4x_do_intra_iret\n\t"		/* return */
);

static int l4x_handle_lxsyscall(void)
{
	void *pc = (void *)l4_utcb_exc_pc(l4_utcb_get());
	extern char in_kernel_int80_helper[];
	unsigned long syscall;
	struct pt_regs *regsp;
	struct thread_info *ti;
	const int l4x_intra_regs_size
		= sizeof(struct pt_regs) - 2 * sizeof(unsigned long);

	if (pc < (void *)_stext || pc > (void *)_etext)
		return 1; /* Not for us */

	if (l4_utcb_get()->exc.err != 0x402)
		return 1; /* No int80 error code */

	if (*(unsigned short *)pc != 0x80cd)
		return 1; /* No int80 instructions */

	syscall = l4_utcb_get()->exc.eax;

	if (!is_lx_syscall(syscall))
		return 1; /* Not a valid system call number */

	ti = (struct thread_info *)(l4_utcb_get()->exc.esp & ~(THREAD_SIZE - 1));
	regsp = &ti->task->thread.regs;

	utcb_to_ptregs(l4_utcb_get(), regsp);
	l4x_set_kernel_mode(regsp);

	/* Set pc after int80 */
	regsp->eip += 2;

	l4_utcb_get()->exc.esp -= l4x_intra_regs_size;
	memcpy((void *)l4_utcb_get()->exc.esp, regsp, l4x_intra_regs_size);

	/* eax has the function, see in_kernel_int80_helper */
	if (syscall == __NR_execve)
		l4_utcb_get()->exc.eax = (unsigned long)l4_kernelinternal_execve;
	else
		l4_utcb_get()->exc.eax = (unsigned long)sys_call_table[syscall];

	/* Set PC to helper */
	l4_utcb_get()->exc.eip = (unsigned long)in_kernel_int80_helper;

	return 0;
}

static int l4x_handle_msr(void)
{
	void *pc = (void *)l4_utcb_exc_pc(l4_utcb_get());
	unsigned long reg = l4_utcb_get()->exc.ecx;

	/* wrmsr */
	if (*(unsigned short *)pc == 0x300f) {
		LOG_printf("WARNING: Unknown wrmsr: %08lx at %p\n", reg, pc);

		l4_utcb_get()->exc.eip += 2;
		return 0; // handled
	}

	/* rdmsr */
	if (*(unsigned short *)pc == 0x320f) {

		if (reg == MSR_IA32_MISC_ENABLE) {
			l4_utcb_get()->exc.eax = l4_utcb_get()->exc.edx = 0;
		} else
			LOG_printf("WARNING: Unknown rdmsr: %08lx at %p\n", reg, pc);

		l4_utcb_get()->exc.eip += 2;
		return 0; // handled
	}

	return 1; // not for us
}

static int l4x_handle_hlt_for_bugs_test(void)
{
	void *pc = (void *)l4_utcb_exc_pc(l4_utcb_get());

	if (*(unsigned int *)pc == 0xf4f4f4f4) {
		// check_bugs does 4 times hlt
		LOG_printf("Jumping over 4x 'hlt' at 0x%lx\n",
		           (unsigned long)pc);
		l4_utcb_get()->exc.eip += 4;
		return 0; // handled
	}

	return 1; // not for us
}

#ifdef CONFIG_L4_USE_L4VMM
static int l4x_l4vmm_handle_exception(void)
{
	return l4vmm_handle_exception(l4_utcb_get());
}
#endif

static inline void l4x_print_exception(l4_threadid_t t)
{
	LOG_printf("EX: "l4util_idfmt": pc = "l4_addr_fmt
	           " trapno = 0x%lx err/pfa = 0x%lx%s\n",
	           l4util_idstr(t), l4_utcb_get()->exc.eip,
		   l4_utcb_get()->exc.trapno,
		   l4_utcb_get()->exc.trapno == 14
	             ? l4_utcb_get()->exc.pfa
	             : l4_utcb_get()->exc.err,
	           l4_utcb_get()->exc.trapno == 14
	             ? (l4_utcb_get()->exc.err & 2)
	               ? " w" : " r"
	             : "");

	if (l4x_debug_show_exceptions >= 2
	    && !l4_utcb_exc_is_pf(l4_utcb_get())) {
		/* Lets assume we can do the following... */
		unsigned len = 72, i;
		unsigned long eip = l4_utcb_get()->exc.eip - 43;

		LOG_printf("Dump: ");
		for (i = 0; i < len; i++, eip++)
			if (eip == l4_utcb_get()->exc.eip)
				LOG_printf("<%02x> ", *(unsigned char *)eip);
			else
				LOG_printf("%02x ", *(unsigned char *)eip);

		LOG_printf(".\n");
	}
}
#endif /* ARCH_x86 */

#ifdef ARCH_arm
static void l4x_setup_die_utcb(void)
{
	struct pt_regs regs;
	extern void die(const char *msg, struct pt_regs *regs, int err);
	static char message[40];
	l4_utcb_t *utcb = l4_utcb_get();

	snprintf(message, sizeof(message), "Boom!");
	message[sizeof(message) - 1] = 0;

	utcb_to_ptregs(utcb, &regs);
	regs.ARM_ORIG_r0 = 0;
	l4x_set_kernel_mode(&regs);

	/* Copy pt_regs on the stack */
	utcb->exc.sp -= sizeof(struct pt_regs);
	*(struct pt_regs *)utcb->exc.sp = regs;

	/* Put arguments for die into registers */
	utcb->exc.r[0] = (unsigned long)message;
	utcb->exc.r[1] = utcb->exc.sp;
	utcb->exc.r[2] = utcb->exc.err;

	/* Set PC to die function */
	utcb->exc.pc  = (unsigned long)die;
	utcb->exc.ulr = 0;
}

static void l4x_arm_set_reg(l4_utcb_t *u, int num, unsigned long val)
{
	if (num > 15) {
		LOG_printf("Invalid register: %d\n", num);
		return;
	}

	switch (num) {
		case 15: u->exc.pc = val;  break;
		case 14: u->exc.ulr = val; break;
		default: u->exc.r[num] = val;
	}
}

static int l4x_arm_instruction_emu(void)
{
	l4_utcb_t *u = l4_utcb_get();
	unsigned long op = *(unsigned long *)u->exc.pc;

	if ((op & 0xff000000) == 0xee000000) {
		// always, mrc
		unsigned int reg;

		op &= 0x00ffffff;
		reg = (op >> 12) & 0xf;
		if ((op & 0x00ff0fff) == 0x00100f30) {
			// currently done directly in system.h because
			// called to often
			LOG_printf("Read Cache Type Register, to r%d\n", reg);
			u->exc.pc += 4;
			// 32kb i/d cache
			l4x_arm_set_reg(u, reg, 0x1c192992);
			return 0;
		} else if ((op & 0x00ff0fff) == 0x100f10) {
			// currently done directly in system.h because
			// called to often
			LOG_printf("Read ID code register, to r%d\n", reg);
			u->exc.pc += 4;
			l4x_arm_set_reg(u, reg, 0x860f0001);
			return 0;
		}
	}

	LOG_printf("Exception state:\n");
	LOG_printf("PC = %08lx SP = %08lx r0 = %08lx r1 = %08lx\n",
	           u->exc.pc, u->exc.sp, u->exc.r[0], u->exc.r[1]);
	LOG_printf("Opcode: %08lx\n", op);

	return 1; // not for us
}

static inline void l4x_print_exception(l4_threadid_t t)
{
	LOG_printf("EX: "l4util_idfmt": pc = "l4_addr_fmt" err = 0x%lx\n",
	           l4util_idstr(t),
		   l4_utcb_get()->exc.pc, l4_utcb_get()->exc.err);

	if (l4x_debug_show_exceptions >= 2
	    && !l4_utcb_exc_is_pf(l4_utcb_get())
	    && (l4_utcb_get()->exc.pc & 3) == 0) {
		/* Lets assume we can do the following... */
		unsigned len = 72 >> 2, i;
		unsigned long eip = l4_utcb_get()->exc.pc - 44;

		LOG_printf("Dump: ");
		for (i = 0; i < len; i++, eip += sizeof(unsigned long))
			if (eip == l4_utcb_get()->exc.pc)
				LOG_printf("<%08lx> ", *(unsigned long *)eip);
			else
				LOG_printf("%08lx ", *(unsigned long *)eip);

		LOG_printf(".\n");
	}
}
#endif /* ARCH_arm */

struct l4x_exception_func_struct {
	int (*f)(void);
};
static struct l4x_exception_func_struct l4x_exception_func_list[] = {
#ifdef ARCH_x86
	{ .f = l4x_handle_hlt_for_bugs_test }, // before kprobes!
	{ .f = l4x_handle_kprobes },
	{ .f = l4x_handle_int1 },
	{ .f = l4x_handle_clisti },
	{ .f = l4x_handle_lxsyscall },
	{ .f = l4x_handle_msr },
#endif
#ifdef CONFIG_L4_USE_L4VMM
	{ .f = l4x_l4vmm_handle_exception },
#endif
#ifdef ARCH_arm
	{ .f = l4x_arm_instruction_emu },
#endif
};
static const int l4x_exception_funcs
	= sizeof(l4x_exception_func_list) / sizeof(l4x_exception_func_list[0]);

static int l4x_default(l4_threadid_t *src_id, l4_umword_t *dw0,
                       l4_umword_t *dw1, l4_msgtag_t *tag)
{
	if (!l4_msgtag_is_exception(*tag)
	    && !l4_msgtag_is_io_page_fault(*tag)) {
		static unsigned long old_pf_addr = ~0UL, old_pf_pc = ~0UL;
		if (unlikely(old_pf_addr == (*dw0 & ~1) && old_pf_pc == *dw1)) {
			LOG_printf("Double page fault dw0=%08lx dw1=%08lx\n",
			           *dw0, *dw1);
			enter_kdebug("Double pagefault");
		}
		old_pf_addr = *dw0 & ~1;
		old_pf_pc   = *dw1;
	}

	if (unlikely(!l4_task_equal(*src_id, linux_server_thread_id))) {
		LOG_printf("Invalid source for request: "l4util_idfmt"\n",
		           l4util_idstr(*src_id));
		return 1; // no-reply
	}

	if (l4_msgtag_is_exception(*tag)) {
		int i;

		if (l4x_debug_show_exceptions)
			l4x_print_exception(*src_id);

		for (i = 0; i < l4x_exception_funcs; i++)
			if (!l4x_exception_func_list[i].f())
				break;
		if (i == l4x_exception_funcs)
			l4x_setup_die_utcb();

		*tag = l4_msgtag(0, L4_UTCB_EXCEPTION_REGS_SIZE, 0, 0);
		*dw0 = *dw1 = 0;
		return 0; // reply
	}

	if (l4x_debug_show_exceptions)
		LOG_printf("PF: " l4util_idfmt ": pfaddr = " l4_addr_fmt
		           " pc = " l4_addr_fmt " (%s%s)\n",
		           l4util_idstr(*src_id), *dw0, *dw1,
		           *dw0 & 2 ? "rw" : "ro", *dw0 & 1 ? ", T" : "");

#ifdef ARCH_x86
	/* Make an exception out of a I/O page fault */
	if (l4_is_io_page_fault(*dw0)) {
		*dw0 = -1;
		return 0; // reply
	}
#endif

	/* For a 0 pointer deref, come back with an exception */
	if ((*dw0 & ~3) == 0)
		*dw0 = -1;
	else {
		/* Forward page fault to our pager */
		l4x_forward_pf(*dw0, *dw1);
		*dw0 = 0;
	}

	*dw1 = 0;
	return 0; // reply
}

enum {
	L4X_SERVER_EXIT = 0xd0000000,
};

static void l4x_server_loop(void)
{
	int do_wait = 1;
	l4_msgtag_t tag = (l4_msgtag_t){0};
	l4_umword_t w0 = 0, w1 = 0;
	l4_msgdope_t result;
	l4_threadid_t src;

	while (1) {

		while (do_wait)
			do_wait = l4_ipc_wait_tag(&src, L4_IPC_SHORT_MSG,
			                          &w0, &w1,
			                          L4_IPC_NEVER, &result, &tag);

		if (l4_msgtag_label(tag) == 0 && w0 == L4X_SERVER_EXIT) {
			l4x_linux_main_exit(); // will not return anyway
			do_wait = 1;
			continue; // do not reply
		}

		if (l4x_default(&src, &w0, &w1, &tag))  {
			do_wait = 1;
			continue; // do not reply
		}

		do_wait = l4_ipc_reply_and_wait_tag(src, L4_IPC_SHORT_MSG,
		                                    w0, w1, tag, &src,
		                                    L4_IPC_SHORT_MSG,
		                                    &w0, &w1,
		                                    L4_IPC_SEND_TIMEOUT_0,
		                                    &result, &tag);
	}
}


void __attribute__((noreturn)) l4x_exit_l4linux(void)
{
	l4_msgdope_t result;

	LOG_printf("%s %d\n", __func__, __LINE__);
	__cxa_finalize(0);

	LOG_printf("%s %d\n", __func__, __LINE__);
	l4_ipc_send(l4x_start_thread_id, L4_IPC_SHORT_MSG,
	             L4X_SERVER_EXIT, 0, L4_IPC_NEVER, &result);
	LOG_printf("%s %d\n", __func__, __LINE__);
	l4_sleep_forever();
	LOG_printf("%s %d\n", __func__, __LINE__);
}

int l4x_map_iomemory_from_sigma0(l4_addr_t phys, l4_addr_t virt, l4_size_t size)
{
	l4_threadid_t sigma0_id = L4_NIL_ID;
	int ret;

	sigma0_id.id.task    = 2;
	sigma0_id.id.lthread = 0;

	if ((ret = l4sigma0_map_iomem(sigma0_id, phys, virt, size, 0))) {
		printk("Error mapping IO memory from Sigma0. "
		       "Error: %d (%s)\n", ret, l4sigma0_map_errstr(ret));
		return 1;
	}

	return 0;
}

/* ---------------------------------------------------------------- */
/* swsusp stuff */

#ifdef CONFIG_PM
int arch_prepare_suspend(void)
{
	LOG_printf("%s\n", __func__);
	return 0;
}

void l4x_swsusp_before_resume(void)
{
	// make our AS readonly so that we see all PFs
#if 0
	l4_fpage_unmap(l4_fpage(0, 31, 0, 0),
	               L4_FP_REMAP_PAGE | L4_FP_ALL_SPACES);
#endif
}

void l4x_swsusp_after_resume(void)
{
	LOG_printf("%s\n", __func__);
}


/* ---- */
/* we need to remember virtual mappings to restore them after resume */

#include <asm/generic/vmalloc.h>
#include <asm/l4lxapi/memory.h>

struct l4x_virtual_mem_struct {
	struct list_head list;
	unsigned long address, page;
};

static LIST_HEAD(virtual_pages);

enum l4x_virtual_mem_type {
	L4X_VIRTUAL_MEM_TYPE_MAP,
	L4X_VIRTUAL_MEM_TYPE_UNMAP,
};

void l4x_virtual_mem_register(unsigned long address, unsigned long page)
{
	struct l4x_virtual_mem_struct *e;
	if (!(e = kmalloc(sizeof(*e), GFP_KERNEL)))
		BUG();
	e->address = address;
	e->page    = page;
	list_add_tail(&e->list, &virtual_pages);
}

void l4x_virtual_mem_unregister(unsigned long address)
{
	struct list_head *p, *tmp;
	list_for_each_safe(p, tmp, &virtual_pages) {
		struct l4x_virtual_mem_struct *e
		 = list_entry(p, struct l4x_virtual_mem_struct, list);
		if (e->address == address) {
			list_del(p);
			kfree(e);
		}
	}
}

static void l4x_virtual_mem_handle_pages(enum l4x_virtual_mem_type t)
{
	struct list_head *p;
	list_for_each(p, &virtual_pages) {
		struct l4x_virtual_mem_struct *e
		 = list_entry(p, struct l4x_virtual_mem_struct, list);

		if (t == L4X_VIRTUAL_MEM_TYPE_MAP) {
			LOG_printf("map virtual %lx -> %lx\n", e->address, e->page);
			l4lx_memory_map_virtual_page(e->address, e->page);
		} else {
			LOG_printf("unmap virtual %lx\n", e->address);
			l4lx_memory_unmap_virtual_page(e->address);
		}
	}
}

/* ---- */

#include <asm/generic/suspres.h>

#include <linux/bootmem.h>

struct l4x_suspend_resume_struct {
	struct list_head list;
	void (*func)(enum l4x_suspend_resume_state);
};

static LIST_HEAD(suspres_func_list);

void l4x_suspend_resume_register(void (*func)(enum l4x_suspend_resume_state))
{
	struct l4x_suspend_resume_struct *e;
	if (slab_is_available())
		e = kmalloc(sizeof(*e), GFP_ATOMIC); // may be called with irqs off
	else
		e = alloc_bootmem(sizeof(*e));
	if (!e)
		return;

	e->func = func;
	list_add(&e->list, &suspres_func_list);
}

static void l4x_suspend_resume_call_funcs(enum l4x_suspend_resume_state state)
{
	struct list_head *p;
	list_for_each(p, &suspres_func_list) {
		struct l4x_suspend_resume_struct *e
		 = list_entry(p, struct l4x_suspend_resume_struct, list);
		e->func(state);
	}
}


#include <linux/pm.h>
#include <linux/platform_device.h>

static int l4x_power_mgmt_suspend(struct platform_device *dev, pm_message_t state)
{
	struct task_struct *p;

	LOG_printf("%s (state = %d)\n", __func__, state.event);

	for_each_process(p) {
		if (l4_is_nil_id(p->thread.user_thread_id))
			continue;

		if (!l4lx_task_delete(p->thread.user_thread_id, 1))
			LOG_printf("Error deleting %s(%d)\n", p->comm, p->pid);
		if (l4lx_task_number_free(p->thread.user_thread_id))
			LOG_printf("Error freeing %s(%d)\n", p->comm, p->pid);
		p->thread.user_thread_id = L4_INVALID_ID;
		LOG_printf("kicked %s(%d)\n", p->comm, p->pid);
	}


	l4x_suspend_resume_call_funcs(L4X_SUSPEND);
	l4x_virtual_mem_handle_pages(L4X_VIRTUAL_MEM_TYPE_UNMAP);
	return 0;
}

static int l4x_power_mgmt_resume(struct platform_device *dev)
{
	struct task_struct *p;

	LOG_printf("%s\n", __func__);

	l4x_virtual_mem_handle_pages(L4X_VIRTUAL_MEM_TYPE_MAP);
	l4x_suspend_resume_call_funcs(L4X_RESUME);

	for_each_process(p) {
		int error;
		l4_threadid_t src_id;
		l4_umword_t data;
		l4_msgdope_t dummydope;

		if (l4_is_nil_id(p->thread.user_thread_id))
			continue;

		if (l4lx_task_get_new_task(L4_NIL_ID,
		                           &p->thread.user_thread_id))
			LOG_printf("l4lx_task_get_new_task failed\n");
#ifdef CONFIG_SMP
#warning resume: all tasks started on cpu0
#endif
		if (!l4lx_task_create_pager(p->thread.user_thread_id,
		                            l4x_cpu_thread_get(0)))
			LOG_printf("l4lx_task_create for %s(%d) failed\n",
			           p->comm, p->pid);

		do {
			error = l4_ipc_wait(&src_id,
			                    L4_IPC_SHORT_MSG, &data, &data,
			                    L4_IPC_SEND_TIMEOUT_0, &dummydope);
			if (error)
				LOG_printf("ipc error %x\n", error);
		} while (!l4_thread_equal(src_id, p->thread.user_thread_id));

		LOG_printf("contacted %s(%d)\n", p->comm, p->pid);
	}

	return 0;
}

static struct platform_driver l4x_power_mgmt_drv = {
	.suspend = l4x_power_mgmt_suspend,
	.resume  = l4x_power_mgmt_resume,
	.driver  = {
		.name = "l4x_power_mgmt",
	},
};

static void l4x_power_mgmt_platform_release(struct device *device)
{}

static struct platform_device l4x_power_mgmt_dev = {
	.name = "l4x_power_mgmt",
	.dev = {
		.release = l4x_power_mgmt_platform_release,
	}
};

static int l4x_power_mgmt_init(void)
{
	int ret;
	if (!(ret = platform_driver_register(&l4x_power_mgmt_drv))) {
		ret = platform_device_register(&l4x_power_mgmt_dev);
		if (ret)
			platform_driver_unregister(&l4x_power_mgmt_drv);
	}
	return ret;
}

module_init(l4x_power_mgmt_init);
#endif /* CONFIG_PM */


void exit(int code)
{
	__cxa_finalize(0);

	if (!l4ts_connected()) {
		LOG_printf("SIMPLE_TS not found -- cannot send exit event");
		l4_sleep_forever();
	}

	l4ts_exit();

	LOG_printf("Still alive, going zombie...\n");
	l4_sleep_forever();
}

/* -------------------------------------------------- */
/*   Maybe for l4util                                 */

/**
 * Set the PC of a thread, leaving the SP where it is.
 */
void l4x_thread_set_pc(l4_threadid_t thread, void *pc)
{
	l4_threadid_t preempter = L4_INVALID_ID, pager = L4_INVALID_ID;
	l4_umword_t dummy;

	l4_thread_ex_regs(thread, (l4_umword_t)pc, ~0UL,
	                  &preempter, &pager, &dummy, &dummy, &dummy);
}


/* -------------------------------------------------- */

void l4x_setup_threads(void)
{
	l4lx_thread_prio_set(linux_server_thread_id, CONFIG_L4_PRIO_SERVER);

	/* init task management subsystem */
	l4lx_task_init();	/* do this after rmgr_init() if used */
}

/* -------------------------------------------------- */
/* some irq stuff */

#ifndef CONFIG_L4_TAMED
#include <asm/hardirq.h>

void l4x_local_irq_disable(void)
{
	l4x_real_irq_disable();
	l4x_irq_flag(smp_processor_id()) = L4_IRQ_DISABLED;
}
EXPORT_SYMBOL(l4x_local_irq_disable);

void l4x_local_irq_enable(void)
{
	l4x_irq_flag(smp_processor_id()) = L4_IRQ_ENABLED;
	l4x_real_irq_enable();
}
EXPORT_SYMBOL(l4x_local_irq_enable);

unsigned long l4x_local_save_flags(void)
{
	return l4x_irq_flag(smp_processor_id());
}
EXPORT_SYMBOL(l4x_local_save_flags);

void l4x_local_irq_restore(unsigned long flags)
{
	l4x_irq_flag(smp_processor_id()) = flags;
	if (flags == L4_IRQ_ENABLED)
		l4x_real_irq_enable();

}
EXPORT_SYMBOL(l4x_local_irq_restore);
#endif

/* ----------------------------------------------------- */

int l4x_peek_upage(unsigned long addr,
                   unsigned long __user *datap,
                   int *ret)
{
	unsigned long tmp;

	if (addr >= UPAGE_USER_ADDRESS
	    && addr < UPAGE_USER_ADDRESS + PAGE_SIZE) {
		addr -= UPAGE_USER_ADDRESS;
		tmp = *(unsigned long *)(addr + &_upage_start);
		*ret = put_user(tmp, datap);
		return 1;
	}
	return 0;
}

/* ----------------------------------------------------- */

void l4x_printk_func(char *buf, int len)
{
	outnstring(buf, len);
}

#include <linux/hardirq.h>

/* ----------------------------------------------------- */
/* Prepare a thread for use as an IRQ thread. */
void l4x_prepare_irq_thread(struct thread_info *ti)
{
	/* Stack setup */
	*ti = (struct thread_info) INIT_THREAD_INFO(init_task);

	l4x_stack_setup(ti);

	ti->preempt_count = HARDIRQ_OFFSET;
	ti->addr_limit    = KERNEL_DS;

	/* Set pager */
	l4lx_thread_set_kernel_pager(l4_myself());

#ifdef ARCH_x86
	switch_to_new_gdt();
#endif
}

/* ----------------------------------------------------- */
void l4x_show_process(struct task_struct *t)
{
#ifdef ARCH_x86
	printk("%2d: %s tsk st: %lx thrd flgs: %lx " PRINTF_L4TASK_FORM " esp: %08lx\n",
	       t->pid, t->comm, t->state, task_thread_info(t)->flags,
	       PRINTF_L4TASK_ARG(t->thread.user_thread_id),
	       t->thread.esp);
#endif

#ifdef ARCH_arm
	printk("%2d: %s tsk st: %lx thrd flgs: %lx " PRINTF_L4TASK_FORM " esp: %08x\n",
	       t->pid, t->comm, t->state, task_thread_info(t)->flags,
	       PRINTF_L4TASK_ARG(t->thread.user_thread_id),
	       task_thread_info(t)->cpu_context.sp);
#endif
}

void l4x_show_processes(void)
{
	struct task_struct *t;
	for_each_process(t) {
		if (t->pid >= 10)
			l4x_show_process(t);
	}
	printk("c");
	l4x_show_process(current);
}

void l4x_show_sigpending_processes(void)
{
	struct task_struct *t;
	printk("Processes with pending signals:\n");
	for_each_process(t) {
		if (signal_pending(t))
			l4x_show_process(t);
	}
	printk("Signal list done.\n");

}

/* Just a function we can call without defining the header files */
void kdb_ke(void)
{
	enter_kdebug("kdb_ke");
}

#ifdef CONFIG_L4_DEBUG_SEGFAULTS
void l4x_print_vm_area_maps(struct task_struct *p)
{
	struct vm_area_struct *vma = p->mm->mmap;


	while (vma) {
		struct file *file = vma->vm_file;

		LOG_printf("%p - %p", (void *)vma->vm_start, (void *)vma->vm_end);

		if (file) {
			char buf[40];
			int count = 0;

			char *s = buf;
			char *p = d_path(file->f_dentry, file->f_vfsmnt, s, sizeof(buf));
			if (!IS_ERR(p)) {
				while (s <= p) {
					char c = *p++;
					if (!c) {
						p = buf + count;
						count = s - buf;
						buf[count] = 0;
						break;
					} else if (!strchr("", c)) {
						*s++ = c;
					} else if (s + 4 > p) {
						break;
					} else {
						*s++ = '\\';
						*s++ = '0' + ((c & 0300) >> 6);
						*s++ = '0' + ((c & 070) >> 3);
						*s++ = '0' + (c & 07);
					}
				}
			}
			LOG_printf(" %s", count ? buf : "Unknown");
		}

		LOG_printf("\n");
		vma = vma->vm_next;
	}
}
#endif

#ifdef ARCH_x86

#include <linux/clockchips.h>

struct clock_event_device *global_clock_event;

static void clock_init_l4_timer(enum clock_event_mode mode,
                                struct clock_event_device *evt)
{
}

static int clock_l4_next_event(unsigned long delta, struct clock_event_device *evt)
{
	return 0;
}

struct clock_event_device l4_clockevent = {
	.name		= "l4",
	.features	= CLOCK_EVT_FEAT_PERIODIC,
	.set_mode	= clock_init_l4_timer,
	.set_next_event	= clock_l4_next_event,
	.shift		= 32,
	.irq		= 0,
};

void setup_pit_timer(void)
{
	l4_clockevent.cpumask = cpumask_of_cpu(0);
	clockevents_register_device(&l4_clockevent);
	global_clock_event = &l4_clockevent;
}
#endif

/* ----------------------------------------------------------------------- */
/* Export list, we could also put these in a separate file (like l4_ksyms.c) */

#ifdef ARCH_x86
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>

#include <asm/i387.h>
#include <asm/checksum.h>
#include <asm/delay.h>
#include <asm/dma-mapping.h>
#include <asm/io.h>

EXPORT_SYMBOL(__VMALLOC_RESERVE);

EXPORT_SYMBOL(swapper_pg_dir);
EXPORT_SYMBOL(__down_failed);
EXPORT_SYMBOL(__down_failed_interruptible);
EXPORT_SYMBOL(__down_failed_trylock);
EXPORT_SYMBOL(__up_wakeup);
EXPORT_SYMBOL(init_thread_union);
EXPORT_SYMBOL(csum_partial);
EXPORT_SYMBOL(csum_partial_copy);

EXPORT_SYMBOL(strstr);

#ifdef CONFIG_X86_USE_3DNOW
EXPORT_SYMBOL(_mmx_memcpy);
EXPORT_SYMBOL(mmx_clear_page);
EXPORT_SYMBOL(mmx_copy_page);
#endif

EXPORT_SYMBOL(l4x_fpu_set);

#endif /* ARCH_x86 */

/* Some exports from L4 libraries etc. */
EXPORT_SYMBOL(LOG_printf);

EXPORT_SYMBOL(l4env_vmalloc_memory_start);

/* Exports for L4 specific modules */
EXPORT_SYMBOL(l4_sleep);
EXPORT_SYMBOL(l4rm_do_attach);
EXPORT_SYMBOL(l4rm_detach);

#include <l4/names/libnames.h>
EXPORT_SYMBOL(names_waitfor_name);

char l4env_ipc_errstrings[0];
EXPORT_SYMBOL(l4env_ipc_errstrings);

EXPORT_SYMBOL(l4semaphore_restart_up);
EXPORT_SYMBOL(l4semaphore_restart_down);
EXPORT_SYMBOL(l4semaphore_thread_l4_id);

EXPORT_SYMBOL(l4thread_myself);

EXPORT_SYMBOL(l4x_prepare_irq_thread);
