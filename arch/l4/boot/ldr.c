
#include <stdio.h>
#include <string.h>

#define __USE_GNU
#include <dlfcn.h>

#include <l4/l4rm/l4rm.h>
#include <l4/dm_generic/types.h>
#include <l4/dm_mem/dm_mem.h>
#include <l4/util/elf.h>
#include <l4/util/util.h>
#include <l4/log/log_printf.h>

#include <l4/dm_phys/dm_phys.h>

#include <l4/sys/compiler.h>
#include <l4/l4con/stream-server.h>

char LOG_tag[9] = "l4lx";

extern char image_vmlinux_start[];
extern char image_vmlinux_end[];

asm(
".p2align 12                     \n"
".globl image_vmlinux_start      \n"
"image_vmlinux_start:            \n"
".incbin \"" VMLINUX_IMAGE "\"   \n"
".globl image_vmlinux_end        \n"
"image_vmlinux_end:              \n"
".p2align 12                     \n"
);

struct shared_data {
	unsigned long (*external_resolver)(void);
	L4_CV l4_utcb_t *(*l4lx_utcb_get)(void);
};
struct shared_data exchg;

unsigned long __l4_external_resolver(void);

L4_CV l4_utcb_t *l4sys_utcb_get(void)
{
	if (exchg.l4lx_utcb_get)
		return exchg.l4lx_utcb_get();
	return l4_utcb_get();
}




#ifdef CONFIG_L4_FB_DRIVER
typedef L4_CV void
     stream_io_push_component_t(CORBA_Object _dice_corba_obj,
                                const stream_io_input_event_t *event,
                                CORBA_Server_Environment *_dice_corba_env);

static stream_io_push_component_t *stream_io_push_component_cb;

L4_CV void
stream_io_push_component(CORBA_Object _dice_corba_obj,
                         const stream_io_input_event_t *event,
                         CORBA_Server_Environment *_dice_corba_env)
{
	if (stream_io_push_component_cb)
		stream_io_push_component_cb(_dice_corba_obj, event, _dice_corba_env);
}

L4_CV void register_stream_io_push_component(stream_io_push_component_t *func);
L4_CV void register_stream_io_push_component(stream_io_push_component_t *func)
{
	stream_io_push_component_cb = func;
}
#endif

#ifdef CONFIG_L4_CONS
typedef L4_CV void
  cons_event_ping_component_t(CORBA_Object _dice_corba_obj,
                              CORBA_Server_Environment *_dice_corba_env);

static cons_event_ping_component_t *cons_event_ping_component_cb;

L4_CV void
cons_event_ping_component(CORBA_Object _dice_corba_obj,
                          CORBA_Server_Environment *_dice_corba_env)
{
	if (cons_event_ping_component_cb)
		cons_event_ping_component_cb(_dice_corba_obj, _dice_corba_env);
}

L4_CV void register_cons_event_ping_component(cons_event_ping_component_t *func);
L4_CV void register_cons_event_ping_component(cons_event_ping_component_t *func)
{
	cons_event_ping_component_cb = func;
}

#endif






void do_resolve_error(const char *funcname);
void do_resolve_error(const char *funcname)
{
	LOG_printf("Symbol '%s' not found\n", funcname);
	enter_kdebug("Symbol not found!");
}

int main(int argc, char **argv)
{
	ElfW(Ehdr) *ehdr = (void *)image_vmlinux_start;
	int i;
	int (*entry)(int, char **);

	if (!l4util_elf_check_magic(ehdr)
	    || !l4util_elf_check_arch(ehdr)) {
		printf("lxldr: Invalid vmlinux binary (No ELF)\n");
		return 1;
	}

	for (i = 0; i < ehdr->e_phnum; ++i) {
		int r;
		l4_addr_t map_addr;
		l4_size_t map_size;
		l4dm_dataspace_t ds;
		l4_offs_t offset;
		l4_threadid_t pager;


		ElfW(Phdr) *ph = (ElfW(Phdr)*)((l4_addr_t)l4util_elf_phdr(ehdr)
		                               + i * ehdr->e_phentsize);
		//printf("PH %d (t: %d) off=%08x f=%08x m=%08x\n",
		 //      i, ph->p_type, ph->p_offset, ph->p_filesz, ph->p_memsz);
		if (ph->p_type != PT_LOAD)
			continue;

		if (ph->p_vaddr & ~L4_PAGEMASK) {
			printf("lxldr: unaligned section\n");
			continue;
		}

		if (ph->p_filesz < ph->p_memsz) {
			r = l4dm_mem_open(L4DM_DEFAULT_DSM,
			                  ph->p_memsz, L4_PAGESIZE,
			                  L4DM_CONTIGUOUS | L4DM_PINNED,
			                  "lxldr alloc'ed", &ds);
			if (r) {
				printf("lxldr: error getting memory: %d\n", r);
				return 1;
			}
			r = l4rm_attach_to_region(&ds, (void *)ph->p_vaddr,
		                                  ph->p_memsz, 0,
		                                  L4RM_MAP | L4DM_RW);
			if (r) {
				printf("lxldr: failed attaching new memory %d\n", r);
				return 1;
			}
			memcpy((void *)ph->p_vaddr,
			       (char *)image_vmlinux_start + ph->p_offset,
			       ph->p_filesz);
			memset((void *)ph->p_vaddr + ph->p_filesz, 0,
			       ph->p_memsz - ph->p_filesz);
			continue;
		}

		r = l4rm_lookup((char *)image_vmlinux_start + ph->p_offset,
		                &map_addr, &map_size, &ds, &offset, &pager);
		if (r != L4RM_REGION_DATASPACE) {
			printf("lxldr: Failed lookup\n");
			return 1;
		}

		r = l4rm_attach_to_region(&ds, (void *)ph->p_vaddr,
		                          ph->p_memsz, offset,
		                          L4RM_MAP | L4DM_RW);
		if (r) {
			printf("lxldr: Failed to attach section\n");
			return 1;
		}
	}

	entry = (void *)ehdr->e_entry;
	exchg.external_resolver = __l4_external_resolver;
	asm volatile("push %[argv]\n"
	             "push %[argc]\n"
	             "push $0\n"
	             "mov  %[exchg], %%esi\n"
	             "jmp  *%[entry]\n"
		     :
		     : [argv] "r" (argv),
		       [argc] "r" (argc),
		       [exchg] "r" (&exchg),
		       [entry] "r" (entry)
		     : "memory");


	l4_sleep_forever();
	return 0;
}
