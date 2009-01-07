/*
 * This file has API specific definitions which don't fit anywhere else
 * (or are too generic).
 *
 */
#ifndef __L4_ASM__API_L4ENV__API_H__
#define __L4_ASM__API_L4ENV__API_H__

#include <l4/sys/types.h>
#include <l4/dm_generic/dm_generic.h>
#include <l4/log/log_printf.h>

/* from arch/l4/kernel/main.c */
extern unsigned long l4env_vmalloc_memory_start;

/* Dataspace for our (main) memory */
extern l4dm_dataspace_t l4env_ds_mainmem;

/* Adress where our main memory starts */
extern void * l4env_mainmem_start;

/* Area ID of the reserved vmalloc and possibly modules region */
extern l4_uint32_t l4env_vmalloc_areaid;
extern l4_uint32_t l4env_modules_areaid;

unsigned long l4env_virt_to_phys(volatile void * address);
void * l4env_phys_to_virt(unsigned long address);

#endif /* ! __L4_ASM__API_L4ENV__API_H__ */
