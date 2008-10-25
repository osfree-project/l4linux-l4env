#ifndef __ASM_L4__ARCH_ARM__CACHEFLUSH_H__
#define __ASM_L4__ARCH_ARM__CACHEFLUSH_H__

/* Avoid copying the whole file, we just redefined some macros */
#include <arm-arch/asm/cacheflush.h>

#undef flush_cache_vmap
#undef flush_cache_vunmap

#include <asm/generic/vmalloc.h>

#define flush_cache_vmap(start, end)            \
	do { l4x_vmalloc_map_vm_area(start, end); } while (0)
/* end - 'guard page' */
#define flush_cache_vunmap(start, end)          \
	do { l4x_vmalloc_unmap_vm_area(start, end - PAGE_SIZE); } while (0)

#endif /* __ASM_L4__ARCH_ARM__CACHEFLUSH_H__ */
