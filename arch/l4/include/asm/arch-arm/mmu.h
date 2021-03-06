#ifndef __ARM_MMU_H
#define __ARM_MMU_H

#ifdef CONFIG_MMU

#include <asm/generic/mmu.h>

typedef struct {
#ifdef CONFIG_CPU_HAS_ASID
	unsigned int id;
#endif
	unsigned int kvm_seq;

	int l4x_task_id;
	enum l4x_unmap_mode_enum l4x_unmap_mode;
} mm_context_t;

#ifdef CONFIG_CPU_HAS_ASID
#define ASID(mm)	((mm)->context.id & 255)
#else
#define ASID(mm)	(0)
#endif

#else

/*
 * From nommu.h:
 *  Copyright (C) 2002, David McCullough <davidm@snapgear.com>
 *  modified for 2.6 by Hyok S. Choi <hyok.choi@samsung.com>
 */
typedef struct {
	unsigned long		end_brk;
} mm_context_t;

#endif

#endif
