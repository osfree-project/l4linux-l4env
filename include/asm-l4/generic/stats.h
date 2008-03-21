#ifndef __ASM_L4__GENERIC__STATS_H__
#define __ASM_L4__GENERIC__STATS_H__

#ifdef CONFIG_L4_DEBUG_STATS

#include <l4/util/atomic.h>

struct l4x_debug_stats {
	long l4x_debug_stats_suspend;
	long l4x_debug_stats_pagefault;
	long l4x_debug_stats_exceptions;
	long l4x_debug_stats_pagefault_but_in_PTs;
	long l4x_debug_stats_pagefault_write;
};

extern struct l4x_debug_stats l4x_debug_stats_data;

#define CONSTRUCT_ONE(name);						\
	extern long name;						\
	static inline void name##_hit(void)				\
	{								\
		l4util_atomic_add(&l4x_debug_stats_data.name, 1);	\
	}								\
	static inline long name##_get(void)				\
	{								\
		return l4x_debug_stats_data.name;			\
	}

#else

#define CONSTRUCT_ONE(name);						\
	static inline void name##_hit(void)				\
	{								\
	}								\
	static inline long name##_get(void)				\
	{								\
		return 0;						\
	}

#endif /* CONFIG_L4_DEBUG_STATS */

CONSTRUCT_ONE(l4x_debug_stats_suspend);
CONSTRUCT_ONE(l4x_debug_stats_pagefault);
CONSTRUCT_ONE(l4x_debug_stats_exceptions);
CONSTRUCT_ONE(l4x_debug_stats_pagefault_but_in_PTs);
CONSTRUCT_ONE(l4x_debug_stats_pagefault_write);

#undef CONSTRUCT_ONE

#endif /* ! __ASM_L4__GENERIC__STATS_H__ */
