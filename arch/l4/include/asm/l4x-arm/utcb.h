#ifndef __ASM_L4__L4X_ARM__UTCB_H__
#define __ASM_L4__L4X_ARM__UTCB_H__

#include <l4/sys/utcb.h>

static inline void l4x_utcb_set(l4_threadid_t t, l4_utcb_t *u)
{}

static inline l4_utcb_t *l4x_utcb_get(l4_threadid_t t)
{
	return l4_utcb_get();
}

#endif /* ! __ASM_L4__L4X_ARM__UTCB_H__ */
