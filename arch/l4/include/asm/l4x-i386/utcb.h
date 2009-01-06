#ifndef __ASM_L4__L4X_I386__UTCB_H__
#define __ASM_L4__L4X_I386__UTCB_H__

#include <asm/l4lxapi/generic/thread_gen.h>

enum { L4X_UTCB_POINTERS = L4LX_THREAD_NO_THREADS + 3 /* l4env threads */ };

extern l4_utcb_t *l4x_utcb_pointer[L4X_UTCB_POINTERS];

static inline void l4x_utcb_set(l4_threadid_t t, l4_utcb_t *u)
{
	BUG_ON(t.id.lthread >= L4X_UTCB_POINTERS);
	l4x_utcb_pointer[t.id.lthread] = u;
}

static inline l4_utcb_t *l4x_utcb_get(l4_threadid_t t)
{
	return l4x_utcb_pointer[t.id.lthread];
}

#endif /* ! __ASM_L4__L4X_I386__UTCB_H__ */
