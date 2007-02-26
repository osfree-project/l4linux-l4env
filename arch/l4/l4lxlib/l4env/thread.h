/*
 * Inline implementations of the API defined in asm/l4lxapi/thread.h
 * for L4Env.
 *
 * $Id: thread.h,v 1.2 2003/04/13 11:06:11 adam Exp $
 *
 */
#ifndef __L4LXLIB__L4ENV__THREAD_H__
#define __L4LXLIB__L4ENV__THREAD_H__

#include <l4/sys/types.h>

L4_INLINE int l4lx_thread_equal(l4_threadid_t t1, l4_threadid_t t2)
{
	/* XXX: actually we can't take l4thread_equal here,
	 *      or we define l4lx_thread_equal to define something else...
	 */
	//return l4thread_equal(t1.id.lthread, t2.id.lthread);
	return l4_thread_equal(t1, t2);
}

#endif /* !__L4LXLIB__L4ENV__THREAD_H__ */
