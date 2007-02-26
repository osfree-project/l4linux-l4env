/*
 * Inline implementations of include/asm-l4/l4lxapi/misc.h
 * for L4Env.
 *
 * $Id: misc.h,v 1.4 2003/06/20 19:48:35 adam Exp $
 *
 */
#ifndef __L4LXLIB__L4ENV__MISC_H__
#define __L4LXLIB__L4ENV__MISC_H__

#include <l4/thread/thread.h>
#include <l4/util/util.h>

L4_INLINE void l4lx_sleep(int ms)
{
	l4thread_sleep(ms);
}

L4_INLINE void l4lx_usleep(int us)
{
	l4thread_usleep(us);
}

L4_INLINE void l4lx_sleep_forever(void)
{
	l4_sleep_forever();
}

#endif /* !__L4LXLIB__L4ENV__MISC_H__ */
