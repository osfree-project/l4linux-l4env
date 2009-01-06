/*
 * Miscellaneous functions.
 *
 * $Id: misc.h,v 1.2 2003/03/17 22:37:40 adam Exp $
 *
 */

#ifndef __ASM_L4__L4LXAPI__MISC_H__
#define __ASM_L4__L4LXAPI__MISC_H__

#include <l4/sys/compiler.h>
#include <l4/sys/types.h>

/* Probably not here ... */
/**
 * \defgroup l4lxapi L4-Linux internal API Reference.
 * Documentation of the internal L4-Linux API to L4.
 */

/**
 * \defgroup misc Misc functions.
 * \ingroup l4lxapi
 */


/**
 * \defgroup misc_sleep Sleeping functions.
 * \ingroup misc
 */

/**
 * \brief Sleep in milliseconds.
 * \ingroup misc_sleep
 *
 * \param	ms	Milliseconds to sleep.
 */
L4_INLINE void l4lx_sleep(int ms);

/**
 * \brief Sleep in microseconds.
 * \ingroup misc_sleep
 *
 * \param	us	Microseconds to sleep.
 */
L4_INLINE void l4lx_usleep(int us);

/**
 * \brief Sleep forever. May be interrupted through an interrupted IPC.
 * \ingroup misc_sleep
 */
L4_INLINE void l4lx_sleep_forever(void);


/*****************************************************************************
 * Include inlined implementations
 *****************************************************************************/

#include <asm/l4lxapi/impl/misc.h>

#endif /* ! __ASM_L4__L4LXAPI__MISC_H__ */
