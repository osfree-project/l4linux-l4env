/*
 * Legacy functions.
 *
 * WARNING: Do not use this functions in L4Linux!
 *
 * $Id: legacy.c,v 1.1 2002/08/10 20:02:18 adam Exp $
 */

#include <asm/l4lxapi/misc.h>

/*
 * Some libs/code from the DROPS tree which is linked to L4Linux
 * needs l4_sleep...
 */
void l4_sleep(int ms)
{
	l4lx_sleep(ms);
}
