#ifndef __ASM_L4__API_L4ENV__IDS_H__
#define __ASM_L4__API_L4ENV__IDS_H__

#include <l4/sys/types.h>

extern inline unsigned long l4x_get_taskno(l4_threadid_t tid)
{
	return tid.id.task;
}

#endif /* ! __ASM_L4__API_L4ENV__IDS_H__ */
