/*
 * Kernel thread related things.
 */
#ifndef __ASM_L4__GENERIC__KTHREADS_H__
#define __ASM_L4__GENERIC__KTHREADS_H__

#include <l4/sys/types.h>

/* thread id of the linux server thread */
extern l4_threadid_t linux_server_thread_id;

/* thread id of the starter thread, also pager for all other threads */
extern l4_threadid_t l4x_start_thread_id;

#endif /* ! __ASM_L4__GENERIC__KTHREADS_H__ */
