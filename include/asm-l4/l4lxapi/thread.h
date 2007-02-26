/*
 * This header file defines the L4Linux internal interface
 * for thread management. All API must implement it.
 *
 * $Id: thread.h,v 1.5 2003/03/17 22:37:40 adam Exp $
 */
#ifndef __ASM_L4__L4LXAPI__THREAD_H__
#define __ASM_L4__L4LXAPI__THREAD_H__

#include <l4/sys/types.h>

/* Convenience include */
#include <asm/l4lxapi/generic/thread_gen.h>

/**
 * \defgroup thread Thread management functions.
 * \ingroup l4lxapi
 */


/**
 * \brief Initialize thread handling.
 * \ingroup thread
 *
 * Call before any thread is created.
 */
void l4lx_thread_init(void);

/**
 * \brief Create a thread.
 * \ingroup thread
 * 
 * \param thread_func	Thread function.
 * \param stack_pointer	The stack, if set to NULL a stack will be allocated.
 * 			This is the stack pointer from the top of the stack
 * 			which means that you can put other data on the top
 * 			of the stack yourself. If you supply your stack
 * 			yourself you have to make sure your stack is big
 * 			enough.
 * \param stack_data	Pointer to some data which will be copied to the
 *			stack. It can be used to transfer data to your new
 *			thread.
 * \param stack_data_size Size of your data pointed to by the stack_data
 * 			pointer.
 * \param prio		Priority of the thread. If set to -1 the default
 * 			priority will be choosen (i.e. no prio will be set).
 * \param name		String describing the thread. Only used for
 * 			debugging purposes.
 *
 * \return Thread ID of the new thread, L4_INVALID_ID if an error occured.
 *
 * The stack layout for non L4Env threads:
 *
 * <pre>
 * Stack                                    Stack
 * bottom                                    top
 * ___________________________________...._____
 * |                            | | |      |  |
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *      <===============       ^ ^ ^   ^     ^
 *         Stack growth        | | |   |     |--- thread ID (not always)
 *                             | | |   |--------- data for new thread
 *                             | | |------------- pointer of data section
 *                             | | 		  given to the new thread
 *                             | |--------------- fake return address
 *                             |----------------- ESP for new thread
 * </pre>
 */
l4_threadid_t l4lx_thread_create(void (*thread_func)(void *data),
				 void *stack_pointer,
				 void *stack_data, unsigned stack_data_size,
				 int prio,
				 const char *name);

/**
 * \brief Get the thread id of the (current) thread.
 * \ingroup thread
 *
 * \return The thread id.
 *
 * This function returns the thread id of the current thread.
 * On APIs where l4_myself() is fast it calls l4_myself directly.
 * When l4_myself() is slow (V2) the thread id is stored on top of the
 * stack when the thread is created and is then taken from there.
 */
l4_threadid_t l4lx_thread_id_get(void);

/**
 * \brief Convert thread number to threadid.
 * \ingroup thread
 *
 * \param thread_no	Thread number.
 *
 * \return The thread id created from the thread number. Note that all
 * fields of the thread id except the thread number are undefined.
 *
 * XXX: ...
 */
l4_threadid_t l4lx_thread_no_to_tid(int thread_no);

/**
 * \brief Change the pager of a (kernel) thread.
 * \ingroup thread
 *
 * \param thread	Thread to modify.
 * \param pager		Pager thread.
 */
void l4lx_thread_pager_change(l4_threadid_t thread, l4_threadid_t pager);

/**
 * \brief Change pager of given thread to the kernel pager.
 * \ingroup thread
 *
 * \param thread        Thread to modify.
 */
void l4lx_thread_set_kernel_pager(l4_threadid_t thread);

/**
 * \brief Shutdown a thread.
 * \ingroup thread
 *
 * \param thread	Thread id of the thread to kill.
 */
void l4lx_thread_shutdown(l4_threadid_t thread);

/**
 * \brief Set the priority of a thread.
 * \ingroup thread
 *
 * \param  thread	Id of the thread.
 * \param  prio		Priority to set.
 *
 * \return 0 on success.
 */
int l4lx_thread_prio_set(l4_threadid_t thread,
			 int prio);

/**
 * \brief Get the priority of the thread.
 * \ingroup thread
 *
 * \param  thread	Id of the thread.
 * 
 * \return Priority of the thread (>=0), error code otherwise (< 0)
 */
int l4lx_thread_prio_get(l4_threadid_t thread);

/**
 * \brief Migrates a thread to a certain processor
 * \ingroup thread
 *
 * \param thread	Id of the thread
 * \param cpu		Id of the processor
 *
 * \return 0 on success.
 */
int l4lx_thread_cpu_set(l4_threadid_t thread, int cpu);

/**
 * \brief Check if two thread ids are equal. Do not use with different
 *        tasks (at least in L4ENV)!
 * \ingroup thread
 *
 * \param  t1		Thread 1.
 * \param  t2		Thread 2.
 *
 * \return 1 if threads are equal, 0 if not.
 */
L4_INLINE int l4lx_thread_equal(l4_threadid_t t1, l4_threadid_t t2);


/*****************************************************************************
 * Include inlined implementations
 *****************************************************************************/

#include <asm/l4lxapi/impl/thread.h>

#endif /* ! __ASM_L4__L4LXAPI__THREAD_H__ */
