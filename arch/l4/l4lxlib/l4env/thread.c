/*
 * Functions implementing the API defined in asm/l4lxapi/thread.h
 * for l4env.
 *
 * $Id: thread.c,v 1.8 2003/03/17 22:33:58 adam Exp $
 *
 */

#include <l4/sys/syscalls.h>
#include <l4/sys/kdebug.h>
#include <l4/env/errno.h>

#include <l4/thread/thread.h>

#include <asm/l4lxapi/thread.h>
#include <asm/l4lxapi/misc.h>
#include <asm/generic/kthreads.h>
#include <asm/api/api.h>
#include <asm/api/macros.h>

#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/string.h>

/*
 * l4lx_thread_init
 */
void l4lx_thread_init(void)
{
	/* Nothing up to now... */
}

/*
 * l4lx_threadno_to_tid
 */
l4_threadid_t inline l4lx_thread_no_to_tid(int thread_no)
{
	/* XXX */
	l4_threadid_t t;
	t.id.lthread = thread_no;
	return t;
}


/*
 * l4lx_thread_create
 */
/*
 * Some hints:
 *  Linux kernel threads all run in the same thread in L4Linux and have
 *  differend stacks (of course). Consequently, we cannot use the threadlib
 *  in its current form as it only knows about one stack per thread and
 *  would call l4_myself() all the time when other/unknown stacks are used.
 *  To avoid this, we can pursue the following ways:
 *  .  The threadlib allows to register other stacks for a thread.
 *     But that requires that the lib always loops through a list to
 *     compare the stackpointer with the stack areas. Putting the
 *     threadid on the stack is definitely faster.
 *  .  As the threadlib chooses a threadid for us, we can't put it
 *     on the stack before calling l4thread_create_long, but after creating
 *     the thread it could already be too late to do so. So we'd need some
 *     sort of call back routine which gets the threadid of the new thread
 *     and modifies the stack of the thread before it really gets started.
 *     Choosing the threadids ourselves seems not possible either, since e.g.
 *     kernel modules are permitted to use threadlib functionality directly
 *     (i.e. without going through l4lxlib), so that we can't really know
 *     which threads exist and which not (maybe we could lock threads and
 *     check for existence but I don't know if that works with non-existent
 *     ones).
 *
 *  This all looks like another pro for V4...
 */
l4_threadid_t l4lx_thread_create(void (*thread_func)(void *data),
				 void *stack_pointer,
				 void *stack_data, unsigned stack_data_size,
				 int prio,
				 const char *name)
{
	void *data, *stack_top;
	l4_threadid_t ret = linux_server_thread_id;
	l4thread_t thread_no;
	char l4lx_name[20] = "l4lx.";

	stack_top = stack_pointer;

	/* Prepare stack */
	if (stack_pointer != NULL) {
		/* copy the data onto the stack */
		stack_pointer = l4lx_thread_stack_setup_data(stack_pointer,
							     stack_data,
							     stack_data_size,
							     &data);
	} else {
		/* the threadlib is supposed to supply the stack but
		 * we need to copy the data somewhere else because the
		 * caller isn't supposed to hold the data indefinitely,
		 * we use the stack memory for that
		 * (we don't use this memory for stacks!) */
		if ((data = l4lx_thread_stack_get()) == NULL) {
			LOG_printf("%s: No more thread stacks available!\n", __func__);
			return L4_INVALID_ID;
		}
		memcpy(data, stack_data, stack_data_size);
	}

	/* Prefix name with 'l4lx.' */
	strncpy(l4lx_name + strlen(l4lx_name), name,
	        sizeof(l4lx_name) - strlen(l4lx_name));
	l4lx_name[sizeof(l4lx_name) - 1] = 0;

	if ((thread_no = l4thread_create_long
			(L4THREAD_INVALID_ID,
			 thread_func, l4lx_name,
			 (stack_pointer != NULL)
				? (l4_addr_t)stack_pointer : L4THREAD_INVALID_SP,
			 L4LX_THREAD_STACK_SIZE -
				((stack_pointer != NULL)
					? (stack_top - stack_pointer) : 0),
			 (prio == -1) ? L4THREAD_DEFAULT_PRIO : prio,
			 data,
			 L4THREAD_CREATE_ASYNC)) < 0 ) {
		LOG_printf("%s: Error creating thread '%s': %s(%d)\n",
		           __func__, name, l4env_errstr(thread_no), thread_no);
		return L4_INVALID_ID;
	}

	/* XXX: V2 stuff... */
	ret.id.lthread = thread_no;

	LOG_printf("%s: Created thread " PRINTF_L4TASK_FORM " (%s)\n",
	           __func__, PRINTF_L4TASK_ARG(ret), name);

	if (stack_pointer == NULL)
		l4lx_thread_stack_register(ret, data);

	l4lx_thread_name_set(ret, name);

	return ret;
}
EXPORT_SYMBOL(l4lx_thread_create);

/*
 * l4lx_thread_id_get
 */
inline l4_threadid_t l4lx_thread_id_get(void)
{
	return l4thread_l4_id(l4thread_myself());
}

/*
 * l4lx_thread_pager_change
 */
void l4lx_thread_pager_change(l4_threadid_t thread, l4_threadid_t pager)
{
	l4_threadid_t _pager = L4_INVALID_ID, _preempter = L4_INVALID_ID;
	l4_umword_t o;

	l4_thread_ex_regs(thread,
	                  (l4_umword_t)-1,
	                  (l4_umword_t)-1,
	                  &_preempter, &_pager,
	                  &o, &o, &o);

	l4_thread_ex_regs(thread,
	                  (l4_umword_t)-1,
	                  (l4_umword_t)-1,
	                  &_preempter, &pager,
	                  &o, &o, &o);
}

/*
 * l4lx_thread_set_kernel_pager
 */
void l4lx_thread_set_kernel_pager(l4_threadid_t thread)
{
	l4lx_thread_pager_change(thread, l4x_start_thread_id);
}

/*
 * l4lx_thread_shutdown
 */
void l4lx_thread_shutdown(l4_threadid_t thread)
{
	/* free "stack memory" used for data if there's some */
	l4lx_thread_stack_return(thread);

	/* XXX: V2 stuff */
	l4thread_shutdown(thread.id.lthread);
	l4lx_thread_name_delete(thread);
}
EXPORT_SYMBOL(l4lx_thread_shutdown);

/*
 * l4lx_thread_prio_set
 */
int l4lx_thread_prio_set(l4_threadid_t thread,
		       int prio)
{
	return l4thread_set_prio(thread.id.lthread, prio);
}

/*
 * l4lx_thread_prio_get
 */
int l4lx_thread_prio_get(l4_threadid_t thread)
{
	/* XXX: V2 stuff */
	return l4thread_get_prio(thread.id.lthread);
}

/*
 * l4lx_thread_cpu_set
 */
int l4lx_thread_cpu_set(l4_threadid_t thread, int cpu)
{
	return 0;
}
