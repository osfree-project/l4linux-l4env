/*
 * Stack handling. Used by all API interfaces.
 *
 * $Id: thread_gen.c,v 1.4 2003/02/20 13:37:49 adam Exp $
 * 
 */

#include <linux/spinlock.h>
#include <linux/bitops.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/init.h>

#include <asm/l4lxapi/generic/thread_gen.h>
#include <asm/l4lxapi/thread.h>
#include <l4/sys/kdebug.h>

#define __STACKS_ARRAY_ELEM_TYPE unsigned long
#define __STACKS_ARRAY_ELEMS \
	((L4LX_THREAD_NO_THREADS / (8 * sizeof(__STACKS_ARRAY_ELEM_TYPE))) + 1)

static char l4lx_thread_stacks[L4LX_THREAD_STACK_SIZE * L4LX_THREAD_NO_THREADS]
	__attribute((aligned(L4LX_THREAD_STACK_SIZE)));
static __STACKS_ARRAY_ELEM_TYPE l4lx_thread_stacks_used[__STACKS_ARRAY_ELEMS];
/* If the thread is L4_NIL_ID the corresponding stacks isn't used */
static l4_threadid_t l4lx_thread_stack_to_thread_no[L4LX_THREAD_NO_THREADS];

/* Storage for thread names */
struct l4lx_thread_name_struct l4lx_thread_names[L4LX_THREAD_NO_THREADS] __nosavedata;

void *l4lx_thread_stack_get(void)
{
	int n;
	unsigned long flags;

	local_irq_save(flags);

	n = find_first_zero_bit(l4lx_thread_stacks_used,
				L4LX_THREAD_NO_THREADS);
	set_bit(n, l4lx_thread_stacks_used);

	local_irq_restore(flags);

	if (n >= L4LX_THREAD_NO_THREADS)
		return NULL;

	return &l4lx_thread_stacks[L4LX_THREAD_STACK_SIZE * (n + 1)];
}

void l4lx_thread_stack_register(l4_threadid_t thread, void *stack_pointer)
{
	/* Calculate array entry of this stack as returned by
	 * l4lx_thread_stack_get */
	int offset = (char *)stack_pointer - l4lx_thread_stacks;
	int n = (offset / L4LX_THREAD_STACK_SIZE);
	if (offset % L4LX_THREAD_STACK_SIZE == 0)
		n--;

	/* sanity check */
	if (n < 0 || n >= L4LX_THREAD_NO_THREADS)
		enter_kdebug("Wrong stack_pointer given?!");
	else
		/* eventually register it */
		l4lx_thread_stack_to_thread_no[n] = thread;
}

void *l4lx_thread_stack_alloc(l4_threadid_t thread)
{
	void *stack_pointer;

	if ((stack_pointer = l4lx_thread_stack_get()) == NULL)
		return NULL;

	l4lx_thread_stack_register(thread, stack_pointer);
	return stack_pointer;
}

static int l4lx_thread_stack_get_pos(l4_threadid_t thread)
{
	int i;

	/* Free used stack if it's ours */
	for (i = 0; i < L4LX_THREAD_NO_THREADS; i++) {
		if (l4lx_thread_equal(l4lx_thread_stack_to_thread_no[i],
				      thread))
			return i;
	}
	return -1;
}

void l4lx_thread_stack_return(l4_threadid_t thread)
{
	int i;

	if ((i = l4lx_thread_stack_get_pos(thread)) != -1) {
		/* Stack was used by the thread */
		l4lx_thread_stack_to_thread_no[i] = L4_NIL_ID;
		clear_bit(i, l4lx_thread_stacks_used);
	}
}

void *l4lx_thread_stack_setup_id(l4_threadid_t thread,
				void *stack_pointer)
{
	/* Put the thread id on the stack */
	stack_pointer -= sizeof(l4_threadid_t);
	*(l4_threadid_t *)stack_pointer = thread;

	return stack_pointer;
}

void *l4lx_thread_stack_setup_data(void *stack_pointer,
				   void *stack_data, unsigned stack_data_size,
				   void **data)
{
	/* Set up data section of the stack */
	if (stack_data != NULL && stack_data_size != 0) {
		/* We have to put some data onto the stack */
		stack_pointer -= stack_data_size;
		*data = memcpy(stack_pointer, stack_data, stack_data_size);
	} else {
		/* No data supplied */
		*data = NULL;
	}

	return stack_pointer;
}

void *l4lx_thread_stack_setup_thread(void *stack_pointer, void *data)
{
	/* Put the data pointer on to the stack itself as a param
	 * to the thread function.
	 */
	stack_pointer = memcpy(stack_pointer - sizeof(data),
			       &data, sizeof(data));
	/* Put fake return address on stack */
	stack_pointer = memset(stack_pointer - sizeof(void *), 0, 1);

	return stack_pointer;
}

void *l4lx_thread_stack_get_base_pointer(l4_threadid_t thread)
{
	int i;

	if ((i = l4lx_thread_stack_get_pos(thread)) == -1)
		return NULL;

	return &l4lx_thread_stacks[i];
}

/*
 * Functions for thread names.
 */
void l4lx_thread_name_set(l4_threadid_t thread, const char *name)
{
	int i = 0;

	for (; i < L4LX_THREAD_NO_THREADS; i++)
		if (l4lx_thread_equal(l4lx_thread_names[i].id, L4_NIL_ID)) {
			l4lx_thread_names[i].id = thread;
			strncpy(l4lx_thread_names[i].name, name,
				L4LX_THREAD_NAME_LEN);
			l4lx_thread_names[i].name[L4LX_THREAD_NAME_LEN-1] = 0;

			return;
		}

	enter_kdebug("Thread names exhausted!");
}

void l4lx_thread_name_delete(l4_threadid_t thread)
{
	int i = 0;

	for (; i < L4LX_THREAD_NO_THREADS; i++)
		if (l4lx_thread_equal(l4lx_thread_names[i].id, thread)) {
			l4lx_thread_names[i].id = L4_NIL_ID;
			return;
		}

	enter_kdebug("Unknown TID to delete thread name!");
}
