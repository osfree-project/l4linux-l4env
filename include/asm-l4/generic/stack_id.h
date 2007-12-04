#ifndef __ASM_L4__GENERIC__STACK_ID_H__
#define __ASM_L4__GENERIC__STACK_ID_H__

#include <asm/thread_info.h>
#include <l4/sys/syscalls.h>
#include <asm/l4lxapi/thread.h>

struct l4x_stack_struct {
	l4_threadid_t l4id;
	unsigned int  l4prio;
};

static inline
struct l4x_stack_struct *l4x_stack_struct_get(struct thread_info *ti)
{
	/* struct is just after the thread_info struct on the stack */
	return (struct l4x_stack_struct *)(ti + 1);
}

static inline void l4x_stack_setup(struct thread_info *ti)
{
	struct l4x_stack_struct *s = l4x_stack_struct_get(ti);
	s->l4id   = l4_myself();
	s->l4prio = l4lx_thread_prio_get(s->l4id);
}

static inline l4_threadid_t l4x_stack_id_get(void)
{
	return l4x_stack_struct_get(current_thread_info())->l4id;
}

static inline unsigned int l4x_stack_prio_get(void)
{
	return l4x_stack_struct_get(current_thread_info())->l4prio;
}

#endif /* ! __ASM_L4__GENERIC__STACK_ID_H__ */
