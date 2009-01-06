#ifndef __ASM_L4__API_L4ENV__MACROS_H__
#define __ASM_L4__API_L4ENV__MACROS_H__

/* place holder for thread id in printf */
#define PRINTF_L4TASK_FORM	"%02x.%02x"
#define PRINTF_L4TASK_ARG(t)	(t).id.task,(t).id.lthread

/* For some asm stuff */
#define SIZEOF_LONG		4
#define SIZEOF_INT		4
#define SIZEOF_ATOMIC_T		4
#define SIZEOF_L4_THREADID_T	8

#define L4_THREADID_TASKNO_MASK	0x0ffe0000

#endif /* ! __ASM_L4__API_L4ENV__MACROS_H__ */
