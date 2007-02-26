/*
 * Architecture specific handling for tamed mode for i386.
 */
#ifndef __ASM_L4__L4X_I386__TAMED_H__
#define __ASM_L4__L4X_I386__TAMED_H__

#ifndef L4X_TAMED_LABEL
#error Only use from within tamed.c!
#endif

static inline void l4x_tamed_sem_down(void)
{
	unsigned dummy1, dummy2, dummy3;

	asm volatile
	  (
	   "1:                         \n\t"
	   "decl    0(%%edx)           \n\t"        /* decrement counter */
	   "jge     2f                 \n\t"

#ifdef CONFIG_L4_DEBUG_TAMED_COUNT_INTERRUPT_DISABLE
	   "incl    cli_taken          \n\t"
#endif
	   "pushl   %%ebx              \n\t"
	   "pushl   %%eax              \n\t"
	   "pushl   %%edx              \n\t"
	   "pushl   %%ebp              \n\t"

	   "xorl    %%eax,%%eax        \n\t"        /* short send */
	   "xorl    %%ebp,%%ebp        \n\t"        /* short receive */
	   "movl    $1,%%edx           \n\t"        /* dw0 -> L4SEMAPHORE_BLOCK */
	   "movl    %%ecx,%%ebx        \n\t"        /* dw1 -> prio */
	   "xorl    %%ecx,%%ecx        \n\t"        /* timeout never */

	   IPC_SYSENTER

	   "cmp     $1, %%edx          \n\t"
	   "popl    %%ebp              \n\t"
	   "popl    %%edx              \n\t"
	   "popl    %%eax              \n\t"
	   "popl    %%ebx              \n\t"
	   "je      2f                 \n\t"
	   "jmp     1b                 \n\t"

	   "2:                         \n\t"
	   : "=c" (dummy1), "=D" (dummy2), "=S" (dummy3)
	   : "c"  (l4x_stack_prio_get()),
	     "d"  (&cli_lock.sem),
	     "D"  (cli_sem_thread_id.lh.high), "S"  (cli_sem_thread_id.lh.low)
	   : "memory");
}


static inline void l4x_tamed_sem_up(void)
{
	unsigned dummy1, dummy2, dummy3;

	asm volatile
	  (
	   "incl    0(%%edx)           \n\t"        /* increment counter */
	   "jg      2f                 \n\t"

	   "pushl   %%ebx              \n\t"
	   "pushl   %%eax              \n\t"
	   "pushl   %%edx              \n\t"
	   "pushl   %%ebp              \n\t"

	   "xorl    %%eax,%%eax        \n\t"        /* short send */
	   "xorl    %%ebp,%%ebp        \n\t"        /* short receive */
	   "movl    $2,%%edx           \n\t"        /* dw0 -> L4SEMAPHORE_RELEASE */
	   "movl    %%ecx,%%ebx        \n\t"        /* dw1 -> prio */
	   "xorl    %%ecx,%%ecx        \n\t"        /* timeout never */

	   IPC_SYSENTER

	   "popl    %%ebp              \n\t"
	   "popl    %%edx              \n\t"
	   "popl    %%eax              \n\t"
	   "popl    %%ebx              \n\t"

	   "2:                         \n\t"
	   : "=c" (dummy1), "=D" (dummy2), "=S" (dummy3)
	   : "c"  (l4x_stack_prio_get()),
	     "d"  (&cli_lock.sem),
	     "D"  (cli_sem_thread_id.lh.high), "S"  (cli_sem_thread_id.lh.low)
	   : "memory");
}
#endif /* ! __ASM_L4__L4X_I386__TAMED_H__ */
