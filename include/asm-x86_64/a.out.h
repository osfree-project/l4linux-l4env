#ifndef __X8664_A_OUT_H__
#define __X8664_A_OUT_H__

/* 32bit a.out */

struct exec
{
  unsigned int a_info;		/* Use macros N_MAGIC, etc for access */
  unsigned a_text;		/* length of text, in bytes */
  unsigned a_data;		/* length of data, in bytes */
  unsigned a_bss;		/* length of uninitialized data area for file, in bytes */
  unsigned a_syms;		/* length of symbol table data in file, in bytes */
  unsigned a_entry;		/* start address */
  unsigned a_trsize;		/* length of relocation info for text, in bytes */
  unsigned a_drsize;		/* length of relocation info for data, in bytes */
};

#define N_TRSIZE(a)	((a).a_trsize)
#define N_DRSIZE(a)	((a).a_drsize)
#define N_SYMSIZE(a)	((a).a_syms)

#ifdef __KERNEL__
#include <linux/thread_info.h>
#define STACK_TOP	TASK_SIZE
#define STACK_TOP_MAX	TASK_SIZE64
#endif

#endif /* __A_OUT_GNU_H__ */
