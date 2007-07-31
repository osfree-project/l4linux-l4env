#ifndef __ASM_L4__API_L4ENV__CONFIG_H__
#define __ASM_L4__API_L4ENV__CONFIG_H__

#include <asm/processor.h>		/* for TASK_SIZE */

/* L4 task number limits */
#define TASK_NO_MAX			255

#define UPAGE_USER_ADDRESS		(TASK_SIZE + 0x8000)
#define UPAGE_USER_ADDRESS_END		(UPAGE_USER_ADDRESS + PAGE_SIZE)

#define PAGE0_PAGE_ADDRESS		0x2000

#endif /* ! __ASM_L4__API_L4ENV__CONFIG_H__ */
