
#include <asm/processor.h>

/* Configure place for the L4RM heap, put it above our main memory
 * dataspace, so that the address space below is small.
 */
const l4_addr_t l4rm_heap_start_addr = TASK_SIZE - (4 << 20);

/* Also put thread data at the end of the address space */
const l4_addr_t l4thread_stack_area_addr = TASK_SIZE - (256 << 20);
const l4_addr_t	l4thread_tcb_table_addr  = TASK_SIZE - (260 << 20);

/* Set max amount of threads which can be created, weak symbol from
 * thread library */
const int l4thread_max_threads = 128;
