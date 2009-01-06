#ifndef __ASM_L4__GENERIC__IRQ_H__
#define __ASM_L4__GENERIC__IRQ_H__

#define L4_IRQ_DISABLED 0
#define L4_IRQ_ENABLED  1

#define TIMER_IRQ	0

#define l4x_irq_flag(cpu) __IRQ_STAT((cpu), __l4x_irq_flag)

void l4x_local_irq_disable(void);
void l4x_local_irq_enable(void);
unsigned long l4x_local_save_flags(void);
void l4x_local_irq_restore(unsigned long flags);

/* --------------------------------------- */
/* More or less for ARM only */

void l4x_setup_virt_irq(unsigned int irq);
void l4x_setup_dev_irq(unsigned int irq);

#endif /* ! __ASM_L4__GENERIC__IRQ_H__ */
