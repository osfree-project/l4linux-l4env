/*
 * This header files defines the IRQ functions which need to be provided by
 * every implementation of this interface.
 * The functions mostly correspond to the "struct hw_interrupt_type"
 * members.
 *
 * $Id:
 *
 */
#ifndef __ASM_L4__L4LXAPI__IRQ_H__
#define __ASM_L4__L4LXAPI__IRQ_H__

#include <asm/l4lxapi/generic/irq_gen.h>

/**
 * \defgroup irq Interrupt handling functionality.
 * \ingroup l4lxapi
 */

/**
 * \defgroup irq_dev Device IRQ handling functionality.
 * \ingroup irq
 */

/**
 * \brief Initialize the interrupt handling.
 * \ingroup irq
 */
void l4lx_irq_init(void);

/**
 * \brief Get defined priority of a certain interrupt thread.
 * \ingroup irq
 *
 * \param	irq	Interrupt.
 * \return	Defined priority of the interrupt thread.
 *
 * Every API implementation has to define this function which
 * returns the priority of the specific interrupt thread. This function does
 * not return the actual thread priority!
 */
int l4lx_irq_prio_get(unsigned int irq);

/**
 * Startup of a device IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 * \return 1 if successful, 0 on failure.
 */
unsigned int l4lx_irq_dev_startup_hw(unsigned int irq);

/**
 * Startup of a virtual IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 * \return 1 if successful, 0 on failure.
 */
unsigned int l4lx_irq_dev_startup_virt(unsigned int irq);

/**
 * \brief Shutdown of a device IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_shutdown_hw(unsigned int irq);

/**
 * \brief Shutdown of a virtual IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_shutdown_virt(unsigned int irq);

/**
 * \brief Enable a device IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_enable_hw(unsigned int irq);

/**
 * \brief Enable a virtual IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_enable_virt(unsigned int irq);

/**
 * \brief Disable a device IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_disable_hw(unsigned int irq);

/**
 * \brief Disable a virtual IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_disable_virt(unsigned int irq);

/**
 * \brief Acknowledge (and possibly mask) a device IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_ack_hw(unsigned int irq);

/**
 * \brief Acknowledge (and possibly mask) a virtual IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_ack_virt(unsigned int irq);

/**
 * \brief Mask a device IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_mask_hw(unsigned int irq);

/**
 * \brief Mask a virtual IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_mask_virt(unsigned int irq);

/**
 * \brief Unmask a device IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_unmask_hw(unsigned int irq);

/**
 * \brief Unmask a virtual IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_unmask_virt(unsigned int irq);

/**
 * \brief Unmask a device IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_end_hw(unsigned int irq);

/**
 * \brief Unmask a virtual IRQ.
 * \ingroup irq_dev
 *
 * \param irq	IRQ.
 */
void l4lx_irq_dev_end_virt(unsigned int irq);

/**
 * \defgroup irq_timer Timer interrupt functionality.
 * \ingroup  irq
 */

/**
 * \brief Startup of the timer interrupt.
 * \ingroup irq_timer
 *
 * \param irq	IRQ.
 * \return 1 if successful, 0 on failure.
 */
unsigned int l4lx_irq_timer_startup(unsigned int irq);

/**
 * \brief Shutdown of an IRQ.
 * \ingroup irq_timer
 *
 * \param irq	IRQ.
 */
void l4lx_irq_timer_shutdown(unsigned int irq);

/**
 * \brief Enable an IRQ.
 * \ingroup irq_timer
 *
 * \param irq	IRQ.
 */
void l4lx_irq_timer_enable(unsigned int irq);

/**
 * \brief Disable an IRQ.
 * \ingroup irq_timer
 *
 * \param irq	IRQ.
 */
void l4lx_irq_timer_disable(unsigned int irq);

/**
 * \brief Acknowledge (and possibly mask) an IRQ.
 * \ingroup irq_timer
 *
 * \param irq	IRQ.
 */
void l4lx_irq_timer_ack(unsigned int irq);

/**
 * \brief Mask an IRQ.
 * \ingroup irq_timer
 *
 * \param irq	IRQ.
 */
void l4lx_irq_timer_mask(unsigned int irq);

/**
 * \brief Unmask an IRQ.
 * \ingroup irq_timer
 *
 * \param irq	IRQ.
 */
void l4lx_irq_timer_unmask(unsigned int irq);

/**
 * \brief Unmask an IRQ.
 * \ingroup irq_timer
 *
 * \param irq	IRQ.
 */
void l4lx_irq_timer_end(unsigned int irq);


#endif /* ! __ASM_L4__L4LXAPI__IRQ_H__ */
