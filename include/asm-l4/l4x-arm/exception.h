#ifndef __ASM_L4__L4X_ARM__EXCEPTION_H__
#define __ASM_L4__L4X_ARM__EXCEPTION_H__

#include <asm/ptrace.h>

#include <l4/sys/utcb.h>

struct l4x_exception_msg {
	l4_fpage_t fp;
	l4_msgdope_t size_dope;
	l4_msgdope_t send_dope;
	l4_umword_t words[3];
	l4_strdope_t excp_regs;
};

static inline void l4x_setup_ipc_descriptor(struct l4x_exception_msg *msg,
                                            l4_utcb_t *utcb)
{
	msg->size_dope          = L4_IPC_DOPE(3, 1);
	msg->send_dope          = L4_IPC_DOPE(3, 1);
	msg->excp_regs.rcv_size = sizeof(struct l4_utcb_exception);
	msg->excp_regs.rcv_str  = (unsigned long)utcb;
	msg->excp_regs.snd_size = sizeof(struct l4_utcb_exception);
	msg->excp_regs.snd_str  = (unsigned long)utcb;
}

enum l4x_cpu_modes {
	L4X_MODE_KERNEL = SYSTEM_MODE,
	L4X_MODE_USER   = USR_MODE,
};

static inline void l4x_set_cpu_mode(struct pt_regs *r, enum l4x_cpu_modes mode)
{
	r->ARM_cpsr = (r->ARM_cpsr & ~MODE_MASK) | (mode & MODE_MASK);
}

static inline void l4x_set_user_mode(struct pt_regs *r)
{
	l4x_set_cpu_mode(r, USR_MODE);
}

static inline void l4x_set_kernel_mode(struct pt_regs *r)
{
	l4x_set_cpu_mode(r, SYSTEM_MODE);
}

static inline unsigned long l4x_get_cpu_mode(struct pt_regs *r)
{
	return processor_mode(r);
}

static inline void utcb_to_ptregs(l4_utcb_t *utcb, struct pt_regs *ptregs)
{
	/* TODO: compactify this to a memcpy */
	ptregs->uregs[0]  = utcb->exc.r[0];
	ptregs->uregs[1]  = utcb->exc.r[1];
	ptregs->uregs[2]  = utcb->exc.r[2];
	ptregs->uregs[3]  = utcb->exc.r[3];
	ptregs->uregs[4]  = utcb->exc.r[4];
	ptregs->uregs[5]  = utcb->exc.r[5];
	ptregs->uregs[6]  = utcb->exc.r[6];
	ptregs->uregs[7]  = utcb->exc.r[7];
	ptregs->uregs[8]  = utcb->exc.r[8];
	ptregs->uregs[9]  = utcb->exc.r[9];
	ptregs->uregs[10] = utcb->exc.r[10];
	ptregs->uregs[11] = utcb->exc.r[11];
	ptregs->uregs[12] = utcb->exc.r[12];
	ptregs->ARM_sp    = utcb->exc.sp;
	ptregs->ARM_lr    = utcb->exc.ulr;
	ptregs->ARM_pc    = utcb->exc.pc;
	// disable IRQ and FIQ, for valid_user_regs(regsp)
	ptregs->ARM_cpsr  = utcb->exc.cpsr & ~(PSR_F_BIT|PSR_I_BIT);
}

static inline void ptregs_to_utcb(struct pt_regs *ptregs, l4_utcb_t *utcb)
{
	/* TODO: compactify this to a memcpy */
	utcb->exc.r[0]  = ptregs->uregs[0];
	utcb->exc.r[1]  = ptregs->uregs[1];
	utcb->exc.r[2]  = ptregs->uregs[2];
	utcb->exc.r[3]  = ptregs->uregs[3];
	utcb->exc.r[4]  = ptregs->uregs[4];
	utcb->exc.r[5]  = ptregs->uregs[5];
	utcb->exc.r[6]  = ptregs->uregs[6];
	utcb->exc.r[7]  = ptregs->uregs[7];
	utcb->exc.r[8]  = ptregs->uregs[8];
	utcb->exc.r[9]  = ptregs->uregs[9];
	utcb->exc.r[10] = ptregs->uregs[10];
	utcb->exc.r[11] = ptregs->uregs[11];
	utcb->exc.r[12] = ptregs->uregs[12];
	utcb->exc.sp    = ptregs->ARM_sp;
	utcb->exc.ulr   = ptregs->ARM_lr;
	utcb->exc.pc    = ptregs->ARM_pc;
	utcb->exc.cpsr  = ptregs->ARM_cpsr;
}

#endif /* ! __ASM_L4__L4X_ARM__EXCEPTION_H__ */
