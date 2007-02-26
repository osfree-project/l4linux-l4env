#ifndef __ASM_L4__L4X_I386__EXCEPTION_H__
#define __ASM_L4__L4X_I386__EXCEPTION_H__

#include <asm/ptrace.h>

#include <l4/sys/utcb.h>

enum l4x_cpu_modes {
	L4X_MODE_KERNEL = 0,
	L4X_MODE_USER   = 3,
};

static inline void l4x_set_cpu_mode(struct pt_regs *r, enum l4x_cpu_modes mode)
{
	r->xcs = mode;
}

static inline void l4x_set_user_mode(struct pt_regs *r)
{
	l4x_set_cpu_mode(r, L4X_MODE_USER);
}

static inline void l4x_set_kernel_mode(struct pt_regs *r)
{
	l4x_set_cpu_mode(r, L4X_MODE_KERNEL);
}

static inline unsigned long l4x_get_cpu_mode(struct pt_regs *r)
{
	return r->xcs & 3;
}

#define U2P(p, u, r)   do { p->r = u->exc.r; } while (0)
static inline void utcb_to_ptregs(l4_utcb_t *utcb, struct pt_regs *ptregs)
{
	U2P(ptregs, utcb, eax);
	U2P(ptregs, utcb, ebx);
	U2P(ptregs, utcb, ecx);
	U2P(ptregs, utcb, edx);
	U2P(ptregs, utcb, edi);
	U2P(ptregs, utcb, esi);
	U2P(ptregs, utcb, ebp);
	U2P(ptregs, utcb, eip);
	U2P(ptregs, utcb, eflags);
	U2P(ptregs, utcb, esp);
}
#undef U2P

#define P2U(u, p, r) do { u->exc.r = p->r; } while (0)
static inline void ptregs_to_utcb(struct pt_regs *ptregs, l4_utcb_t *utcb)
{
	P2U(utcb, ptregs, eax);
	P2U(utcb, ptregs, ebx);
	P2U(utcb, ptregs, ecx);
	P2U(utcb, ptregs, edx);
	P2U(utcb, ptregs, edi);
	P2U(utcb, ptregs, esi);
	P2U(utcb, ptregs, ebp);
	P2U(utcb, ptregs, eip);
	P2U(utcb, ptregs, eflags);
	P2U(utcb, ptregs, esp);
}
#undef P2U

#endif /* ! __ASM_L4__L4X_I386__EXCEPTION_H__ */
