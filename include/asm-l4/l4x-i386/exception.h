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
	r->cs = mode;
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
	return r->cs & 3;
}

static inline void l4x_make_up_kernel_regs(struct pt_regs *r)
{
	l4x_set_cpu_mode(r, L4X_MODE_KERNEL);
	r->ip = (unsigned long)__builtin_return_address(0);
	r->sp = current_stack_pointer;
	r->flags = native_save_fl();
}

#define U2P(p, pr, u, ur)   do { p->pr = u->exc.ur; } while (0)
static inline void utcb_to_ptregs(l4_utcb_t *utcb, struct pt_regs *ptregs)
{
	U2P(ptregs, ax,    utcb, eax);
	U2P(ptregs, bx,    utcb, ebx);
	U2P(ptregs, cx,    utcb, ecx);
	U2P(ptregs, dx,    utcb, edx);
	U2P(ptregs, di,    utcb, edi);
	U2P(ptregs, si,    utcb, esi);
	U2P(ptregs, bp,    utcb, ebp);
	U2P(ptregs, ip,    utcb, eip);
	U2P(ptregs, flags, utcb, eflags);
	U2P(ptregs, sp,    utcb, esp);
	ptregs->fs = utcb->exc.fs;
}
#undef U2P

#define P2U(u, ur, p, pr) do { u->exc.ur = p->pr; } while (0)
static inline void ptregs_to_utcb(struct pt_regs *ptregs, l4_utcb_t *utcb)
{
	P2U(utcb, eax,    ptregs, ax);
	P2U(utcb, ebx,    ptregs, bx);
	P2U(utcb, ecx,    ptregs, cx);
	P2U(utcb, edx,    ptregs, dx);
	P2U(utcb, edi,    ptregs, di);
	P2U(utcb, esi,    ptregs, si);
	P2U(utcb, ebp,    ptregs, bp);
	P2U(utcb, eip,    ptregs, ip);
	P2U(utcb, eflags, ptregs, flags);
	P2U(utcb, esp,    ptregs, sp);
	utcb->exc.fs = ptregs->fs;
}
#undef P2U

#endif /* ! __ASM_L4__L4X_I386__EXCEPTION_H__ */
