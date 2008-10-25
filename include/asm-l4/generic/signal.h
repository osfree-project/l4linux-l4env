#ifndef __ASM_L4__GENERIC__SIGNAL_H__
#define __ASM_L4__GENERIC__SIGNAL_H__

#ifdef ARCH_x86
void do_signal(struct pt_regs *regs);
#endif

#ifdef ARCH_arm
int do_signal(sigset_t *oldset, struct pt_regs *regs, int syscall);
#endif

#endif /* ! __ASM_L4__GENERIC__SIGNAL_H__ */
