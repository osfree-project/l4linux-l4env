/*
 * linux/arch/l4/arch-i386/kernel/sysenter.c
 *
 * (C) Copyright 2002 Linus Torvalds
 * Portions based on the vdso-randomization code from exec-shield:
 * Copyright(C) 2005-2006, Red Hat, Inc., Ingo Molnar
 *
 * This file contains the needed initializations to support sysenter.
 */

#include <linux/init.h>
#include <linux/smp.h>
#include <linux/thread_info.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/elf.h>
#include <linux/mm.h>
#include <linux/module.h>

#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>

/*
 * Should the kernel map a VDSO page into processes and pass its
 * address down to glibc upon exec()?
 */
unsigned int __read_mostly vdso_enabled = 1;

EXPORT_SYMBOL_GPL(vdso_enabled);

static int __init vdso_setup(char *s)
{
	vdso_enabled = simple_strtoul(s, NULL, 0);

	return 1;
}

__setup("vdso=", vdso_setup);

extern asmlinkage void sysenter_entry(void);

void enable_sep_cpu(void)
{
#if 0
	int cpu = get_cpu();
	struct tss_struct *tss = &per_cpu(init_tss, cpu);

	if (!boot_cpu_has(X86_FEATURE_SEP)) {
		put_cpu();
		return;
	}

	tss->ss1 = __KERNEL_CS;
	tss->esp1 = sizeof(struct tss_struct) + (unsigned long) tss;
	wrmsr(MSR_IA32_SYSENTER_CS, __KERNEL_CS, 0);
	wrmsr(MSR_IA32_SYSENTER_ESP, tss->esp1, 0);
	wrmsr(MSR_IA32_SYSENTER_EIP, (unsigned long) sysenter_entry, 0);
	put_cpu();	
#endif
}

/*
 * These symbols are defined by vsyscall.o to mark the bounds
 * of the ELF DSO images included therein.
 */
extern const char vsyscall_int80_start, vsyscall_int80_end;
extern const char vsyscall_sysenter_start, vsyscall_sysenter_end;
static void *syscall_page = &_upage_start;

int __init sysenter_setup(void)
{
#if 0
	syscall_page = (void *)get_zeroed_page(GFP_ATOMIC);
#endif

#ifdef CONFIG_COMPAT_VDSO
	__set_fixmap(FIX_VDSO, __pa(syscall_page), PAGE_READONLY);
	printk("Compat vDSO mapped to %08lx.\n", __fix_to_virt(FIX_VDSO));
#else
#error Not supported (yet?)
	/*
	 * In the non-compat case the ELF coredumping code needs the fixmap:
	 */
	__set_fixmap(FIX_VDSO, __pa(syscall_page), PAGE_KERNEL_RO);
#endif

#if 0
	if (!boot_cpu_has(X86_FEATURE_SEP)) {
		memcpy(syscall_page,
		       &vsyscall_int80_start,
		       &vsyscall_int80_end - &vsyscall_int80_start);
		return 0;
	}

	memcpy(syscall_page,
	       &vsyscall_sysenter_start,
	       &vsyscall_sysenter_end - &vsyscall_sysenter_start);

#endif

	return 0;
}

static struct page *syscall_nopage(struct vm_area_struct *vma,
				unsigned long adr, int *type)
{
	struct page *p = virt_to_page(adr - vma->vm_start + syscall_page);
	get_page(p);
	return p;
}

/* Prevent VMA merging */
static void syscall_vma_close(struct vm_area_struct *vma)
{
}

static struct vm_operations_struct syscall_vm_ops = {
	.close = syscall_vma_close,
	.nopage = syscall_nopage,
};

#if 0
/* Defined in vsyscall-sysenter.S */
extern void SYSENTER_RETURN;
#endif

/* Setup a VMA at program startup for the vsyscall page */
int arch_setup_additional_pages(struct linux_binprm *bprm, int exstack)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long addr = UPAGE_USER_ADDRESS;
	int ret;

	down_write(&mm->mmap_sem);
	vma = kmem_cache_zalloc(vm_area_cachep, SLAB_KERNEL);
	if (!vma) {
		ret = -ENOMEM;
		goto up_fail;
	}

	vma->vm_start = addr;
	vma->vm_end = addr + PAGE_SIZE;
	/* MAYWRITE to allow gdb to COW and set breakpoints */
	vma->vm_flags = VM_READ|VM_EXEC|VM_MAYREAD|VM_MAYEXEC|VM_MAYWRITE;
	vma->vm_flags |= mm->def_flags;
	vma->vm_page_prot = protection_map[vma->vm_flags & 7];
	vma->vm_ops = &syscall_vm_ops;
	vma->vm_mm = mm;

	ret = insert_vm_struct(mm, vma);
	if (unlikely(ret)) {
		kmem_cache_free(vm_area_cachep, vma);
		goto up_fail;
	}

	current->mm->context.vdso = (void *)addr;
#if 0
	current_thread_info()->sysenter_return =
				    (void *)VDSO_SYM(&SYSENTER_RETURN);
#endif
	mm->total_vm++;
up_fail:
	up_write(&mm->mmap_sem);
	return ret;

	return 0;
}

const char *arch_vma_name(struct vm_area_struct *vma)
{
	if (vma->vm_mm && vma->vm_start == (long)vma->vm_mm->context.vdso)
		return "[vdso]";
	return NULL;
}

struct vm_area_struct *get_gate_vma(struct task_struct *tsk)
{
	return NULL;
}

int in_gate_area(struct task_struct *task, unsigned long addr)
{
	return 0;
}

int in_gate_area_no_task(unsigned long addr)
{
	return 0;
}
