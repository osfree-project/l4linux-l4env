/*
 * include/asm-l4/arch-i386/processor.h
 *
 *
 */

#ifndef __ASM_L4__ARCH_I386__PROCESSOR_H__
#define __ASM_L4__ARCH_I386__PROCESSOR_H__

#include <asm/vm86.h>
#include <asm/math_emu.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <asm/types.h>
#include <asm/sigcontext.h>
#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/system.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <asm/percpu.h>
#include <asm/ptrace.h>

#include <l4/sys/types.h>

struct l4x_iodb;

/* flag for disabling the tsc */
extern int tsc_disable;

struct desc_struct {
	unsigned long a,b;
};

#define desc_empty(desc) \
		(!((desc)->a | (desc)->b))

#define desc_equal(desc1, desc2) \
		(((desc1)->a == (desc2)->a) && ((desc1)->b == (desc2)->b))
/*
 * Default implementation of macro that returns current
 * instruction pointer ("program counter").
 */
#define current_text_addr() ({ void *pc; __asm__("movl $1f,%0\n1:":"=g" (pc)); pc; })

/*
 *  CPU type and hardware bug flags. Kept separately for each CPU.
 *  Members of this structure are referenced in head.S, so think twice
 *  before touching them. [mj]
 */

struct cpuinfo_x86 {
	__u8	x86;		/* CPU family */
	__u8	x86_vendor;	/* CPU vendor */
	__u8	x86_model;
	__u8	x86_mask;
	char	wp_works_ok;	/* It doesn't on 386's */
	char	hlt_works_ok;	/* Problems on some 486Dx4's and old 386's */
	char	hard_math;
	char	rfu;
       	int	cpuid_level;	/* Maximum supported CPUID level, -1=no CPUID */
	unsigned long	x86_capability[NCAPINTS];
	char	x86_vendor_id[16];
	char	x86_model_id[64];
	int 	x86_cache_size;  /* in KB - valid for CPUS which support this
				    call  */
	int 	x86_cache_alignment;	/* In bytes */
	char	fdiv_bug;
	char	f00f_bug;
	char	coma_bug;
	char	pad0;
	int	x86_power;
	unsigned long loops_per_jiffy;
#ifdef CONFIG_SMP
	cpumask_t llc_shared_map;	/* cpus sharing the last level cache */
#endif
	unsigned char x86_max_cores;	/* cpuid returned max cores value */
	unsigned char apicid;
#ifdef CONFIG_SMP
	unsigned char booted_cores;	/* number of cores as seen by OS */
	__u8 phys_proc_id; 		/* Physical processor id. */
	__u8 cpu_core_id;  		/* Core id */
#endif
} __attribute__((__aligned__(SMP_CACHE_BYTES)));

#define X86_VENDOR_INTEL 0
#define X86_VENDOR_CYRIX 1
#define X86_VENDOR_AMD 2
#define X86_VENDOR_UMC 3
#define X86_VENDOR_NEXGEN 4
#define X86_VENDOR_CENTAUR 5
#define X86_VENDOR_RISE 6
#define X86_VENDOR_TRANSMETA 7
#define X86_VENDOR_NSC 8
#define X86_VENDOR_NUM 9
#define X86_VENDOR_UNKNOWN 0xff

/*
 * capabilities of CPUs
 */

extern struct cpuinfo_x86 boot_cpu_data;
extern struct cpuinfo_x86 new_cpu_data;
extern struct tss_struct doublefault_tss;
DECLARE_PER_CPU(struct tss_struct, init_tss);

#ifdef CONFIG_SMP
extern struct cpuinfo_x86 cpu_data[];
#define current_cpu_data cpu_data[smp_processor_id()]
#else
#define cpu_data (&boot_cpu_data)
#define current_cpu_data boot_cpu_data
#endif

extern	int cpu_llc_id[NR_CPUS];
extern char ignore_fpu_irq;

extern void identify_cpu(struct cpuinfo_x86 *);
extern void print_cpu_info(struct cpuinfo_x86 *);
extern unsigned int init_intel_cacheinfo(struct cpuinfo_x86 *c);
extern unsigned short num_cache_leaves;

#ifdef CONFIG_X86_HT
extern void detect_ht(struct cpuinfo_x86 *c);
#else
static inline void detect_ht(struct cpuinfo_x86 *c) {}
#endif

/*
 * EFLAGS bits
 */
#define X86_EFLAGS_CF	0x00000001 /* Carry Flag */
#define X86_EFLAGS_PF	0x00000004 /* Parity Flag */
#define X86_EFLAGS_AF	0x00000010 /* Auxillary carry Flag */
#define X86_EFLAGS_ZF	0x00000040 /* Zero Flag */
#define X86_EFLAGS_SF	0x00000080 /* Sign Flag */
#define X86_EFLAGS_TF	0x00000100 /* Trap Flag */
#define X86_EFLAGS_IF	0x00000200 /* Interrupt Flag */
#define X86_EFLAGS_DF	0x00000400 /* Direction Flag */
#define X86_EFLAGS_OF	0x00000800 /* Overflow Flag */
#define X86_EFLAGS_IOPL	0x00003000 /* IOPL mask */
#define X86_EFLAGS_NT	0x00004000 /* Nested Task */
#define X86_EFLAGS_RF	0x00010000 /* Resume Flag */
#define X86_EFLAGS_VM	0x00020000 /* Virtual Mode */
#define X86_EFLAGS_AC	0x00040000 /* Alignment Check */
#define X86_EFLAGS_VIF	0x00080000 /* Virtual Interrupt Flag */
#define X86_EFLAGS_VIP	0x00100000 /* Virtual Interrupt Pending */
#define X86_EFLAGS_ID	0x00200000 /* CPUID detection flag */

static inline void __cpuid(unsigned int *eax, unsigned int *ebx,
			   unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	__asm__("cpuid"
		: "=a" (*eax),
		  "=b" (*ebx),
		  "=c" (*ecx),
		  "=d" (*edx)
		: "0" (*eax), "2" (*ecx));
}

/*
 * Generic CPUID function
 * clear %ecx since some cpus (Cyrix MII) do not set or clear %ecx
 * resulting in stale register contents being returned.
 */
static inline void cpuid(unsigned int op, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = 0;
	__cpuid(eax, ebx, ecx, edx);
}

/* Some CPUID calls want 'count' to be placed in ecx */
static inline void cpuid_count(int op, int count, int *eax, int *ebx, int *ecx,
			       int *edx)
{
	*eax = op;
	*ecx = count;
	__cpuid(eax, ebx, ecx, edx);
}

/*
 * CPUID functions returning a single datum
 */
static inline unsigned int cpuid_eax(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return eax;
}
static inline unsigned int cpuid_ebx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return ebx;
}
static inline unsigned int cpuid_ecx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return ecx;
}
static inline unsigned int cpuid_edx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);
	return edx;
}

#define load_cr3(pgdir) write_cr3(__pa(pgdir))

/*
 * Intel CPU features in CR4
 */
#define X86_CR4_VME		0x0001	/* enable vm86 extensions */
#define X86_CR4_PVI		0x0002	/* virtual interrupts flag enable */
#define X86_CR4_TSD		0x0004	/* disable time stamp at ipl 3 */
#define X86_CR4_DE		0x0008	/* enable debugging extensions */
#define X86_CR4_PSE		0x0010	/* enable page size extensions */
#define X86_CR4_PAE		0x0020	/* enable physical address extensions */
#define X86_CR4_MCE		0x0040	/* Machine check enable */
#define X86_CR4_PGE		0x0080	/* enable global pages */
#define X86_CR4_PCE		0x0100	/* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR		0x0200	/* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT	0x0400	/* enable unmasked SSE exceptions */

/*
 * Save the cr4 feature set we're using (ie
 * Pentium 4MB enable and PPro Global page
 * enable), so that any CPU's that boot up
 * after us can get the correct flags.
 */
extern unsigned long mmu_cr4_features;

static inline void set_in_cr4 (unsigned long mask)
{
	unsigned cr4;
	mmu_cr4_features |= mask;
	cr4 = read_cr4();
	cr4 |= mask;
	write_cr4(cr4);
}

static inline void clear_in_cr4 (unsigned long mask)
{
	unsigned cr4;
	mmu_cr4_features &= ~mask;
	cr4 = read_cr4();
	cr4 &= ~mask;
	write_cr4(cr4);
}

/*
 *      NSC/Cyrix CPU configuration register indexes
 */

#define CX86_PCR0 0x20
#define CX86_GCR  0xb8
#define CX86_CCR0 0xc0
#define CX86_CCR1 0xc1
#define CX86_CCR2 0xc2
#define CX86_CCR3 0xc3
#define CX86_CCR4 0xe8
#define CX86_CCR5 0xe9
#define CX86_CCR6 0xea
#define CX86_CCR7 0xeb
#define CX86_PCR1 0xf0
#define CX86_DIR0 0xfe
#define CX86_DIR1 0xff
#define CX86_ARR_BASE 0xc4
#define CX86_RCR_BASE 0xdc

/*
 *      NSC/Cyrix CPU indexed register access macros
 */

#define getCx86(reg) ({ outb((reg), 0x22); inb(0x23); })

#define setCx86(reg, data) do { \
	outb((reg), 0x22); \
	outb((data), 0x23); \
} while (0)

/* Stop speculative execution */
static inline void sync_core(void)
{
	int tmp;
	asm volatile("cpuid" : "=a" (tmp) : "0" (1) : "ebx","ecx","edx","memory");
}

static inline void __monitor(const void *eax, unsigned long ecx,
		unsigned long edx)
{
	BUG();
}

static inline void __mwait(unsigned long eax, unsigned long ecx)
{
	BUG();
}

extern void mwait_idle_with_hints(unsigned long eax, unsigned long ecx);

/* from system description table in BIOS.  Mostly for MCA use, but
others may find it useful. */
extern unsigned int machine_id;
extern unsigned int machine_submodel_id;
extern unsigned int BIOS_revision;
extern unsigned int mca_pentium_flag;

/* Boot loader type from the setup header */
extern int bootloader_type;

/*
 * User space process size:
 */
#define TASK_SIZE	(0xBFC00000UL)

/* This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE	(PAGE_ALIGN(TASK_SIZE / 3))

#define HAVE_ARCH_PICK_MMAP_LAYOUT

/*
 * Size of io_bitmap.
 */
#define IO_BITMAP_BITS  65536
#define IO_BITMAP_BYTES (IO_BITMAP_BITS/8)
#define IO_BITMAP_LONGS (IO_BITMAP_BYTES/sizeof(long))
#define IO_BITMAP_OFFSET offsetof(struct tss_struct,io_bitmap)
#define INVALID_IO_BITMAP_OFFSET 0x8000
#define INVALID_IO_BITMAP_OFFSET_LAZY 0x9000

struct i387_fsave_struct {
	long	cwd;
	long	swd;
	long	twd;
	long	fip;
	long	fcs;
	long	foo;
	long	fos;
	long	st_space[20];	/* 8*10 bytes for each FP-reg = 80 bytes */
	long	status;		/* software status information */
};

struct i387_fxsave_struct {
	unsigned short	cwd;
	unsigned short	swd;
	unsigned short	twd;
	unsigned short	fop;
	long	fip;
	long	fcs;
	long	foo;
	long	fos;
	long	mxcsr;
	long	mxcsr_mask;
	long	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
	long	xmm_space[32];	/* 8*16 bytes for each XMM-reg = 128 bytes */
	long	padding[56];
} __attribute__ ((aligned (16)));

struct i387_soft_struct {
	long	cwd;
	long	swd;
	long	twd;
	long	fip;
	long	fcs;
	long	foo;
	long	fos;
	long	st_space[20];	/* 8*10 bytes for each FP-reg = 80 bytes */
	unsigned char	ftop, changed, lookahead, no_update, rm, alimit;
	struct info	*info;
	unsigned long	entry_eip;
};

union i387_union {
	struct i387_fsave_struct	fsave;
	struct i387_fxsave_struct	fxsave;
	struct i387_soft_struct soft;
};

typedef struct {
	unsigned long seg;
} mm_segment_t;

//struct thread_struct;

/* just to make asm-offsets work unmodified */
struct tss_struct {
	unsigned short	back_link,__blh;
	unsigned long	esp0;
	unsigned short	ss0,__ss0h;
	unsigned long	esp1;
	unsigned short	ss1,__ss1h;	/* ss1 is used to cache MSR_IA32_SYSENTER_CS */
	unsigned long	esp2;
	unsigned short	ss2,__ss2h;
	unsigned long	__cr3;
	unsigned long	eip;
	unsigned long	eflags;
	unsigned long	eax,ecx,edx,ebx;
	unsigned long	esp;
	unsigned long	ebp;
	unsigned long	esi;
	unsigned long	edi;
	unsigned short	es, __esh;
	unsigned short	cs, __csh;
	unsigned short	ss, __ssh;
	unsigned short	ds, __dsh;
	unsigned short	fs, __fsh;
	unsigned short	gs, __gsh;
	unsigned short	ldt, __ldth;
	unsigned short	trace, io_bitmap_base;
	/*
	 * The extra 1 is there because the CPU will access an
	 * additional byte beyond the end of the IO permission
	 * bitmap. The extra byte must be all 1 bits, and must
	 * be within the limit.
	 */
	unsigned long	io_bitmap[IO_BITMAP_LONGS + 1];
	/*
	 * Cache the current maximum and the last task that used the bitmap:
	 */
	unsigned long io_bitmap_max;
	struct thread_struct *io_bitmap_owner;
	/*
	 * pads the TSS to be cacheline-aligned (size is 0x100)
	 */
	unsigned long __cacheline_filler[35];
	/*
	 * .. and then another 0x100 bytes for emergency kernel stack
	 */
	unsigned long stack[64];
} __attribute__((packed));

#define ARCH_MIN_TASKALIGN	16

struct thread_struct {
	struct desc_struct tls_array[GDT_ENTRY_TLS_ENTRIES];
	unsigned long kernel_sp;		/* Kernel stack pointer */
	l4_threadid_t user_thread_id;		/* L4 Thread ID of the process */
	unsigned int initial_state_set : 1;	/* 1 if initial state was set */
	unsigned int task_start_fork : 1;	/* 1 if forking */
	unsigned int started : 1;		/* set if created successfully */
	unsigned int is_hybrid : 1;		/* set if hybrid task */
	unsigned int restart : 1;		/* restart - for exec */
	unsigned int hybrid_pf : 1;             /* PF while hybrid */
	unsigned int hybrid_sc_in_prog : 1;	/* l4 syscall in progress  */
	unsigned long hybrid_pf_addr;           /* PF address while hybrid */
	struct pt_regs regs;
	union i387_union i387;			/* floating point info */
	unsigned long gs;
	unsigned long fs;
	unsigned long pfa;
	unsigned long pf_count;
	unsigned long error_code;
	unsigned long trap_no;			/* sigsegv stuff */

	/* IO permissions */
	struct l4x_iodb *iodb;
};

#define INIT_THREAD  {							\
}

static inline void load_esp0(struct tss_struct *tss, unsigned long esp0)
{
	/* Not the job of L4Linux */
}

#if 0
#define start_thread(regs, new_eip, new_esp) do {		\
	enter_kdebug("NEEDS HACKING");				\
} while (0)
#endif
extern void start_thread(struct pt_regs *regs, unsigned long eip, unsigned long esp);

/*
 * These special macros can be used to get or set a debugging register
 */
#define get_debugreg(var, register)				\
		__asm__("movl %%db" #register ", %0"		\
			:"=r" (var))
#define set_debugreg(value, register)			\
		__asm__("movl %0,%%db" #register		\
			: /* no output */			\
			:"r" (value))

/*
 * Set IOPL bits in EFLAGS from given mask
 */
static inline void set_iopl_mask(unsigned mask)
{
	unsigned int reg;
	__asm__ __volatile__ ("pushfl;"
			      "popl %0;"
			      "andl %1, %0;"
			      "orl %2, %0;"
			      "pushl %0;"
			      "popfl"
				: "=&r" (reg)
				: "i" (~X86_EFLAGS_IOPL), "r" (mask));
}

/* Forward declaration, a strange C thing */
struct task_struct;
struct mm_struct;

/* Free all resources held by a thread. */
extern void release_thread(struct task_struct *);

/* Prepare to copy thread state - unlazy all lazy status */
extern void prepare_to_copy(struct task_struct *tsk);

/*
 * create a kernel thread without removing it from tasklists
 */
extern int kernel_thread(int (*fn)(void *), void * arg, unsigned long flags);

extern unsigned long thread_saved_pc(struct task_struct *tsk);
void show_trace(struct task_struct *task, struct pt_regs *regs, unsigned long *stack);

unsigned long get_wchan(struct task_struct *p);

#define THREAD_SIZE_LONGS      (THREAD_SIZE/sizeof(unsigned long))
#define KSTK_TOP(info)                                                 \
({                                                                     \
       unsigned long *__ptr = (unsigned long *)(info);                 \
       (unsigned long)(&__ptr[THREAD_SIZE_LONGS]);                     \
})

#define task_pt_regs(task)                                             \
({                                                                     \
       struct pt_regs *__regs__;                                       \
       __regs__ = &(task)->thread.regs;                                \
       __regs__ - 0;                                                   \
})

#define KSTK_EIP(task) (task_pt_regs(task)->eip)
#define KSTK_ESP(task) (task_pt_regs(task)->esp)


struct microcode_header {
	unsigned int hdrver;
	unsigned int rev;
	unsigned int date;
	unsigned int sig;
	unsigned int cksum;
	unsigned int ldrver;
	unsigned int pf;
	unsigned int datasize;
	unsigned int totalsize;
	unsigned int reserved[3];
};

struct microcode {
	struct microcode_header hdr;
	unsigned int bits[0];
};

typedef struct microcode microcode_t;
typedef struct microcode_header microcode_header_t;

/* microcode format is extended from prescott processors */
struct extended_signature {
	unsigned int sig;
	unsigned int pf;
	unsigned int cksum;
};

struct extended_sigtable {
	unsigned int count;
	unsigned int cksum;
	unsigned int reserved[3];
	struct extended_signature sigs[0];
};

/* REP NOP (PAUSE) is a good thing to insert into busy-wait loops. */
static inline void rep_nop(void)
{
	__asm__ __volatile__("rep;nop": : :"memory");
}

#define cpu_relax()	rep_nop()

/* generic versions from gas */
#define GENERIC_NOP1	".byte 0x90\n"
#define GENERIC_NOP2    	".byte 0x89,0xf6\n"
#define GENERIC_NOP3        ".byte 0x8d,0x76,0x00\n"
#define GENERIC_NOP4        ".byte 0x8d,0x74,0x26,0x00\n"
#define GENERIC_NOP5        GENERIC_NOP1 GENERIC_NOP4
#define GENERIC_NOP6	".byte 0x8d,0xb6,0x00,0x00,0x00,0x00\n"
#define GENERIC_NOP7	".byte 0x8d,0xb4,0x26,0x00,0x00,0x00,0x00\n"
#define GENERIC_NOP8	GENERIC_NOP1 GENERIC_NOP7

/* Opteron nops */
#define K8_NOP1 GENERIC_NOP1
#define K8_NOP2	".byte 0x66,0x90\n" 
#define K8_NOP3	".byte 0x66,0x66,0x90\n" 
#define K8_NOP4	".byte 0x66,0x66,0x66,0x90\n" 
#define K8_NOP5	K8_NOP3 K8_NOP2 
#define K8_NOP6	K8_NOP3 K8_NOP3
#define K8_NOP7	K8_NOP4 K8_NOP3
#define K8_NOP8	K8_NOP4 K8_NOP4

/* K7 nops */
/* uses eax dependencies (arbitary choice) */
#define K7_NOP1  GENERIC_NOP1
#define K7_NOP2	".byte 0x8b,0xc0\n" 
#define K7_NOP3	".byte 0x8d,0x04,0x20\n"
#define K7_NOP4	".byte 0x8d,0x44,0x20,0x00\n"
#define K7_NOP5	K7_NOP4 ASM_NOP1
#define K7_NOP6	".byte 0x8d,0x80,0,0,0,0\n"
#define K7_NOP7        ".byte 0x8D,0x04,0x05,0,0,0,0\n"
#define K7_NOP8        K7_NOP7 ASM_NOP1

#ifdef CONFIG_MK8
#define ASM_NOP1 K8_NOP1
#define ASM_NOP2 K8_NOP2
#define ASM_NOP3 K8_NOP3
#define ASM_NOP4 K8_NOP4
#define ASM_NOP5 K8_NOP5
#define ASM_NOP6 K8_NOP6
#define ASM_NOP7 K8_NOP7
#define ASM_NOP8 K8_NOP8
#elif defined(CONFIG_MK7)
#define ASM_NOP1 K7_NOP1
#define ASM_NOP2 K7_NOP2
#define ASM_NOP3 K7_NOP3
#define ASM_NOP4 K7_NOP4
#define ASM_NOP5 K7_NOP5
#define ASM_NOP6 K7_NOP6
#define ASM_NOP7 K7_NOP7
#define ASM_NOP8 K7_NOP8
#else
#define ASM_NOP1 GENERIC_NOP1
#define ASM_NOP2 GENERIC_NOP2
#define ASM_NOP3 GENERIC_NOP3
#define ASM_NOP4 GENERIC_NOP4
#define ASM_NOP5 GENERIC_NOP5
#define ASM_NOP6 GENERIC_NOP6
#define ASM_NOP7 GENERIC_NOP7
#define ASM_NOP8 GENERIC_NOP8
#endif

#define ASM_NOP_MAX 8

/* Prefetch instructions for Pentium III and AMD Athlon */
/* It's not worth to care about 3dnow! prefetches for the K6
   because they are microcoded there and very slow.
   However we don't do prefetches for pre XP Athlons currently
   That should be fixed. */
#define ARCH_HAS_PREFETCH
static inline void prefetch(const void *x)
{
	alternative_input(ASM_NOP4,
			  "prefetchnta (%1)",
			  X86_FEATURE_XMM,
			  "r" (x));
}

#define ARCH_HAS_PREFETCH
#define ARCH_HAS_PREFETCHW
#define ARCH_HAS_SPINLOCK_PREFETCH

/* 3dnow! prefetch to get an exclusive cache line. Useful for 
   spinlocks to avoid one state transition in the cache coherency protocol. */
static inline void prefetchw(const void *x)
{
	alternative_input(ASM_NOP4,
			  "prefetchw (%1)",
			  X86_FEATURE_3DNOW,
			  "r" (x));
}
#define spin_lock_prefetch(x)	prefetchw(x)

extern void select_idle_routine(const struct cpuinfo_x86 *c);

#define cache_line_size() (boot_cpu_data.x86_cache_alignment)

extern unsigned long boot_option_idle_override;
extern void enable_sep_cpu(void);
extern int sysenter_setup(void);

#endif /* ! __ASM_L4__ARCH_I386__PROCESSOR_H__ */