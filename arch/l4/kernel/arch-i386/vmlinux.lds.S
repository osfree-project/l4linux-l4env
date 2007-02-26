/* ld script to make i386 Linux kernel
 * Written by Martin Mares <mj@atrey.karlin.mff.cuni.cz>;
 *
 * Don't define absolute symbols until and unless you know that symbol
 * value is should remain constant even if kernel image is relocated
 * at run time. Absolute symbols are not relocated. If symbol value should
 * change if kernel is relocated, make the symbol section relative and
 * put it inside the section definition.
 */

/* Don't define absolute symbols until and unless you know that symbol
 * value is should remain constant even if kernel image is relocated
 * at run time. Absolute symbols are not relocated. If symbol value should
 * change if kernel is relocated, make the symbol section relative and
 * put it inside the section definition.
 */
#define LOAD_OFFSET __PAGE_OFFSET

#include <asm-generic/vmlinux.lds.h>
#include <asm/thread_info.h>
#include <asm/page.h>
#include <asm/cache.h>
#include <asm/boot.h>

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(phys_startup_32)
jiffies = jiffies_64;

#if 0
PHDRS {
	text PT_LOAD FLAGS(5);	/* R_E */
	data PT_LOAD FLAGS(7);	/* RWE */
	note PT_NOTE FLAGS(4);	/* R__ */
}
#endif
SECTIONS
{
  . = 0x400000;
  phys_startup_32 = startup_32 - LOAD_OFFSET;
  /* read-only */
  startup_32 = .;
  _text = .;			/* Text and read-only data */
  _stext = .;
  .text : AT(ADDR(.text) - LOAD_OFFSET) {
	*(.text .text.*)
	SCHED_TEXT
	LOCK_TEXT
	KPROBES_TEXT
	*(.fixup)
	*(.gnu.warning)
	} = 0x9090
	/*} :text = 0x9090 */

  .rel.dyn : AT(ADDR(.rel.dyn) - LOAD_OFFSET) { *(.rel.dyn) }
  _etext = .;			/* End of text section */

  . = ALIGN(16);		/* Exception table */
  __ex_table : AT(ADDR(__ex_table) - LOAD_OFFSET) {
  	__start___ex_table = .;
	 *(__ex_table)
  	__stop___ex_table = .;
  }

  RODATA

  BUG_TABLE

  . = ALIGN(4);
  .tracedata : AT(ADDR(.tracedata) - LOAD_OFFSET) {
  	__tracedata_start = .;
	*(.tracedata)
  	__tracedata_end = .;
  }

  /* writeable */
  . = ALIGN(4096);
  _sdata = .;
  .got  : AT(ADDR(.got) - (0)) { *(.got) *(.got.plt) }
  .data : AT(ADDR(.data) - LOAD_OFFSET) {	/* Data */
	*(.got)
	*(.got.plt)
	*(.data)
	CONSTRUCTORS
	. = ALIGN(4);
	__l4env_initcall_start = .;
	*(.l4env_initcall.init)
	__l4env_initcall_end = .;
	}

  .paravirtprobe : AT(ADDR(.paravirtprobe) - LOAD_OFFSET) {
  	__start_paravirtprobe = .;
	*(.paravirtprobe)
  	__stop_paravirtprobe = .;
  }

  . = ALIGN(4096);
  .data_nosave : AT(ADDR(.data_nosave) - LOAD_OFFSET) {
  	__nosave_begin = .;
	*(.data.nosave)
  	. = ALIGN(4096);
  	__nosave_end = .;
  }

  . = ALIGN(4096);
  .data.page_aligned : AT(ADDR(.data.page_aligned) - LOAD_OFFSET) {
	*(.data.idt)
  }

  . = ALIGN(32);
  .data.cacheline_aligned : AT(ADDR(.data.cacheline_aligned) - LOAD_OFFSET) {
	*(.data.cacheline_aligned)
  }

  /* rarely changed data like cpu maps */
  . = ALIGN(32);
  .data.read_mostly : AT(ADDR(.data.read_mostly) - LOAD_OFFSET) {
	*(.data.read_mostly)
	_edata = .;		/* End of data section */
  }

  . = ALIGN(THREAD_SIZE);	/* init_task */
  .data.init_task : AT(ADDR(.data.init_task) - LOAD_OFFSET) {
	*(.data.init_task)
  }

  /* might get freed after init */
  . = ALIGN(4096);
  .smp_altinstructions : AT(ADDR(.smp_altinstructions) - LOAD_OFFSET) {
	__smp_alt_begin = .;
	__smp_alt_instructions = .;
	*(.smp_altinstructions)
	__smp_alt_instructions_end = .;
  }
  . = ALIGN(4);
  .smp_locks : AT(ADDR(.smp_locks) - LOAD_OFFSET) {
  	__smp_locks = .;
	*(.smp_locks)
	__smp_locks_end = .;
  }
  .smp_altinstr_replacement : AT(ADDR(.smp_altinstr_replacement) - LOAD_OFFSET) {
	*(.smp_altinstr_replacement)
  	__smp_alt_end = .;
  }
  /* will be freed after init
   * Following ALIGN() is required to make sure no other data falls on the
   * same page where __smp_alt_end is pointing as that page might be freed
   * after boot. Always make sure that ALIGN() directive is present after
   * the section which contains __smp_alt_end.
   */
  . = ALIGN(4096);

  /* will be freed after init */
  . = ALIGN(4096);		/* Init code and data */
  .init.text : AT(ADDR(.init.text) - LOAD_OFFSET) {
  	__init_begin = .;
	_sinittext = .;
	*(.init.text)
	_einittext = .;
  }
  .init.data : AT(ADDR(.init.data) - LOAD_OFFSET) { *(.init.data) }
  . = ALIGN(16);
  .init.setup : AT(ADDR(.init.setup) - LOAD_OFFSET) {
  	__setup_start = .;
	*(.init.setup)
  	__setup_end = .;
   }
  .initcall.init : AT(ADDR(.initcall.init) - LOAD_OFFSET) {
  	__initcall_start = .;
	INITCALLS
  	__initcall_end = .;
  }
  .con_initcall.init : AT(ADDR(.con_initcall.init) - LOAD_OFFSET) {
  	__con_initcall_start = .;
	*(.con_initcall.init)
  	__con_initcall_end = .;
  }
  SECURITY_INIT
  . = ALIGN(4);
  .altinstructions : AT(ADDR(.altinstructions) - LOAD_OFFSET) {
  	__alt_instructions = .;
	*(.altinstructions)
	__alt_instructions_end = .;
  }
  .altinstr_replacement : AT(ADDR(.altinstr_replacement) - LOAD_OFFSET) {
	*(.altinstr_replacement)
  }
  . = ALIGN(4);
  .parainstructions : AT(ADDR(.parainstructions) - LOAD_OFFSET) {
  	__start_parainstructions = .;
	*(.parainstructions)
  	__stop_parainstructions = .;
  }
  /* .exit.text is discard at runtime, not link time, to deal with references
     from .altinstructions and .eh_frame */
  .exit.text : AT(ADDR(.exit.text) - LOAD_OFFSET) { *(.exit.text) }
  .exit.data : AT(ADDR(.exit.data) - LOAD_OFFSET) { *(.exit.data) }
  . = ALIGN(4096);
  .init.ramfs : AT(ADDR(.init.ramfs) - LOAD_OFFSET) {
	__initramfs_start = .;
	*(.init.ramfs)
	__initramfs_end = .;
  }
  . = ALIGN(L1_CACHE_BYTES);
  .data.percpu  : AT(ADDR(.data.percpu) - LOAD_OFFSET) {
	__per_cpu_start = .;
	*(.data.percpu)
	__per_cpu_end = .;
  }
  __init_end = .;
  . = ALIGN(4096);
  /* freed after init ends here */

  /* This is needed for L4Env --
   *   copy out of l4/pkg/crtx/lib/src/ARCH-x86/main_stat.ld */
  .ctors : AT(ADDR(.ctors) - LOAD_OFFSET)
  {
    LONG(0)
    /* traverse this list backwards (see __attribute__((init_priority)) */
    KEEP (*(.mark_beg_ctors))
    KEEP (*(.ctors))
    KEEP (*(SORT(.ctors.*)))
    KEEP (*(.mark_end_ctors))
    /* traverse this list forwards */
    KEEP (*(.mark_beg_c_ctors))
    #define QM1c() .c_ctors.?
    #define QM2c() .c_ctors.??
    #define QM3c() .c_ctors.???
    #define QM4c() .c_ctors.????
    #define QM5c() .c_ctors.?????
    KEEP (*(SORT(QM1c())))
    KEEP (*(SORT(QM2c())))
    KEEP (*(SORT(QM3c())))
    KEEP (*(SORT(QM4c())))
    KEEP (*(SORT(QM5c())))
    KEEP (*(.c_ctors))
    KEEP (*(.mark_end_c_ctors))
  }
  .dtors : AT(ADDR(.dtors) - LOAD_OFFSET)
  {
    LONG(0)
    /* traverse this list backwards (see __attribute__((init_priority)) */
    KEEP (*(.mark_beg_dtors))
    KEEP (*(.dtors))
    KEEP (*(SORT(.dtors.*)))
    KEEP (*(.mark_end_dtors))
    /* traverse this list forwards */
    KEEP (*(.mark_beg_c_dtors))
    #define QM1d() .c_dtors.?
    #define QM2d() .c_dtors.??
    #define QM3d() .c_dtors.???
    #define QM4d() .c_dtors.????
    #define QM5d() .c_dtors.?????
    KEEP (*(SORT(QM1d())))
    KEEP (*(SORT(QM2d())))
    KEEP (*(SORT(QM3d())))
    KEEP (*(SORT(QM4d())))
    KEEP (*(SORT(QM5d())))
    KEEP (*(.c_dtors))
    KEEP (*(.mark_end_c_dtors))
  }

  /* We have variable in our .bss that are 8K aligned, which makes
   * the .bss section also be 8K aligned.
   * The alignment here ensures that there's no hole between the
   * .bss.page_aligned section and the .bss section so that
   * the area between __bss_start and __bss_stop is continuous */
  . = ALIGN(8192);


  .bss : AT(ADDR(.bss) - LOAD_OFFSET) {
	__bss_start = .;		/* BSS */
	*(.bss.page_aligned)
	*(.bss)
	. = ALIGN(4);
	__bss_stop = .;
	/* This is where the kernel creates the early boot page tables */
	. = ALIGN(4096);
	pg0 = . ;
  }

  . = ALIGN(4096);
  .rospace : AT(ADDR(.rospace) - LOAD_OFFSET) { *(.rospace) }

  _end = . ;

  /* Sections to be discarded */
  /DISCARD/ : {
	*(.exitcall.exit)
	}

  STABS_DEBUG

  DWARF_DEBUG

/*  NOTES */
}
