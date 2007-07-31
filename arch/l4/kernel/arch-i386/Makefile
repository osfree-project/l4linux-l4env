#
# arch/l4/kernel/arch-i386/Makefile
#

obj-y		:= dispatch.o entry.o i387.o ioport.o irq.o irq_l4.o \
		   ldt.o mach_setup.o pci-dma.o process.o ptrace.o reboot.o \
		   setup.o signal.o sys_i386.o time.o traps.o e820.o \
		   unimpl.o topology.o alternative.o tsc.o sysenter.o

obj-$(CONFIG_STACKTRACE)	+= stacktrace.o
obj-y				+= cpu/
obj-$(CONFIG_ACPI_BOOT)		+= acpi.o
obj-$(CONFIG_MODULES)		+= module.o
obj-$(CONFIG_KPROBES)		+= kprobes.o
obj-$(CONFIG_K8_NB)		+= k8.o
obj-$(CONFIG_SMP)		+= mpparse.o nmi.o apic.o io_apic.o smp.o smpboot.o smpcommon.o

# Make sure this is linked after any other paravirt_ops structs: see head.S
obj-$(CONFIG_PARAVIRT)		+= paravirt.o

# -------------------------------------------
b		:= ../../../i386/kernel
alternative-y	:= $(b)/alternative.o
ldt-y		:= $(b)/ldt.o
module-y	:= $(b)/module.o
pci-dma-y	:= $(b)/pci-dma.o
sys_i386-y	:= $(b)/sys_i386.o
topology-y	:= $(b)/topology.o
i387-y		:= $(b)/i387.o
e820-y		:= $(b)/e820.o
nmi-y		:= $(b)/nmi.o
smpcommon-y	:= $(b)/smpcommon.o

k8-y		+= ../../../x86_64/kernel/k8.o
stacktrace-y	+= ../../../x86_64/kernel/stacktrace.o

# get sigframe.h for signal.c
CFLAGS		+= -Iarch/i386/kernel

# -------------------------------------------
obj-y		+= upage.final.o

$(obj)/upage.final.o: $(obj)/upage.so

# get vsyscall-sigreturn.S for vsyscall-int80.S
AFLAGS		+= -Iarch/i386/kernel

$(obj)/vsyscall-int80.S: $(srctree)/arch/i386/kernel/vsyscall-int80.S
	@ln -sf $< $(obj)

$(obj)/vsyscall-note.S: $(srctree)/arch/i386/kernel/vsyscall-note.S
	@ln -sf $< $(obj)

targets		+= upage.o vsyscall-int80.o upage.so vsyscall-note.o

vsyscall-flags = -shared -s -Wl,-soname=linux-gate.so.1 \
		$(call ld-option, -Wl$(comma)--hash-style=sysv)
SYSCFLAGS_upage.so = $(vsyscall-flags)

quiet_cmd_upage = UPAGE   $@
      cmd_upage = $(CC) -m elf_i386 -nostdlib $(SYSCFLAGS_$(@F)) \
      		        -Wl,-T,$(filter-out FORCE,$^) -o $@

export CPPFLAGS_vsyscall.lds += -P -C -U$(ARCH)

$(obj)/upage.so: $(src)/upage.lds $(obj)/vsyscall-int80.o \
		 $(obj)/upage.o $(obj)/vsyscall-note.o FORCE
	$(call if_changed,upage)

extra-y += upage-syms.o
$(obj)/built-in.o: $(obj)/upage-syms.o
$(obj)/built-in.o: ld_flags += -R $(obj)/upage-syms.o

SYSCFLAGS_upage-syms.o = -r
$(obj)/upage-syms.o: $(src)/upage.lds $(obj)/vsyscall-int80.o \
		     $(obj)/upage.o $(obj)/vsyscall-note.o FORCE
	$(call if_changed,upage)
