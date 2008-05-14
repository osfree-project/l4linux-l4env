#
# arch/l4/kernel/arch-i386/Makefile
#

obj-y		:= dispatch.o entry.o i387.o ioport.o irq.o irq_l4.o \
		   ldt.o mach_setup.o pci-dma.o process.o ptrace.o reboot.o \
		   setup.o signal.o sys_i386.o time.o traps.o e820.o \
		   unimpl.o topology.o alternative.o tsc.o \
		   tls.o step.o rtc.o ds.o io_delay.o

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
b		:= ../../../x86/kernel
alternative-y	:= $(b)/alternative.o
ldt-y		:= $(b)/ldt.o
module-y	:= $(b)/module_32.o
pci-dma-y	:= $(b)/pci-dma_32.o
sys_i386-y	:= $(b)/sys_i386_32.o
topology-y	:= $(b)/topology.o
i387-y		:= $(b)/i387.o
e820-y		:= $(b)/e820_32.o
nmi-y		:= $(b)/nmi_32.o
smpcommon-y	:= $(b)/smpcommon_32.o
k8-y		+= $(b)/k8.o
stacktrace-y	+= $(b)/stacktrace.o
tls-y		+= $(b)/tls.o
step-y		+= $(b)/step.o
ds-y		+= $(b)/ds.o
io_delay-y	+= $(b)/io_delay.o

# get sigframe_32.h for signal.c
KBUILD_CFLAGS	+= -Iarch/x86/kernel

# syscall_table_32.S
KBUILD_AFLAGS	+= -Iarch/x86/kernel
