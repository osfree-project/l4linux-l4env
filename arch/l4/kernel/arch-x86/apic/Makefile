
obj-$(CONFIG_X86_LOCAL_APIC)    += apic.o probe_$(BITS).o ipi.o nmi.o
obj-$(CONFIG_X86_IO_APIC)       += io_apic.o
obj-$(CONFIG_SMP)               += ipi.o

# -------------------------------------------
b		:= ../../../../x86/kernel/apic
nmi-y		:= $(b)/nmi.o
probe_32-y	:= $(b)/probe_32.o
