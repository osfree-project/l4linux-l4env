
include $(srctree)/arch/x86/pci/Makefile

KBUILD_CPPFLAGS += -I$(srctree)/arch/x86/pci

b		:= ../../x86/pci

common-y	:= $(b)/common.o
direct-y	:= $(b)/direct.o
fixup-y		:= $(b)/fixup.o
i386-y		:= $(b)/i386.o
irq-y		:= $(b)/irq.o
legacy-y	:= $(b)/legacy.o
mmconfig-y	:= $(b)/mmconfig.o
acpi-y		:= $(b)/acpi.o
init-y		:= $(b)/init.o
early-y		:= $(b)/early.o

