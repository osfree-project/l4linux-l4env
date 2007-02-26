
include $(srctree)/arch/i386/pci/Makefile

CFLAGS += -I$(srctree)/arch/i386/pci

b		:= ../../i386/pci

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

