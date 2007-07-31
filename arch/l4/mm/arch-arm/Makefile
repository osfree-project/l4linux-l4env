#
# arch/l4/mm/arch-arm/Makefile
#

obj-y		:= init.o flush.o ioremap.o proc-l4.o \
		   consistent.o fault.o extable.o mmap.o \
		   pgd.o mmu.o iomap.o

obj-y		+= context.o

CFLAGS          += -Iarch/arm/mm

extable-y	:= ../../../arm/mm/extable.o
mmap-y		:= ../../../arm/mm/mmap.o
iomap-y		:= ../../../arm/mm/iomap.o
