#
# arch/l4/mm/Makefile
#


obj-y	:= fault.o extable.o init.o init_32.o ioremap.o pageattr.o pgtable_32.o pgtable.o mmap.o pat.o

obj-$(CONFIG_SMP)		+= tlb.o

extable-y	+= ../../../x86/mm/extable.o
mmap-y		+= ../../../x86/mm/mmap.o
pat-y		+= ../../../x86/mm/pat.o
pageattr-y	+= ../../../x86/mm/pageattr.o
pgtable_32-y	+= ../../../x86/mm/pgtable_32.o
