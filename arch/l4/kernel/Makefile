#
# arch/l4/kernel/Makefile
#

extra-y		:= head.o init_task.o vmlinux.lds

AFLAGS_head.o   := -DARCH_$(L4_MK_ARCH)

obj-y		:= main.o process_gen.o hybrid.o syscall_guard.o

obj-$(CONFIG_EARLY_PRINTK)	+= early_printk.o
obj-$(CONFIG_L4_TAMED)		+= tamed.o
obj-$(CONFIG_L4_FERRET)		+= ferret.o

export CPPFLAGS_vmlinux.lds += -U$(BASEARCH) -DARCH_$(L4_MK_ARCH)
