#
# arch/l4/kernel/arch-arm/Makefile
#

obj-y		:= process.o sys_arm.o time.o semaphore.o traps.o \
		   switch_to.o setup.o l4.o signal.o irq.o \
		   ptrace.o entry.o dispatch.o

obj-$(CONFIG_MODULES)				+= module.o
obj-$(CONFIG_ISA_DMA_API)			+= dma.o
obj-$(CONFIG_L4_ARM_PLATFORM_ISG)		+= mach_isg.o
obj-$(CONFIG_L4_ARM_PLATFORM_INTEGRATOR)	+= mach_integrator.o

dma-y		:= ../../../arm/kernel/dma.o
irq-y		:= ../../../arm/kernel/irq.o
semaphore-y	:= ../../../arm/kernel/semaphore.o
module-y	:= ../../../arm/kernel/module.o
time-y		:= ../../../arm/kernel/time.o

CPPFLAGS	+= -I$(srctree)/arch/arm/kernel

# ----------------------------------------------------------------------
# _upage_start must(!) be last so that ld gets its calculation right!
define get_upage_defsyms
	upage_base=0xbf008000;						\
	for i in $$($(NM) $< | cut -d\  -f3 | grep -vw l4x_upage_start | grep -ie '^[a-z]');	\
	do								\
		echo -defsym $$i=$$i-l4x_upage_start+$$upage_base;	\
	done;								\
	echo -defsym l4x_upage_start=$$upage_base;
endef

obj-y		+= upage.reloced.o
targets		+= upage.o

quiet_cmd_upage = UPAGE   $@
      cmd_upage = $(LD) $(EXTRA_LDFLAGS) -N \
                        $(shell $(get_upage_defsyms)) -T /dev/null -o $@ $<

$(obj)/upage.reloced.o: $(obj)/upage.o FORCE
	$(call if_changed,upage)