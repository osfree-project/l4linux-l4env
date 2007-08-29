#
# l4/Makefile
#
# Makefile for the L4 architecture.
#

# Set this to really switch to ARM when coming from another arch
ifeq ($(L4ARCH),arm)
CONFIG_L4_ARCH_ARM := y
endif

ifneq ($(CONFIG_L4_ARCH_ARM),)
# arm selection
L4API		:= v2
BASEARCH	:= arm

CHECKFLAGS	:= -D__arm__

L4_MK_ARCH	:= arm
L4_MK_ARCH_CAP	:= ARM
else
# x86 selection
L4API		:= v2
BASEARCH	:= i386

CHECKFLAGS	:= -D__i386__

L4_MK_ARCH	:= x86
L4_MK_ARCH_CAP	:= X86
endif

export BASEARCH L4_MK_ARCH

KBUILD_DEFCONFIG := x86-native_defconfig

# crude hack
TRASH := $(shell test -f $(srctree)/arch/l4/Kconfig.isg || touch $(srctree)/arch/l4/Kconfig.isg; cd $(srctree)/arch/l4 && ln -fs ../i386/Kconfig Kconfig.i386 && ln -sf Kconfig.$(BASEARCH) Kconfig.arch)

HAS_BIARCH	:= $(call cc-option-yn, -m32)
ifeq ($(HAS_BIARCH),y)
AS		:= $(AS) --32
LD		:= $(LD) -m elf_i386
CC		:= $(CC) -m32
endif

BASEENV		:= l4env

ifdef CONFIG_RELOCATABLE
LDFLAGS_vmlinux_i386 := --emit-relocs
endif
LDFLAGS_vmlinux_arm  := --no-warn-mismatch
LDFLAGS_vmlinux	:= $(LDFLAGS_vmlinux_$(BASEARCH))

L4_MK_API	:= l4$(L4API)
L4_MK_CPU	:= $(patsubst "%",%,$(CONFIG_L4_MK_CPU_$(L4_MK_ARCH_CAP)))

# overwrite UTS_MACHINE to get proper architecture in user land
UTS_MACHINE	:= $(BASEARCH)

CFLAGS += -gstabs+ -pipe -msoft-float -DARCH_$(L4_MK_ARCH)

ifeq ($(BASEARCH),i386)
# prevent gcc from keeping the stack 16 byte aligned
CFLAGS += $(call cc-option,-mpreferred-stack-boundary=2,)

# CPU-specific tuning. Anything which can be shared with UML should go here.
include $(srctree)/arch/i386/Makefile.cpu

# temporary until string.h is fixed
cflags-y += -ffreestanding

# this works around some issues with generating unwind tables in older gccs
# newer gccs do it by default
cflags-y += -maccumulate-outgoing-args

# Disable unit-at-a-time mode on pre-gcc-4.0 compilers, it makes gcc use
# a lot more stack due to the lack of sharing of stacklots:
CFLAGS				+= $(shell if [ $(call cc-version) -lt 0400 ] ; then echo $(call cc-option,-fno-unit-at-a-time); fi ;)

# do binutils support CFI?
cflags-y += $(call as-instr,.cfi_startproc\n.cfi_endproc,-DCONFIG_AS_CFI=1,)
AFLAGS += $(call as-instr,.cfi_startproc\n.cfi_endproc,-DCONFIG_AS_CFI=1,)

# is .cfi_signal_frame supported too?
cflags-y += $(call as-instr,.cfi_startproc\n.cfi_signal_frame\n.cfi_endproc,-DCONFIG_AS_CFI_SIGNAL_FRAME=1,)
AFLAGS += $(call as-instr,.cfi_startproc\n.cfi_signal_frame\n.cfi_endproc,-DCONFIG_AS_CFI_SIGNAL_FRAME=1,)
endif

ifeq ($(BASEARCH),arm)
# This selects which instruction set is used.
# Note that GCC does not numerically define an architecture version
# macro, but instead defines a whole series of macros which makes
# testing for a specific architecture or later rather impossible.
arch-$(CONFIG_CPU_32v7)		:=-D__LINUX_ARM_ARCH__=7 $(call cc-option,-march=armv7a,-march=armv5t -Wa$(comma)-march=armv7a)
arch-$(CONFIG_CPU_32v6)		:=-D__LINUX_ARM_ARCH__=6 $(call cc-option,-march=armv6,-march=armv5t -Wa$(comma)-march=armv6)
# Only override the compiler option if ARMv6. The ARMv6K extensions are
# always available in ARMv7
ifeq ($(CONFIG_CPU_32v6),y)
arch-$(CONFIG_CPU_32v6K)	:=-D__LINUX_ARM_ARCH__=6 $(call cc-option,-march=armv6k,-march=armv5t -Wa$(comma)-march=armv6k)
endif
arch-$(CONFIG_CPU_32v5)		:=-D__LINUX_ARM_ARCH__=5 $(call cc-option,-march=armv5te,-march=armv4t)
arch-$(CONFIG_CPU_32v4T)	:=-D__LINUX_ARM_ARCH__=4 -march=armv4t
arch-$(CONFIG_CPU_32v4)		:=-D__LINUX_ARM_ARCH__=4 -march=armv4
arch-$(CONFIG_CPU_32v3)		:=-D__LINUX_ARM_ARCH__=3 -march=armv3

tune-$(CONFIG_CPU_V6)		:=$(call cc-option,-mtune=arm1136j-s,-mtune=strongarm)

CFLAGS += $(call cc-option,-mapcs-32,-mabi=apcs-gnu) $(call cc-option,-mno-thumb-interwork,)
CFLAGS += $(arch-y) $(tune-y)

endif

CFLAGS += $(cflags-y)


# -----------------------------------------------

-include $(objtree)/Makeconf.l4conf

L4OBJ := $(patsubst "%",%,$(CONFIG_L4_OBJ_TREE))
L4DIR := $(shell readlink $(L4OBJ)/source)
export L4OBJ
export L4DIR


# Extra Libs
L4LX_E_L-$(CONFIG_L4_FB_DRIVER) += -ll4dope -lvscreen -lcon -lconstream-server
L4LX_E_L-$(CONFIG_L4_BLK_DRV)   += -lgeneric_blk
L4LX_E_L-$(CONFIG_L4_EXTERNAL_RTC) += -lrtc
L4LX_E_L-$(CONFIG_L4_NEED_DSI)	+= -ldsi
L4LX_E_L-$(CONFIG_L4_OSHKOSH_DRV) += -loshkoshnicdrv
L4LX_E_L-$(CONFIG_L4_ORE_DRV)   += -lore
L4LX_E_L-$(CONFIG_L4_IRQ_OMEGA0) += -lomega0
L4LX_E_L-$(CONFIG_L4_PDSPBLK_DRV) += -lpers_dsp
L4LX_E_L-$(CONFIG_L4_USE_L4VMM)	+= -ll4vmm$(if $(CONFIG_L4_USE_L4VMM_DBG),-dbg) \
                                   -ll4vmm-devices -ll4vmm-c -ll4vmm-cxx

# Extra includes
L4LX_E_I-$(CONFIG_L4_NEED_DSI)	+= -I$(srctree)/arch/l4/lib/support

head-y := arch/l4/kernel/head.o arch/l4/kernel/init_task.o

libs-y				+= arch/l4/lib/arch-$(BASEARCH)/	\
				   arch/l4/lib/support/			\
				   arch/l4/l4lxlib/generic/		\
				   arch/l4/l4lxlib/$(BASEENV)/

core-y				+= arch/l4/kernel/			\
				   arch/l4/kernel/arch-$(BASEARCH)/	\
				   arch/l4/mm/arch-$(BASEARCH)/

ifeq ($(BASEARCH),i386)
drivers-$(CONFIG_PCI)		+= arch/l4/pci/
drivers-$(CONFIG_PM)		+= arch/l4/power/arch-i386/
endif

ifeq ($(BASEARCH),arm)
core-$(CONFIG_FPE_NWFPE)	+= arch/arm/nwfpe/
endif

libs-y				+= -lio-ll -ldm_phys -lgeneric_fprov -ll4util \
				   -ll4sys $(L4LX_E_L-y)

libs-$(CONFIG_L4_FERRET)	+= -lferret_client -lferret_producer \
				   -lferret_init

boot := arch/l4/boot

L4LIBS		= -L$(L4OBJ)/lib/$(L4_MK_ARCH)_$(L4_MK_CPU)/$(L4_MK_API) \
		  -L$(L4OBJ)/lib/$(L4_MK_ARCH)_$(L4_MK_CPU) \
		  -L$(L4OBJ)/lib \
		  -lloader.s


L4INC		= -I$(L4OBJ)/include/$(L4_MK_ARCH)/$(L4_MK_API) \
		  -I$(L4OBJ)/include/$(L4_MK_ARCH) \
		  -I$(L4OBJ)/include/$(L4_MK_API) \
		  -I$(L4OBJ)/include \
		  -I$(L4BID_DICEDIR)/include \
		  $(L4LX_E_I-y)

MACH_INC_i386	:= -Iinclude/asm-l4/$(BASEARCH)-arch/asm/mach-default
MACH_INC_arm	:= -Iinclude/asm-l4/$(BASEARCH)-arch

LDFLAGS_LDSO	= --dynamic-linker libld-l4.s.so \
		   $(L4OBJ)/lib/$(L4_MK_ARCH)_$(L4_MK_CPU)/crt0.o

LDFLAGS_vmlinux	+= $(LDFLAGS_LDSO) $(L4LIBS) -z now
CPPFLAGS	+= -Iinclude/asm-l4/l4-arch -Iinclude/asm-l4/$(BASEARCH)-arch \
		   $(MACH_INC_$(BASEARCH)) $(L4INC) $(CPPFLAGS_SYSENTER-y) \
		   $(L4BID_CPPFLAGS_SYSCALLS-y)

# for DICE
CPPFLAGS	+= -DL4API_$(L4_MK_API)

# IDL also generates header files
CPPFLAGS	+= -I$(obj)/arch/l4/idl

all: vmlinuz

SUFFIX = $(patsubst "%",%,$(CONFIG_L4_VMLINUZ_SUFFIX))

quiet_cmd_compr = COMPR   $< to vmlinuz$(SUFFIX)
      cmd_compr = gzip -c vmlinux > vmlinuz$(SUFFIX)

CLEAN_FILES	+= vmlinuz$(SUFFIX)

quiet_cmd_localinst = LOCINST vmlinuz$(SUFFIX)
      cmd_localinst = ([ -x "$(srctree)/arch/l4/install.local" ] &&		\
	                $(srctree)/arch/l4/install.local vmlinuz$(SUFFIX) $(BASEARCH))\
			  || true

vmlinuz: vmlinux
	$(call cmd,compr);
	$(call cmd,localinst)

mtags:
	(cd $(srctree) && $(MAKE) tags > /dev/null 2>&1; \
	sort tags > .tags.sorting && mv .tags.sorting tags )

include/asm-l4/$(BASEARCH)-arch/asm:
	@echo '  Creating asm-l4/$(BASEARCH)-arch/asm symlink'
	$(Q)mkdir -p $(@D)
	$(Q)ln -s $(src)/include/asm-$(BASEARCH) $@

include/asm-l4/l4-arch/asm:
	@echo '  Creating asm-l4/l4-arch/asm symlink'
	$(Q)mkdir -p $(@D)
	$(Q)ln -s $(src)/include/asm-l4/arch-$(BASEARCH) $@

include/asm-l4/arch:
	@echo '  Creating asm-l4/arch-$(BASEARCH)/arch -> asm/arch symlink'
	$(Q)mkdir -p $(@D)
	$(Q)ln -s $(src)/include/asm-l4/arch-$(BASEARCH)/arch $@

include/asm-l4/api:
	@echo '  Creating asm-l4/api-$(BASEENV) -> asm/api symlink'
	$(Q)mkdir -p $(@D)
	$(Q)ln -s $(src)/include/asm-l4/api-$(BASEENV) $@

include/asm-l4/l4x:
	@echo '  Creating asm-l4/l4x-$(BASEARCH) -> asm/l4x symlink'
	$(Q)mkdir -p $(@D)
	$(Q)ln -s $(src)/include/asm-l4/l4x-$(BASEARCH) $@

include/asm-l4/l4lxapi/impl:
	@echo '  Creating asm-l4/l4lxapi/impl symlink'
	$(Q)mkdir -p $(@D)
	$(Q)ln -s $(src)/arch/l4/l4lxlib/l4env $@

include/asm-l4/mach-types.h: $(srctree)/arch/arm/tools/gen-mach-types $(srctree)/arch/arm/tools/mach-types
	cp $(srctree)/arch/arm/tools/mach-types include/asm-l4/mach-types.list
	echo "l4	MACH_L4	L4	9999" >> include/asm-l4/mach-types.list
	$(AWK) -f $< include/asm-l4/mach-types.list > $@ || { rm -f $@; /bin/false; }
	$(RM) include/asm-l4/mach-types.list

symlinks_arm  = include/asm-l4/mach-types.h

symlinks      = include/asm-l4/api \
                include/asm-l4/l4lxapi/impl \
		include/asm-l4/l4x \
		include/asm-l4/l4-arch/asm \
		include/asm-l4/$(BASEARCH)-arch/asm \
                $(symlinks_$(BASEARCH))

#MRPROPER_FILES	+= $(symlinks)
CLEAN_FILES	+= $(symlinks) Makeconf.l4conf

ifeq ($(config-targets),0)
ifneq ($(wildcard .config),)
$(objtree)/Makeconf.l4conf: $(srctree)/arch/l4/Makefile.l4conf $(srctree)/arch/l4/Makefile
	$(Q)$(MAKE) $(if $(L4DIR),-C $(L4DIR),) -f $< O=$(L4OBJ) OUTPUT=$@

archprepare: check_linux_config $(symlinks) $(objtree)/Makeconf.l4conf
	$(Q)mkdir -p arch/$(BASEARCH)/lib

endif # .config available
else # no archprepare when configuring the kernel
archprepare:
endif # config-targets == 1

# ----

archclean:

chkl4conf:
	@if [ -d $(L4OBJ)/pkg/l4sys ]; then                                  \
		echo "Configuration looks Ok.";                              \
	else                                                                 \
		echo \"$(L4OBJ)\" does not look like an L4 build directory!; \
	fi

## Check a few options that should not be enabled
# regparm: gcc may call memset from our libs, so obey calling convention
#          this should probably be fixed

DIS_OPTS := HIGHMEM4G HIGHMEM64G SMP PREEMPT PCI_GOANY PCI_GOBIOS HPET_TIMER \
            X86_MCE X86_MCE MTRR PARAVIRT KEXEC MCA

check_linux_config:
	@$(foreach i,$(addprefix CONFIG_,$(DIS_OPTS)),     \
	  if [ "$($(i))" = "y" ]; then                     \
	    echo; echo "ERROR: $(i) must not be enabled."; \
	    failed=1;                                      \
	  fi;)                                             \
	  if [ -n "$$failed" ]; then                       \
	    echo; exit 1;                                  \
	  fi

PHONY += chkl4conf check_linux_config

define archhelp
  echo '* vmlinuz	- Compressed kernel image'
  echo '  chkl4conf     - Check L4 specific configuration'
endef

