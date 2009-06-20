#
# l4/Makefile
#
# Makefile for the L4 architecture.
#

# BITS is used as extension for files which are available in a 32 bit
# and a 64 bit version to simplify shared Makefiles.
# e.g.: obj-y += foo_$(BITS).o
BITS := 32
export BITS

# Set this to really switch to ARM when coming from another arch
ifeq ($(L4ARCH),arm)
CONFIG_L4_ARCH_ARM := y
endif

ifneq ($(CONFIG_L4_ARCH_ARM),)
# arm selection
L4API		:= v2
BASEARCH	:= arm
LINSRCARCH      := arm

CHECKFLAGS	:= -D__arm__

L4_MK_ARCH	:= arm
L4_MK_ARCH_CAP	:= ARM
OBJCOPYARCH	:= elf32-littlearm

else

# x86 selection
L4API		:= v2
BASEARCH	:= x86
LINSRCARCH      := x86

L4_MK_ARCH	:= x86
L4_MK_ARCH_CAP	:= X86

OBJCOPYARCH	:= elf32-i386
endif

export BASEARCH L4_MK_ARCH L4_MK_API L4_MK_CPU OBJCOPYARCH

KBUILD_DEFCONFIG := x86-native_defconfig

# crude hack
TRASH := $(shell test -f $(srctree)/arch/l4/Kconfig.isg || \
           touch $(srctree)/arch/l4/Kconfig.isg; \
	   cd $(srctree)/arch/l4 \
	     && ln -fs Kconfig.$(LINSRCARCH) Kconfig.arch)

HAS_BIARCH	:= $(call cc-option-yn, -m32)
ifeq ($(HAS_BIARCH),y)
AS		:= $(AS) --32
LD		:= $(LD) -m elf_i386
CC		:= $(CC) -m32
endif

BASEENV		:= l4env

ifdef CONFIG_RELOCATABLE
LDFLAGS_vmlinux_x86  := --emit-relocs
endif
LDFLAGS_vmlinux_arm  := --no-warn-mismatch
LDFLAGS_vmlinux	:= $(LDFLAGS_vmlinux_$(BASEARCH))

OBJCOPYFLAGS    := -O $(OBJCOPYARCH) -R .note -R .note.gnu.build-id -R .comment -S

L4_MK_API	:= l4$(L4API)
L4_MK_CPU	:= $(patsubst "%",%,$(CONFIG_L4_MK_CPU_$(L4_MK_ARCH_CAP)))

# overwrite UTS_MACHINE to get proper architecture in user land
UTS_MACHINE	:= $(BASEARCH)

KBUILD_CFLAGS   += -gstabs+ -pipe -msoft-float -DARCH_$(L4_MK_ARCH)

ifeq ($(CONFIG_X86_32),y)
	BITS := 32
	UTS_MACHINE := i386
	CHECKFLAGS += -D__i386__

	biarch := $(call cc-option,-m32)
	KBUILD_AFLAGS += $(biarch)
	KBUILD_CFLAGS += $(biarch)

	ifdef CONFIG_RELOCATABLE
		LDFLAGS_vmlinux := --emit-relocs
	endif

	#KBUILD_CFLAGS += -msoft-float -mregparm=3 -freg-struct-return
	KBUILD_CFLAGS += -mregparm=3

	# prevent gcc from keeping the stack 16 byte aligned
	KBUILD_CFLAGS += $(call cc-option,-mpreferred-stack-boundary=2,)

	# Disable unit-at-a-time mode on pre-gcc-4.0 compilers, it makes gcc use
	# a lot more stack due to the lack of sharing of stacklots:
	KBUILD_CFLAGS += $(shell if [ $(call cc-version) -lt 0400 ] ; then \
		echo $(call cc-option,-fno-unit-at-a-time); fi ;)


	# CPU-specific tuning. Anything which can be shared with UML should go here.
	include $(srctree)/arch/x86/Makefile_32.cpu
	KBUILD_CFLAGS += $(cflags-y)

	# temporary until string.h is fixed
	KBUILD_CFLAGS += -ffreestanding
endif

ifeq ($(BASEARCH),x86)
# Stackpointer is addressed different for 32 bit and 64 bit x86
sp-$(CONFIG_X86_32) := esp
sp-$(CONFIG_X86_64) := rsp

# do binutils support CFI?
cfi := $(call as-instr,.cfi_startproc\n.cfi_rel_offset $(sp-y)$(comma)0\n.cfi_endproc,-DCONFIG_AS_CFI=1)
# is .cfi_signal_frame supported too?
cfi-sigframe := $(call as-instr,.cfi_startproc\n.cfi_signal_frame\n.cfi_endproc,-DCONFIG_AS_CFI_SIGNAL_FRAME=1)
KBUILD_AFLAGS += $(cfi) $(cfi-sigframe)
KBUILD_CFLAGS += $(cfi) $(cfi-sigframe)

LDFLAGS := -m elf_$(UTS_MACHINE)

# Speed up the build
KBUILD_CFLAGS += -pipe
# Workaround for a gcc prelease that unfortunately was shipped in a suse release
KBUILD_CFLAGS += -Wno-sign-compare
#
KBUILD_CFLAGS += -fno-asynchronous-unwind-tables
# prevent gcc from generating any FP code by mistake
KBUILD_CFLAGS += $(call cc-option,-mno-sse -mno-mmx -mno-sse2 -mno-3dnow,)

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

KBUILD_CFLAGS += $(call cc-option,-mapcs-32,-mabi=apcs-gnu) $(call cc-option,-mno-thumb-interwork,)
KBUILD_CFLAGS += $(arch-y) $(tune-y)

ifeq ($(CONFIG_ARM_UNWIND),y)
CFLAGS_ABI	+=-funwind-tables
endif

endif


# -----------------------------------------------

-include $(objtree)/Makeconf.l4conf

L4OBJ := $(patsubst "%",%,$(CONFIG_L4_OBJ_TREE))
L4DIR := $(shell readlink $(L4OBJ)/source)
export L4OBJ
export L4DIR


# Extra Libs
L4LX_E_L-$(CONFIG_L4_FB_DRIVER)    += -ll4dope -lvscreen -lcon -lconstream-server
L4LX_E_L-$(CONFIG_L4_BLK_DRV)      += -lgeneric_blk
L4LX_E_L-$(CONFIG_L4_EXTERNAL_RTC) += -lrtc
L4LX_E_L-$(CONFIG_L4_ORE_DRV)      += -lore
L4LX_E_L-$(CONFIG_L4_IRQ_OMEGA0)   += -lomega0
L4LX_E_L-$(CONFIG_L4_PDSPBLK_DRV)  += -lpers_dsp
L4LX_E_L-$(CONFIG_L4_TCG_STPM)     += -lstpm-client
L4LX_E_L-$(CONFIG_L4_USE_L4VMM)	   += -ll4vmm-api$(if $(CONFIG_L4_USE_L4VMM_DBG),-dbg) \
                                      -ll4vmm-core$(if $(CONFIG_L4_USE_L4VMM_DBG),-dbg) \
                                      $(if $(CONFIG_L4_LDR),,-ll4vmm-c) -ll4vmm-cxx
L4LX_E_L-$(CONFIG_L4_CONS)         += -lcons-client
L4LX_E_L-$(CONFIG_L4_FERRET)       += -lferret_client -lferret_producer \
                                      -lferret_init

L4LX_E_L_O-$(CONFIG_L4_USE_L4VMM)  += -ll4vmm-devices$(if $(CONFIG_L4_USE_L4VMM_DBG),-dbg).o

L4LIBS_PATH	= -L$(L4OBJ)/lib/$(L4_MK_ARCH)_$(L4_MK_CPU)/$(L4_MK_API) \
		  -L$(L4OBJ)/lib/$(L4_MK_ARCH)_$(L4_MK_CPU) \
		  -L$(L4OBJ)/lib


L4INC		= -I$(L4OBJ)/include/$(L4_MK_ARCH)/$(L4_MK_API) \
		  -I$(L4OBJ)/include/$(L4_MK_ARCH) \
		  -I$(L4OBJ)/include/$(L4_MK_API) \
		  -I$(L4OBJ)/include \
		  -I$(L4BID_DICE_INCDIR) \
		  $(L4LX_E_I-y)

L4LIBS-$(CONFIG_L4_STATIC_BUILD) = \
                  -llogserver -ldm_mem -ldm_generic -lgeneric_ts \
                  -ll4rm -ll4env -lthread -lsigma0 $(L4LX_E_L-y) \
                  -lsemaphore -lnames -ll4env_err -lgeneric_fprov \
                  -ll4util_root -lslab -levents -lc_be_l4env_start_stop \
                  -lroot \
		  $(shell $(CC) -print-file-name=libgcc.a)

head-y := arch/l4/kernel/head.o arch/l4/kernel/init_task.o

libs-y				+= arch/l4/lib/arch-$(BASEARCH)/	\
				   arch/l4/l4lxlib/generic/		\
				   arch/l4/l4lxlib/$(BASEENV)/

core-y				+= arch/l4/kernel/			\
				   arch/l4/kernel/arch-$(BASEARCH)/	\
				   arch/l4/mm/arch-$(BASEARCH)/
core-$(CONFIG_L4_ARCH_X86)	+= arch/x86/crypto/
core-$(CONFIG_L4_ARCH_X86)	+= arch/x86/vdso/

ifeq ($(BASEARCH),x86)
drivers-$(CONFIG_PCI)		+= arch/l4/pci/
drivers-$(CONFIG_PM)		+= arch/l4/power/arch-x86/
endif

ifeq ($(BASEARCH),arm)
core-$(CONFIG_FPE_NWFPE)	+= arch/arm/nwfpe/
endif

L4LIBS-y			:= $(L4LIBS_PATH) -lio-ll -ldm_phys \
				   -ll4util -ll4sys $(L4LX_E_L-y) \
				   $(L4LIBS-y)

ifeq ($(CONFIG_L4_LDR),y)
  libs-y			+= $(L4LIBS_PATH) -ll4sys
  export L4INC L4LIBS_PATH L4LIBS-y
else
  libs-y			+= $(L4LIBS-y)
endif

L4_CRT0		:= $(L4OBJ)/lib/$(L4_MK_ARCH)_$(L4_MK_CPU)/crt0.o
L4_DYNLINK	:= --dynamic-linker libld-l4.s.so $(L4_CRT0) \
                   -lloader.s $(L4LX_E_L_O-y) -z now
export L4_DYNLINK

ifeq ($(CONFIG_L4_STATIC_BUILD),y)
  LDFLAGS_vmlinux  = $(L4_CRT0)
else
  ifeq ($(CONFIG_L4_LDR),y)
    LDFLAGS_vmlinux  = 
  else
    LDFLAGS_vmlinux  = $(L4_DYNLINK)
  endif
endif

KBUILD_CPPFLAGS	+= -Iarch/l4/include/asm/l4-arch \
		   -I$(src)/arch/$(LINSRCARCH)/include \
		   -Iarch/l4/include/asm/$(LINSRCARCH)-arch \
		   -Iarch/l4/include/asm/orig-arch \
                   -Iarch/l4/include \
                   $(L4INC) $(CPPFLAGS_SYSENTER-y) \
		   $(L4BID_CPPFLAGS_SYSCALLS-y)


# for DICE
KBUILD_CPPFLAGS	+= -DL4API_$(L4_MK_API)

ifneq ($(CONFIG_L4_ARCH_ARM),)
KBUILD_CPPFLAGS += -DTEXT_OFFSET=0x1100000
endif

all: lImage

boot := arch/l4/boot

lImage: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $@

mtags:
	(cd $(srctree) && $(MAKE) tags > /dev/null 2>&1; \
	sort tags > .tags.sorting && mv .tags.sorting tags )

arch/l4/include/asm/$(LINSRCARCH)-arch/mach:
	@echo '  Creating asm-l4/$(LINSRCARCH)-arch/mach symlink'
	$(Q)mkdir -p $(@D)
	$(Q)ln -s $(src)/arch/l4/include/asm/arch-$(LINSRCARCH)/mach $@

arch/l4/include/asm/l4-arch/asm:
	@echo '  Creating asm-l4/l4-arch/asm symlink'
	$(Q)mkdir -p $(@D)
	$(Q)ln -s $(src)/arch/l4/include/asm/arch-$(BASEARCH) $@

arch/l4/include/asm/arch:
	@echo '  Creating asm-l4/arch-$(BASEARCH)/arch -> asm/arch symlink'
	$(Q)mkdir -p $(@D)
	$(Q)ln -s $(src)/arch/l4/include/asm/arch-$(BASEARCH)/arch $@

arch/l4/include/asm/api:
	@echo '  Creating asm-l4/api-$(BASEENV) -> asm/api symlink'
	$(Q)mkdir -p $(@D)
	$(Q)ln -s $(src)/arch/l4/include/asm/api-$(BASEENV) $@

arch/l4/include/asm/l4x:
	@echo '  Creating asm-l4/l4x-$(BASEARCH) -> asm/l4x symlink'
	$(Q)mkdir -p $(@D)
	$(Q)ln -s $(src)/arch/l4/include/asm/l4x-$(BASEARCH) $@

arch/l4/include/asm/l4lxapi/impl:
	@echo '  Creating asm-l4/l4lxapi/impl symlink'
	$(Q)mkdir -p $(@D)
	$(Q)ln -s $(src)/arch/l4/l4lxlib/l4env $@

arch/l4/include/asm/orig-arch:
	@echo '  Creating asm-l4/orig-arch symlink'
	$(Q)mkdir -p $@
	$(Q)ln -s $(src)/arch/$(LINSRCARCH)/include/asm $@/asm-$(LINSRCARCH) 

arch/l4/include/asm/mach-types.h: $(srctree)/arch/arm/tools/gen-mach-types $(srctree)/arch/arm/tools/mach-types
	$(Q)cp $(srctree)/arch/arm/tools/mach-types arch/l4/include/asm/mach-types.list
	$(Q)echo "l4	MACH_L4	L4	9999" >> arch/l4/include/asm/mach-types.list
	$(Q)$(AWK) -f $< arch/l4/include/asm/mach-types.list > $@ || { rm -f $@; /bin/false; }
	$(Q)rm -f arch/l4/include/asm/mach-types.list

symlinks_arm  = arch/l4/include/asm/mach-types.h \
		arch/l4/include/asm/$(LINSRCARCH)-arch/mach

symlinks      = arch/l4/include/asm/api \
                arch/l4/include/asm/l4lxapi/impl \
		arch/l4/include/asm/l4x \
		arch/l4/include/asm/l4-arch/asm \
		arch/l4/include/asm/orig-arch \
                $(symlinks_$(BASEARCH))

MRPROPER_FILES	+= $(symlinks)
CLEAN_FILES	+= Makeconf.l4conf

ifeq ($(config-targets),0)
ifneq ($(wildcard .config),)
$(objtree)/Makeconf.l4conf: $(srctree)/arch/l4/Makefile.l4conf $(srctree)/arch/l4/Makefile
	$(Q)$(if $(L4DIR),PWD=$(L4DIR),) $(MAKE) $(if $(L4DIR),-C $(L4DIR),) -f $< O=$(L4OBJ) OUTPUT=$@

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

DIS_OPTS := HIGHMEM4G HIGHMEM64G PREEMPT PCI_GOANY PCI_GOBIOS HPET_TIMER \
            X86_MCE X86_MCE MTRR PARAVIRT KEXEC MCA SOFTWARE_SUSPEND APM \
	    CPU_FREQ HUGETLBFS HUGETLB_PAGE VM86 X86_DS X86_PTRACE_BTS

check_linux_config:
	@$(foreach i,$(addprefix CONFIG_,$(DIS_OPTS)),     \
	  if [ "$($(i))" = "y" ]; then                     \
	    echo; echo "ERROR: $(i) must not be enabled."; \
	    failed=1;                                      \
	  fi;)                                             \
	  if [ -n "$$failed" ]; then                       \
	    echo; exit 1;                                  \
	  fi
	@if [ "$(CONFIG_X86)" = "y" -a "$(CONFIG_PAGE_OFFSET)" != "0" ]; then \
	  echo "CONFIG_PAGE_OFFSET must be 0."; \
	  exit 1; \
	fi

PHONY += chkl4conf check_linux_config

define archhelp
  echo '* vmlinuz	- Compressed kernel image'
  echo '  chkl4conf     - Check L4 specific configuration'
endef

