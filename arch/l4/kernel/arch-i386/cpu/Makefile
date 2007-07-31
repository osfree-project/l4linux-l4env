#
# Makefile for x86-compatible CPU details and quirks
#

obj-y	:=	common.o proc.o bugs.o

obj-y	+=	amd.o
obj-y	+=	cyrix.o
obj-y	+=	centaur.o
obj-y	+=	transmeta.o
obj-y	+=	intel.o
obj-y	+=	rise.o
obj-y	+=	nexgen.o
obj-y	+=	umc.o
#obj-y	+=	perfctr-watchdog.o

CFLAGS += -I$(srctree)/arch/i386/kernel/cpu

b	:= ../../../../i386/kernel/cpu

amd-y		:= $(b)/amd.o
cyrix-y		:= $(b)/cyrix.o
centaur-y	:= $(b)/centaur.o
transmeta-y	:= $(b)/transmeta.o
intel-y		:= $(b)/intel.o $(b)/intel_cacheinfo.o
rise-y		:= $(b)/rise.o
nexgen-y	:= $(b)/nexgen.o
umc-y		:= $(b)/umc.o
proc-y		:= $(b)/proc.o
bugs-y		:= $(b)/bugs.o
perfctr-watchdog-y := $(b)/perfctr-watchdog.o

#obj-$(CONFIG_X86_MCE)	+=	mcheck/

#obj-$(CONFIG_MTRR)	+= 	mtrr/
#obj-$(CONFIG_CPU_FREQ)	+=	cpufreq/

obj-$(CONFIG_X86_LOCAL_APIC) += perfctr-watchdog.o
