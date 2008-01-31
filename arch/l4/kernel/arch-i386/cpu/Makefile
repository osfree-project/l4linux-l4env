#
# Makefile for x86-compatible CPU details and quirks
#

obj-y			:= intel_cacheinfo.o addon_cpuid_features.o

obj-$(CONFIG_X86_32)	+= common.o proc.o bugs.o
obj-$(CONFIG_X86_32)	+= amd.o
obj-$(CONFIG_X86_32)	+= cyrix.o
obj-$(CONFIG_X86_32)	+= centaur.o
obj-$(CONFIG_X86_32)	+= transmeta.o
obj-$(CONFIG_X86_32)	+= intel.o
obj-$(CONFIG_X86_32)	+= nexgen.o
obj-$(CONFIG_X86_32)	+= umc.o

obj-$(CONFIG_X86_LOCAL_APIC) += perfctr-watchdog.o

#obj-$(CONFIG_X86_MCE)	+= mcheck/
#obj-$(CONFIG_MTRR)	+= mtrr/
#obj-$(CONFIG_CPU_FREQ)	+= cpufreq/

KBUILD_CFLAGS += -I$(srctree)/arch/x86/kernel/cpu

b                      := ../../../../x86/kernel/cpu

amd-y		       := $(b)/amd.o
cyrix-y		       := $(b)/cyrix.o
centaur-y	       := $(b)/centaur.o
transmeta-y	       := $(b)/transmeta.o
intel_cacheinfo-y      := $(b)/intel_cacheinfo.o
addon_cpuid_features-y := $(b)/addon_cpuid_features.o
rise-y		       := $(b)/rise.o
nexgen-y	       := $(b)/nexgen.o
umc-y		       := $(b)/umc.o
proc-y		       := $(b)/proc.o
bugs-y		       := $(b)/bugs.o
perfctr-watchdog-y     := $(b)/perfctr-watchdog.o
