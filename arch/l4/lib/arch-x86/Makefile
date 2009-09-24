#
# Makefile for l4 library functions
#

lib-y	+= checksum.o memcpy.o ../memcpy_user.o ../uaccess.o ../pte.o
lib-$(CONFIG_X86_USE_3DNOW) += mmx_32.o

lib-y	+= ../../../x86/lib/atomic64_32.o
lib-y	+= ../../../x86/lib/delay.o
lib-y	+= ../../../x86/lib/strstr_32.o
lib-y	+= ../../../x86/lib/semaphore_32.o
lib-y	+= ../../../x86/lib/string_32.o
lib-y   += ../../../x86/lib/mmx_32.o

obj-y		+= proc.o
proc-y		:= ../proc.o

create_dir:
	$(Q)mkdir -p $(obj)/../../../x86/lib

PHONY += create_dir

$(obj)/../../../x86/lib/delay.o: create_dir
