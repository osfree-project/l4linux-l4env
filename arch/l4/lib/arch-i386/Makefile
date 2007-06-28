#
# Makefile for l4 library functions
#

lib-y	+= checksum.o memcpy.o

lib-y	+= ../../../i386/lib/bitops.o
lib-y	+= ../../../i386/lib/delay.o
lib-y	+= ../../../i386/lib/mmx.o
lib-y	+= ../../../i386/lib/strstr.o
lib-y	+= ../../../i386/lib/semaphore.o

lib-y	+= ../proc.o
lib-y	+= ../memcpy_user.o
lib-y	+= ../uaccess.o
lib-y	+= ../pte.o

lib-$(CONFIG_X86_USE_3DNOW) += mmx.o
