#
# Makefile for l4 library functions
#

lib-y		:= checksum.o memcpy.o

# (Hmm, composite objects don't work for libs, do we really need lib-y here?)
obj-y		+= strstr.o delay.o bitops.o proc.o \
		   memcpy_user.o uaccess.o pte.o semaphore.o

bitops-y	:= ../../../i386/lib/bitops.o
delay-y		:= ../../../i386/lib/delay.o
mmx-y		:= ../../../i386/lib/mmx.o
strstr-y	:= ../../../i386/lib/strstr.o
semaphore-y	:= ../../../i386/lib/semaphore.o

proc-y		:= ../proc.o
memcpy_user-y	:= ../memcpy_user.o
uaccess-y	:= ../uaccess.o
pte-y		:= ../pte.o

obj-$(CONFIG_X86_USE_3DNOW) += mmx.o
