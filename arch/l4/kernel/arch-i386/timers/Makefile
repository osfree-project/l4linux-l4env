#
# Makefile for x86 timers
#

obj-y := timer.o timer_none.o timer_tsc.o timer_pit.o common.o

timer_pit-y	:= ../../../../i386/kernel/timers/timer_pit.o
timer_tsc-y	:= ../../../../i386/kernel/timers/timer_tsc.o
timer_none-y	:= ../../../../i386/kernel/timers/timer_none.o

obj-$(CONFIG_L4_EXTERNAL_RTC)	+= timer_l4rtc.o
