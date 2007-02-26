/*
 * Timer using the rtc server/lib.
 */
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/timex.h>

#include <asm/timer.h>

#include <l4/rtc/rtc.h>
#include <l4/util/rdtsc.h>

static int __init l4rtc_init(char* override)
{
	l4_uint32_t scaler;
	unsigned long eax = 0, edx = 1000;

	if (override[0] && strncmp(override, "l4rtc", 5))
		return -ENODEV;

	if (l4rtc_get_linux_tsc_scaler(&scaler))
		return -ENODEV;

	if (!scaler)
		return -ENODEV;

	/* Calculate CPU frequency (pilfered from timer_tsc.c) */
	__asm__("divl %2"
	        : "=a" (cpu_khz), "=d" (edx)
		: "r" (scaler), "0" (eax), "1" (edx));

	return 0;
}

static l4_uint32_t l4rtc_last_timer_interrupt_tsc_low;

static void l4rtc_mark_offset(void)
{
	l4rtc_last_timer_interrupt_tsc_low = l4_rdtsc_32();
}

static unsigned long l4rtc_get_offset(void)
{
	l4_uint32_t now = l4_rdtsc_32();

	if (likely(now >= l4rtc_last_timer_interrupt_tsc_low))
		return l4_tsc_to_us(now - l4rtc_last_timer_interrupt_tsc_low);
	else
		return l4_tsc_to_us((1ULL << 32)
				    + now - l4rtc_last_timer_interrupt_tsc_low);
}

static unsigned long long l4rtc_monotonic_clock(void)
{
	return l4_tsc_to_ns(l4_rdtsc());
}

static void l4rtc_delay(unsigned long loops)
{
	int d0;
	__asm__ __volatile__(
		"\tjmp 1f\n"
		".align 16\n"
		"1:\tjmp 2f\n"
		".align 16\n"
		"2:\tdecl %0\n\tjns 2b"
		:"=&a" (d0)
		:"0" (loops));
}

/* tsc timer_opts struct */
static struct timer_opts timer_l4rtc = {
	.name =            "l4rtc",
	.mark_offset =     l4rtc_mark_offset,
	.get_offset =      l4rtc_get_offset,
	.monotonic_clock = l4rtc_monotonic_clock,
	.delay =           l4rtc_delay,
	.read_timer =      read_timer_tsc,
};

struct init_timer_opts __initdata timer_l4rtc_init = {
	.init =	l4rtc_init,
	.opts = &timer_l4rtc,
};
