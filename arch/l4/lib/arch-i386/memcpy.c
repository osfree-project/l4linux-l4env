#include <linux/string.h>
#include <linux/module.h>

#undef memcpy
#undef memset

void *memcpy(void *to, const void *from, size_t n);
#if 0
{
#ifdef CONFIG_X86_USE_3DNOW
	return __memcpy3d(to, from, n);
#else
	return __memcpy(to, from, n);
#endif
}
#endif
void *memcpy(void *to, const void *from, size_t n);
EXPORT_SYMBOL(memcpy);

void *memset(void *s, int c, size_t count);
#if 0
{
	return __memset(s, c, count);
}
#endif
EXPORT_SYMBOL(memset);

void *memmove(void *dest, const void *src, size_t n)
{
	int d0, d1, d2;

	if (dest < src) {
		memcpy(dest,src,n);
	} else {
		__asm__ __volatile__(
			"std\n\t"
			"rep\n\t"
			"movsb\n\t"
			"cld"
			: "=&c" (d0), "=&S" (d1), "=&D" (d2)
			:"0" (n),
			 "1" (n-1+(const char *)src),
			 "2" (n-1+(char *)dest)
			:"memory");
	}
	return dest;
}
EXPORT_SYMBOL(memmove);
