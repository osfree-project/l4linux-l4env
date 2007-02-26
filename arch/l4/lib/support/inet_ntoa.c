
#include <linux/in.h>
#include <linux/kernel.h>

char *inet_ntoa(struct in_addr);

char *inet_ntoa(struct in_addr n)
{
	static  char buf[20];
	unsigned char *p = (unsigned char *)&n;

	snprintf(buf, sizeof(buf),
	         "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return buf;
}
