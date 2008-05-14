
#include <string.h>
#include <l4/sys/compiler.h>

asm(
	".global __l4_external_resolver\n"
	"__l4_external_resolver: \n"
	"	pusha\n"
	"	mov 0x24(%esp), %eax\n"
	"	mov 0x20(%esp), %edx\n"
	"	call __C__l4_external_resolver \n"
	"	mov %eax, 0x20(%esp) \n"
	"	popa\n"
	"	ret $4\n"
   );


#define EF(func) \
	void func(void);
#include <func_list.h>

#undef EF
#define EF(func) \
	else if (!strcmp(L4_stringify(func), funcname)) \
             { p = func; }

void do_resolve_error(const char *funcname);

unsigned long __attribute__((regparm(3)))
__C__l4_external_resolver(unsigned long jmptblentry, char **symtab_ptr);
unsigned long __attribute__((regparm(3)))
__C__l4_external_resolver(unsigned long jmptblentry, char **symtab_ptr)
{
	char *funcname = *symtab_ptr;
	void *p;

	if (0) {
	}
#include <func_list.h>
	else
		p = 0;

	if (!p)
		do_resolve_error(funcname);

	*(unsigned long *)jmptblentry = (unsigned long)p;
	return (unsigned long)p;
}
