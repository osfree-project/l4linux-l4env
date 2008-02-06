
#include <linux/module.h>

#include <l4/util/macros.h>
#include <l4/log/log_printf.h>

#include <asm/l4lxapi/thread.h>

static int __init l4x_module_init(void)
{
	printk("Hi from the sample module\n");
	LOG_printf("sample module: Also a warm welcome to the console\n");

	printk("The current thread is " l4util_idfmt ".\n",
	       l4util_idstr(l4lx_thread_id_get()));


	return 0;
}

static void __exit l4x_module_exit(void)
{
	LOG_printf("Bye from sample module\n");
}

module_init(l4x_module_init);
module_exit(l4x_module_exit);

MODULE_AUTHOR("Adam Lackorzynski <adam@os.inf.tu-dresden.de>");
MODULE_DESCRIPTION("L4Linux sample module");
MODULE_LICENSE("GPL");
