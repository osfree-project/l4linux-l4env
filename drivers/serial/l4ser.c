/*
 *  drivers/char/l4ser.c
 *
 *  L4 pseudo serial driver.
 *
 *  Based on sa1100.c and other drivers from drivers/serial/.
 */
#if defined(CONFIG_L4_SERIAL_CONSOLE) && defined(CONFIG_MAGIC_SYSRQ)
#define SUPPORT_SYSRQ
#endif

#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/console.h>
#include <linux/sysrq.h>
#include <linux/device.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial_core.h>
#include <linux/serial.h>

#include <l4/sys/kdebug.h>
#include <l4/sys/syscalls.h>
#include <asm/generic/setup.h>

#ifdef CONFIG_L4_CONS
#include <asm/generic/l4lib.h>
#include <asm/generic/do_irq.h>
#include <l4/names/libnames.h>
#include <asm/l4lxapi/thread.h>
#include <l4/cons/cons-client.h>
#include <l4/cons/event-server.h>
#include <l4/log/log_printf.h>

typedef L4_CV void
  cons_event_ping_component_t(CORBA_Object _dice_corba_obj,
                              CORBA_Server_Environment *_dice_corba_env);

L4_CV void register_cons_event_ping_component(cons_event_ping_component_t *func);

L4_EXTERNAL_FUNC(register_cons_event_ping_component);

L4_EXTERNAL_FUNC(cons_client_output_string_call);
L4_EXTERNAL_FUNC(cons_client_get_input_call);
L4_EXTERNAL_FUNC(cons_event_server_loop);
L4_EXTERNAL_FUNC(cons_client_create_call);
#endif

/* This is the same major as the sa1100 one */
#define SERIAL_L4SER_MAJOR	204
#define MINOR_START		5

static unsigned int vkey_enable;

static struct uart_port	l4ser_port;

#ifdef CONFIG_L4_CONS
static struct irq_chip *l4ser_orig_irq_type;
static unsigned int use_cons;
static l4_threadid_t cons_id, ev_id = L4_INVALID_ID;
#endif

/*
 * Interrupts are disabled on entering
 */
static void
l4ser_console_write(struct console *co, const char *s, unsigned int count)
{
#ifdef CONFIG_L4_CONS
	if (use_cons) {
		DICE_DECLARE_ENV(env);

		if (l4_is_invalid_id(ev_id))
			return;

		if (cons_client_output_string_call(&cons_id, count, s, &env)
		    || DICE_HAS_EXCEPTION(&env)) {
			LOG_printf("l4ser: console output error\n");
		}
		return;
	}
#endif
	outnstring(s, count);
}

static void l4ser_stop_tx(struct uart_port *port)
{
}

static void l4ser_stop_rx(struct uart_port *port)
{
}

static void l4ser_enable_ms(struct uart_port *port)
{
}

static int
l4ser_getchar(void)
{
#ifdef CONFIG_L4_CONS
	if (use_cons) {
		DICE_DECLARE_ENV(env);
		long ch;

		if (cons_client_get_input_call(&cons_id, &ch, &env) == 1
		    && !DICE_HAS_EXCEPTION(&env))
			return ch;
		return -1;
	}
#endif

	return l4kd_inchar();
}

static void
l4ser_rx_chars(struct uart_port *port)
{
	struct tty_struct *tty = port->info->port.tty;
	unsigned int flg;
	int ch;

	while ((ch = l4ser_getchar()) != -1)  {
		//printk("LX:got char: {%d}\n", ch);

		port->icount.rx++;

		flg = TTY_NORMAL;

		if (uart_handle_sysrq_char(port, ch))
			continue;

		tty_insert_flip_char(tty, ch, flg);
	}
	tty_flip_buffer_push(tty);
	return;
}

#ifdef CONFIG_L4_CONS
L4_CV void
cons_event_ping_component(CORBA_Object _dice_corba_obj,
                          CORBA_Server_Environment *_dice_corba_env)
{
	l4x_do_IRQ(L4X_IRQ_CONS, current_thread_info());
}


L4_CV static void
l4ser_event_thread(void *d)
{
	(void)d;
	l4x_prepare_irq_thread(current_thread_info(), 0);
	cons_event_server_loop(NULL);
}
#endif

static void l4ser_tx_chars(struct uart_port *port)
{
	struct circ_buf *xmit = &port->info->xmit;
	int c;

	if (port->x_char) {
		l4ser_console_write(NULL, &port->x_char, 1);
		port->icount.tx++;
		port->x_char = 0;
		return;
	}

	while (!uart_circ_empty(xmit)) {
		c = CIRC_CNT_TO_END(xmit->head, xmit->tail, UART_XMIT_SIZE);
		l4ser_console_write(NULL, &xmit->buf[xmit->tail], c);
		xmit->tail = (xmit->tail + c) & (UART_XMIT_SIZE - 1);
		port->icount.tx += c;
	}
}

static void l4ser_start_tx(struct uart_port *port)
{
	l4ser_tx_chars(port);
}

static irqreturn_t l4ser_int(int irq, void *dev_id)
{
	struct uart_port *sport = dev_id;

	l4ser_rx_chars(sport);

	return IRQ_HANDLED;
}

static unsigned int l4ser_tx_empty(struct uart_port *port)
{
	return TIOCSER_TEMT;
}

static unsigned int l4ser_get_mctrl(struct uart_port *port)
{
	return 0;
}

static void l4ser_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
}

static void l4ser_break_ctl(struct uart_port *port, int break_state)
{
}

static unsigned int l4ser_irq_startup(unsigned int irq)
{
	return 1;
}

static void l4ser_irq_dummy_void(unsigned int irq)
{
}

struct irq_chip l4ser_irq_type = {
	.name		= "L4Ore IRQ",
	.startup	= l4ser_irq_startup,
	.shutdown	= l4ser_irq_dummy_void,
	.enable		= l4ser_irq_dummy_void,
	.disable	= l4ser_irq_dummy_void,
	.mask		= l4ser_irq_dummy_void,
	.unmask		= l4ser_irq_dummy_void,
	.ack		= l4ser_irq_dummy_void,
	.end		= l4ser_irq_dummy_void,
};

static int l4ser_startup(struct uart_port *port)
{
	int retval;

	if (port->irq) {
#ifdef CONFIG_L4_CONS
		if (use_cons) {
			l4ser_orig_irq_type = irq_desc[port->irq].chip;
			irq_desc[port->irq].chip = &l4ser_irq_type;
		}
#endif
		retval = request_irq(port->irq, l4ser_int, 0, "L4-uart", port);
		if (retval)
			return retval;

		l4ser_rx_chars(port);
	}

	return 0;
}

static void l4ser_shutdown(struct uart_port *port)
{
	if (port->irq) {
		free_irq(port->irq, port);
#ifdef CONFIG_L4_CONS
		if (use_cons)
			irq_desc[port->irq].chip = l4ser_orig_irq_type;
#endif
	}
}

static void l4ser_set_termios(struct uart_port *port, struct ktermios *termios,
                              struct ktermios *old)
{
}

static const char *l4ser_type(struct uart_port *port)
{
	return port->type == PORT_SA1100 ? "L4" : NULL;
}


static int l4ser_request_port(struct uart_port *port)
{
	return 0;
}

static void l4ser_release_port(struct uart_port *port)
{
}

static void l4ser_config_port(struct uart_port *port, int flags)
{
	if (flags & UART_CONFIG_TYPE)
		port->type = PORT_SA1100;
}

static int
l4ser_verify_port(struct uart_port *port, struct serial_struct *ser)
{
	return 0;
}

static struct uart_ops l4ser_pops = {
	.tx_empty	= l4ser_tx_empty,
	.set_mctrl	= l4ser_set_mctrl,
	.get_mctrl	= l4ser_get_mctrl,
	.stop_tx	= l4ser_stop_tx,
	.start_tx	= l4ser_start_tx,
	.stop_rx	= l4ser_stop_rx,
	.enable_ms	= l4ser_enable_ms,
	.break_ctl	= l4ser_break_ctl,
	.startup	= l4ser_startup,
	.shutdown	= l4ser_shutdown,
	.set_termios	= l4ser_set_termios,
	.type		= l4ser_type,
	.release_port	= l4ser_release_port,
	.request_port	= l4ser_request_port,
	.config_port	= l4ser_config_port,
	.verify_port	= l4ser_verify_port,
};

static void __init l4ser_init_ports(void)
{
	static int first = 1;

	if (!first)
		return;
	first = 0;

#ifdef CONFIG_L4_CONS
	if (use_cons) {
		DICE_DECLARE_ENV(env);

		char s[12];
		if (!names_waitfor_name("cons", &cons_id, 10000)) {
			LOG_printf("Server 'cons' not found, aborting.\n");
			return;
		}

#ifdef CONFIG_L4_LDR
		register_cons_event_ping_component(cons_event_ping_component);
#endif

		ev_id = l4lx_thread_create(l4ser_event_thread, 0, NULL,
		                           NULL, 0, CONFIG_L4_PRIO_L4ORE,
		                           "consev");
		if (l4_is_invalid_id(ev_id)) {
			LOG_printf("Event thread creation failed, aborting.\n");
			return;
		}

		snprintf(s, sizeof(s), "L4Linux%d", l4_myself().id.task);
		s[sizeof(s)-1] = 0;

		if (cons_client_create_call(&cons_id, s, &ev_id, &env)
		    || DICE_HAS_EXCEPTION(&env)) {
			LOG_printf("Failed to create console\n");
			l4lx_thread_shutdown(ev_id);
			ev_id = L4_INVALID_ID;
			return;
		}

	} else
#endif
		if (!vkey_enable)
			printk(KERN_WARNING "l4ser: input not enabled!\n");

	l4ser_port.uartclk   = 3686400;
	l4ser_port.ops       = &l4ser_pops;
	l4ser_port.fifosize  = 8;
	l4ser_port.line      = 0;
	l4ser_port.iotype    = UPIO_MEM;
	l4ser_port.membase   = (void *)1;
	l4ser_port.mapbase   = 1;
	l4ser_port.flags     = UPF_BOOT_AUTOCONF;
#ifdef CONFIG_L4_CONS
	if (use_cons)
	  l4ser_port.irq     = L4X_IRQ_CONS;
	else
#endif
	  l4ser_port.irq     = vkey_enable ? l4lx_kinfo->vkey_irq : 0;
}

#ifdef CONFIG_L4_SERIAL_CONSOLE

static int __init
l4ser_console_setup(struct console *co, char *options)
{
	return 0;
}

static struct uart_driver l4ser_reg;
static struct console l4ser_console = {
	.name		= "ttyLv",
	.write		= l4ser_console_write,
	.device		= uart_console_device,
	.setup		= l4ser_console_setup,
	.flags		= CON_PRINTBUFFER,
	.index		= -1,
	.data		= &l4ser_reg,
};

static int __init l4ser_rs_console_init(void)
{
	l4ser_init_ports();
	register_console(&l4ser_console);
	return 0;
}
console_initcall(l4ser_rs_console_init);

#define L4SER_CONSOLE	&l4ser_console
#else
#define L4SER_CONSOLE	NULL
#endif

static struct uart_driver l4ser_reg = {
	.owner			= THIS_MODULE,
	.driver_name		= "ttyLv",
	.dev_name		= "ttyLv",
	.major			= SERIAL_L4SER_MAJOR,
	.minor			= MINOR_START,
	.nr			= 1,
	.cons			= L4SER_CONSOLE,
};

static int __init l4ser_serial_init(void)
{
	int ret;

	printk(KERN_INFO "L4 serial driver\n");

	l4ser_init_ports();

	ret = uart_register_driver(&l4ser_reg);
	if (!ret)
		uart_add_one_port(&l4ser_reg, &l4ser_port);

	return ret;
}

static void __exit l4ser_serial_exit(void)
{
	uart_unregister_driver(&l4ser_reg);
}

module_init(l4ser_serial_init);
module_exit(l4ser_serial_exit);

MODULE_AUTHOR("Adam Lackorzynski <adam@os.inf.tu-dresden.de");
MODULE_DESCRIPTION("L4 serial driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CHARDEV_MAJOR(SERIAL_L4SER_MAJOR);

module_param(vkey_enable, uint, 0400);
MODULE_PARM_DESC(vkey_enable, "Enable virtual key input");
#ifdef CONFIG_L4_CONS
module_param(use_cons, uint, 0400);
MODULE_PARM_DESC(use_cons, "Use console server");
#endif
