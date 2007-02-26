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
#include <linux/console.h>
#include <linux/sysrq.h>
#include <linux/device.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial_core.h>
#include <linux/serial.h>

#include <asm/irq.h>
#include <l4/sys/kdebug.h>

/* This is the same major as the sa1100 one */
#define SERIAL_L4SER_MAJOR	204
#define MINOR_START		5

static unsigned int vkey_irq;

static void l4ser_stop_tx(struct uart_port *port)
{
}

static void l4ser_stop_rx(struct uart_port *port)
{
}

static void l4ser_enable_ms(struct uart_port *port)
{
}

static void
l4ser_rx_chars(struct uart_port *port)
{
	struct tty_struct *tty = port->info->tty;
	unsigned int flg;
	int ch;

	while ((ch = l4kd_inchar()) != -1)  {
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

static void l4ser_tx_chars(struct uart_port *port)
{
	struct circ_buf *xmit = &port->info->xmit;
	int c;

	if (port->x_char) {
		outchar(port->x_char);
		port->icount.tx++;
		port->x_char = 0;
		return;
	}

	while (!uart_circ_empty(xmit)) {
		c = CIRC_CNT_TO_END(xmit->head, xmit->tail, UART_XMIT_SIZE);
		outnstring(&xmit->buf[xmit->tail], c);
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

static int l4ser_startup(struct uart_port *port)
{
	int retval;

	if (port->irq) {
		retval = request_irq(port->irq, l4ser_int, 0, "L4-uart", port);
		if (retval)
			return retval;

		l4ser_rx_chars(port);
	}

	return 0;
}

static void l4ser_shutdown(struct uart_port *port)
{
	if (port->irq)
		free_irq(port->irq, port);
}

static void l4ser_set_termios(struct uart_port *port, struct termios *termios,
                              struct termios *old)
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

static struct uart_port	l4ser_port;

static void __init l4ser_init_ports(void)
{
	static int first = 1;

	printk("%s\n", __func__);

	if (!vkey_irq)
		printk(KERN_WARNING "l4ser: vkey_irq not set - input disabled!\n");

	if (!first)
		return;
	first = 0;

	l4ser_port.uartclk   = 3686400;
	l4ser_port.ops       = &l4ser_pops;
	l4ser_port.fifosize  = 8;
	l4ser_port.line      = 0;
	l4ser_port.irq       = vkey_irq;
	l4ser_port.iotype    = UPIO_MEM;
	l4ser_port.membase   = (void *)1;
	l4ser_port.mapbase   = 1;
	l4ser_port.flags     = UPF_BOOT_AUTOCONF;
}

#ifdef CONFIG_L4_SERIAL_CONSOLE

/*
 * Interrupts are disabled on entering
 */
static void
l4ser_console_write(struct console *co, const char *s, unsigned int count)
{
	outnstring(s, count);
}

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

module_param(vkey_irq, uint, 0);
MODULE_PARM_DESC(vkey_irq, "IRQ number of the virtual key interrupt");
