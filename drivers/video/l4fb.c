/*
 * Framebuffer driver for DOpE/CON
 *
 * based on vesafb.c
 *
 * Adam Lackorzynski <adam@os.inf.tu-dresden.de>
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/fb.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/input.h>
#include <linux/platform_device.h>
#include <linux/screen_info.h>

#include <l4/env/errno.h>
#include <l4/names/libnames.h>
#include <l4/dm_phys/dm_phys.h>

#include <l4/l4con/stream-server.h>
#include <l4/l4con/l4con.h>
#include <l4/l4con/l4con-client.h>

#include <l4/dope/dopelib.h>
#include <l4/dope/vscreen.h>

#include <asm/l4lxapi/thread.h>
#include <asm/l4lxapi/misc.h>

#include <asm/generic/setup.h>
#include <asm/generic/l4fb.h>

/* Default values */
enum {
	SCR_DFL_WIDTH  = 640,
	SCR_DFL_HEIGHT = 480,
	SCR_DFL_DEPTH  = 16,
};

enum mode {
	MODE_NONE,
	MODE_DOPE,
	MODE_CON
};

static unsigned int xres = SCR_DFL_WIDTH, yres = SCR_DFL_HEIGHT;
static unsigned int depth;

static unsigned int dope_xpos = 120, dope_ypos = 60;
static char *dope_window_title = "Linux console";
static unsigned int nograb;
static l4dm_dataspace_t fbds;
static int disable, use_con, use_dope;

static enum mode mode = MODE_NONE;

/* Global variables for DOpE */
static long dope_app_id;

/* Global variables for CON */
static l4_threadid_t   con_id;
static l4_threadid_t   vc_id;
static int             redraw_pending;

static unsigned int l4fb_refresh_sleep = 100;
static int          l4fb_refresh_enabled = 1;

static l4_threadid_t l4fb_refresher_thread = L4_INVALID_ID;
static l4_threadid_t l4fb_input_thread = L4_INVALID_ID;

/* -- module paramter variables ---------------------------------------- */

static int refreshsleep = -1, xpos = -1, ypos = -1;
static char window_title[50];

/* -- framebuffer variables/structures --------------------------------- */

static struct fb_var_screeninfo l4fb_defined = {
	.activate	= FB_ACTIVATE_NOW,
	.height		= -1,
	.width		= -1,
	.right_margin	= 32,
	.upper_margin	= 16,
	.lower_margin	= 4,
	.vsync_len	= 4,
	.vmode		= FB_VMODE_NONINTERLACED,
};

static struct fb_fix_screeninfo l4fb_fix = {
	.id	= "l4fb",
	.type	= FB_TYPE_PACKED_PIXELS,
	.accel	= FB_ACCEL_NONE,
};

static u32 pseudo_palette[17];

/* -- implementations -------------------------------------------------- */

static void vesa_setpalette(int regno, unsigned red, unsigned green,
			    unsigned blue)
{
#if 0
	struct { u_char blue, green, red, pad; } entry;
	int shift = 16 - depth;

	if (pmi_setpal) {
		entry.red   = red   >> shift;
		entry.green = green >> shift;
		entry.blue  = blue  >> shift;
		entry.pad   = 0;
	        __asm__ __volatile__(
                "call *(%%esi)"
                : /* no return value */
                : "a" (0x4f09),         /* EAX */
                  "b" (0),              /* EBX */
                  "c" (1),              /* ECX */
                  "d" (regno),          /* EDX */
                  "D" (&entry),         /* EDI */
                  "S" (&pmi_pal));      /* ESI */
	} else {
		/* without protected mode interface, try VGA registers... */
		outb_p(regno,       dac_reg);
		outb_p(red   >> shift, dac_val);
		outb_p(green >> shift, dac_val);
		outb_p(blue  >> shift, dac_val);
	}
#endif
}

static int l4fb_setcolreg(unsigned regno, unsigned red, unsigned green,
			  unsigned blue, unsigned transp,
			  struct fb_info *info)
{
	/*
	 *  Set a single color register. The values supplied are
	 *  already rounded down to the hardware's capabilities
	 *  (according to the entries in the `var' structure). Return
	 *  != 0 for invalid regno.
	 */
	
	if (regno >= info->cmap.len)
		return 1;

	if (info->var.bits_per_pixel == 8)
		vesa_setpalette(regno,red,green,blue);
	else if (regno < 16) {
		switch (info->var.bits_per_pixel) {
		case 16:
			((u32*) (info->pseudo_palette))[regno] =
				((red   >> (16 -   info->var.red.length)) <<   info->var.red.offset) |
				((green >> (16 - info->var.green.length)) << info->var.green.offset) |
				((blue  >> (16 -  info->var.blue.length)) <<  info->var.blue.offset);
			break;
		case 24:
		case 32:
			red   >>= 8;
			green >>= 8;
			blue  >>= 8;
			((u32 *)(info->pseudo_palette))[regno] =
				(red   << info->var.red.offset)   |
				(green << info->var.green.offset) |
				(blue  << info->var.blue.offset);
			break;
		}
	}

	return 0;
}

static int l4fb_pan_display(struct fb_var_screeninfo *var,
                            struct fb_info *info)
{
	return 0;
}

static void (*l4fb_update_rect)(int x, int y, int w, int h);

static l4fb_input_event_hook_function_type l4fb_input_event_hook_function;

void l4fb_input_event_hook_register(l4fb_input_event_hook_function_type f)
{
	l4fb_input_event_hook_function = f;
}
EXPORT_SYMBOL(l4fb_input_event_hook_register);

void l4fb_refresh_status_set(int status)
{
	l4fb_refresh_enabled = status;
}
EXPORT_SYMBOL(l4fb_refresh_status_set);

l4_threadid_t l4fb_con_con_id_get(void)
{
	return con_id;
}
EXPORT_SYMBOL(l4fb_con_con_id_get);

l4_threadid_t l4fb_con_vc_id_get(void)
{
	return vc_id;
}
l4dm_dataspace_t l4fb_con_ds_id_get(void)
{
	return fbds;
}      
EXPORT_SYMBOL(l4fb_con_vc_id_get);

static void l4fb_con_update_rect(int x, int y, int w, int h)
{
	int res;
	l4con_pslim_rect_t r = { x, y, w, h };
	DICE_DECLARE_ENV(_env);

	if (redraw_pending) {
		r.x =
		r.y = 0;
		r.w = xres;
		r.h = yres;
		redraw_pending = 0;
	}

	if ((res = con_vc_direct_update_call(&vc_id, &r, &_env))
	    || DICE_HAS_EXCEPTION(&_env))
		printk("%s: Error updating region: %s(%d)\n",
		       __func__, l4env_errstr(res), res);
}

static void l4fb_dope_update_rect(int x, int y, int w, int h)
{
	dope_cmdf(dope_app_id, "l4lxvscr.refresh(-x %d -y %d -w %d -h %d)", x, y, w, h);
}

static void l4fb_copyarea(struct fb_info *info, const struct fb_copyarea *region)
{
	cfb_copyarea(info, region);
	if (l4fb_update_rect)
		l4fb_update_rect(region->dx, region->dy, region->width, region->height);
}

static void l4fb_fillrect(struct fb_info *info, const struct fb_fillrect *rect)
{
	cfb_fillrect(info, rect);
	if (l4fb_update_rect)
		l4fb_update_rect(rect->dx, rect->dy, rect->width, rect->height);
}

static void l4fb_imageblit(struct fb_info *info, const struct fb_image *image)
{
	cfb_imageblit(info, image);
	if (l4fb_update_rect)
		l4fb_update_rect(image->dx, image->dy, image->width, image->height);
}

static int l4fb_open(struct fb_info *info, int user)
{
	//printk("%s.\n", __func__);
	return 0;
}

static int l4fb_release(struct fb_info *info, int user)
{
	//printk("%s.\n", __func__);
	return 0;
}

static struct fb_ops l4fb_ops = {
	.owner		= THIS_MODULE,
	.fb_open        = l4fb_open,
	.fb_release     = l4fb_release,
	.fb_setcolreg	= l4fb_setcolreg,
	.fb_pan_display	= l4fb_pan_display,
	.fb_fillrect	= l4fb_fillrect,
	.fb_copyarea	= l4fb_copyarea,
	.fb_imageblit	= l4fb_imageblit,
};

static void __init l4fb_setup(char *options)
{
	char *this_opt, *c;

	if (!options || !*options)
		return;

	while ((this_opt = strsep(&options, ",")) != NULL) {
		if (!*this_opt) continue;

		if (!strncmp(this_opt, "refreshsleep:", 13))
			l4fb_refresh_sleep = simple_strtoul(this_opt + 13, NULL, 0);
		else if (!strncmp(this_opt, "xpos:", 5))
			dope_xpos = simple_strtoul(this_opt + 5, NULL, 0);
		else if (!strncmp(this_opt, "ypos:", 5))
			dope_ypos = simple_strtoul(this_opt + 5, NULL, 0);
		else if (!strncmp(this_opt, "title:", 6))
			dope_window_title = this_opt + 6;
		else if (!strncmp(this_opt, "xres:", 5))
			xres = simple_strtoul(this_opt + 5, NULL, 0);
		else if (!strncmp(this_opt, "yres:", 5))
			yres = simple_strtoul(this_opt + 5, NULL, 0);
		else if (!strncmp(this_opt, "depth:", 6))
			depth = simple_strtoul(this_opt + 6, NULL, 0);
		else if ((c = strchr(this_opt, 'x'))) {
			xres = simple_strtoul(this_opt, NULL, 0);
			yres = simple_strtoul(c + 1, NULL, 0);
			if ((c = strchr(c, '@')))
				depth = simple_strtoul(c + 1, NULL, 0);
		}
	}

	/* sanatize if needed */
	if (!xres || !yres) {
		xres = SCR_DFL_WIDTH;
		yres = SCR_DFL_HEIGHT;
	}
	if (!depth)
		depth = SCR_DFL_DEPTH;
}

/* ============================================ */

/* Mouse and keyboard are split so that mouse button events are not
 * treated as keyboard events in the Linux console. */
struct input_dev *l4input_dev_key;
struct input_dev *l4input_dev_mouse;

static void l4fb_dope_input_callback(dope_event *e, void *arg)
{
	struct input_dev *inp = l4input_dev_mouse;
	int press = 1;

	/* The input_report functions are contributing to the random
	 * subsystem but this subsystem seems to be initialized _after_
	 * l4fb, so that we get 0-pointer derefs when calling
	 * input_report_*.
	 * So wait to submit input events until the system is up and
	 * running.
	 * (Maybe we could play with late_initcall here too.)
	 */
	if (system_state != SYSTEM_RUNNING)
		return;

	switch (e->type) {
		case EVENT_TYPE_RELEASE:
			press = 0;
			/* fall through */
		case EVENT_TYPE_PRESS:
			if (e->press.code < BTN_MISC)
				inp = l4input_dev_key;

			/* e->press.code and e->release.code are the same... */
			input_report_key(inp, e->press.code, press);
			break;
		case EVENT_TYPE_MOTION:
			input_report_rel(inp, REL_X, e->motion.rel_x);
			input_report_rel(inp, REL_Y, e->motion.rel_y);
			input_report_abs(inp, ABS_X, e->motion.abs_x);
			input_report_abs(inp, ABS_Y, e->motion.abs_y);
			break;
		default:
			printk("l4fb: Unknown input event type: %ld\n", e->type);
			return;
	};
	input_sync(inp);
}

static void l4fb_dope_input_thread(void *data)
{
	l4x_prepare_irq_thread(current_thread_info());
	dope_eventloop(dope_app_id);
}

static int l4fb_input_setup_generic(void)
{
	unsigned int i;

	l4input_dev_key   = input_allocate_device();
	l4input_dev_mouse = input_allocate_device();
	if (!l4input_dev_key || !l4input_dev_mouse)
		return -ENOMEM;

	/* Keyboard */
	l4input_dev_key->name = "l4input key";
	l4input_dev_key->phys = "DOpE/CON key";
	l4input_dev_key->id.bustype = BUS_USB;
	l4input_dev_key->id.vendor  = 0;
	l4input_dev_key->id.product = 0;
	l4input_dev_key->id.version = 0;

	/* We generate key events */
	set_bit(EV_KEY, l4input_dev_key->evbit);
	set_bit(EV_REP, l4input_dev_key->evbit);
	/* We can generate every key */
	for (i = 0; i < 0x100; i++)
		set_bit(i, l4input_dev_key->keybit);

	input_register_device(l4input_dev_key);

	/* Mouse */
	l4input_dev_mouse->name = "l4input mouse";
	l4input_dev_mouse->phys = "DOpE/CON mouse";
	l4input_dev_mouse->id.bustype = BUS_USB;
	l4input_dev_mouse->id.vendor  = 0;
	l4input_dev_mouse->id.product = 0;
	l4input_dev_mouse->id.version = 0;

	/* We generate key and relative mouse events */
	set_bit(EV_KEY, l4input_dev_mouse->evbit);
	set_bit(EV_REP, l4input_dev_mouse->evbit);
	set_bit(EV_REL, l4input_dev_mouse->evbit);
	set_bit(EV_ABS, l4input_dev_mouse->evbit);

	/* Buttons */
	set_bit(BTN_0,      l4input_dev_mouse->keybit);
	set_bit(BTN_1,      l4input_dev_mouse->keybit);
	set_bit(BTN_2,      l4input_dev_mouse->keybit);
	set_bit(BTN_3,      l4input_dev_mouse->keybit);
	set_bit(BTN_4,      l4input_dev_mouse->keybit);
	set_bit(BTN_LEFT,   l4input_dev_mouse->keybit);
	set_bit(BTN_RIGHT,  l4input_dev_mouse->keybit);
	set_bit(BTN_MIDDLE, l4input_dev_mouse->keybit);

	/* Movements */
	set_bit(REL_X,      l4input_dev_mouse->relbit);
	set_bit(REL_Y,      l4input_dev_mouse->relbit);
	set_bit(ABS_X,      l4input_dev_mouse->absbit);
	set_bit(ABS_Y,      l4input_dev_mouse->absbit);

	/* Coordinates are 1:1 pixel in frame buffer */
	l4input_dev_mouse->absmin[ABS_X] = 0;
	l4input_dev_mouse->absmin[ABS_Y] = 0;
	l4input_dev_mouse->absmax[ABS_X] = xres;
	l4input_dev_mouse->absmax[ABS_Y] = yres;
	/* We are precise */
	l4input_dev_mouse->absfuzz[ABS_X] = 0;
	l4input_dev_mouse->absfuzz[ABS_Y] = 0;
	l4input_dev_mouse->absflat[ABS_X] = 0;
	l4input_dev_mouse->absflat[ABS_Y] = 0;

	input_register_device(l4input_dev_mouse);

	return 0;
}

static int l4fb_dope_input_setup(void)
{
	dope_bind(dope_app_id, "l4lxvscr", "motion",  l4fb_dope_input_callback, (void *)0x876);
	dope_bind(dope_app_id, "l4lxvscr", "press",   l4fb_dope_input_callback, (void *)0x877);
	dope_bind(dope_app_id, "l4lxvscr", "release", l4fb_dope_input_callback, (void *)0x878);

	l4fb_input_thread = l4lx_thread_create(l4fb_dope_input_thread,
	                                       NULL, NULL, 0, 144, "L4DOpEinput");
	if (l4_is_invalid_id(l4fb_input_thread)) {
		enter_kdebug("l4dopeinput thread err!");
		return -ENODEV;
	}

	return l4fb_input_setup_generic();
}

static __attribute__((unused)) void l4fb_dope_input_cleanup(void)
{
	input_unregister_device(l4input_dev_key);
	input_unregister_device(l4input_dev_mouse);
}

void stream_io_push_component(CORBA_Object _dice_corba_obj,
                              const stream_io_input_event_t *event,
                              CORBA_Server_Environment *_dice_corba_env)
{
	struct input_event *e = (struct input_event *)event;

	/* Prevent input events before system is up, see comment in
	 * DOpE input function for more. */
	if (system_state != SYSTEM_RUNNING) {
		/* Serve pending redraw requests later */
		if (e->type == EV_CON && e->code == EV_CON_REDRAW)
			redraw_pending = 1;
		return;
	}

	if (l4fb_input_event_hook_function)
		if (l4fb_input_event_hook_function(e->type, e->code))
			return;

	/* console sent redraw event -- update whole screen */
	if (e->type == EV_CON && e->code == EV_CON_REDRAW) {
		l4fb_con_update_rect(0, 0, xres, yres);
		return;
	}

	/* The l4input library is based on Linux-2.6, so we're lucky here */
	if (e->type == EV_KEY && e->code < BTN_MISC) {
		input_event(l4input_dev_key, e->type, e->code, e->value);
		input_sync(l4input_dev_key);
	} else {
		input_event(l4input_dev_mouse, e->type, e->code, e->value);
		input_sync(l4input_dev_mouse);
	}
}

static void l4fb_con_input_thread(void *data)
{
	l4x_prepare_irq_thread(current_thread_info());
	stream_io_server_loop(NULL);
}

static void l4fb_con_update_thread(void *data)
{
	l4x_prepare_irq_thread(current_thread_info());
	while (1) {
		if (l4fb_refresh_enabled)
			l4fb_con_update_rect(0, 0, xres, yres);
		l4lx_sleep(l4fb_refresh_sleep);
	}
}

static int l4fb_con_input_setup(l4_threadid_t *id)
{
	l4fb_input_thread = l4lx_thread_create(l4fb_con_input_thread,
	                                       NULL, NULL, 0, 144, "L4ConInput");
	if (l4_is_invalid_id(l4fb_input_thread)) {
		enter_kdebug("l4coninput thread error!");
		return -ENODEV;
	}
	*id = l4fb_input_thread;
	return l4fb_input_setup_generic();
}

static void l4fb_create_refresher_thread(void (*refresher_thread)(void *),
                                         const char *const name_tag)
{
	if (!l4fb_refresh_sleep)
		return;

	l4fb_refresher_thread = l4lx_thread_create(refresher_thread,
	                                           NULL, NULL, 0, 144, name_tag);
	if (l4_is_invalid_id(l4fb_refresher_thread)) {
		printk("Cannot create %s\n", name_tag);
		enter_kdebug("l4fb: refresh thread create error!");
	}
}

/* ============================================ */

static int l4fb_con_init(struct fb_var_screeninfo *var,
                         struct fb_fix_screeninfo *fix)
{
	l4_threadid_t ev_id = L4_NIL_ID;
	l4_uint8_t gmode;
	l4_uint32_t bytes_per_pixel;
	l4_uint32_t bytes_per_line, accel_flags;
	l4_uint32_t fn_x, fn_y;
	int res;
	DICE_DECLARE_ENV(_env);

	LOG_printf("Starting L4FB via CON\n");

	if (names_waitfor_name(CON_NAMES_STR, &con_id, 2000) == 0) {
		LOG_printf("CON not available!\n");
		return -ENODEV;
	}

	if (con_if_openqry_call(&con_id, 16 << 10, 0, 0,
	                        L4THREAD_DEFAULT_PRIO,
	                        &vc_id, CON_NOVFB, &_env)
	    || DICE_HAS_EXCEPTION(&_env)) {
		LOG_printf("Cannot open VC!\n");
		return -ENODEV;
	}

	if ((res = l4fb_con_input_setup(&ev_id)))
		return res;

	if (con_vc_smode_call(&vc_id, CON_INOUT, &ev_id, &_env)
	    || DICE_HAS_EXCEPTION(&_env)) {
		LOG_printf("Cannot setup VC!\n");
		return -ENODEV;
	}

	if (con_vc_graph_gmode_call(&vc_id, &gmode, &var->xres, &var->yres,
	                            &var->bits_per_pixel, &bytes_per_pixel,
	                            &bytes_per_line, &accel_flags,
	                            &fn_x, &fn_y, &_env)
	    || DICE_HAS_EXCEPTION(&_env)) {
		LOG_printf("Cannot get graphics mode!\n");
		return -ENODEV;
	}

	/* The console expects the real screen resolution, not the virtual */
	fix->line_length    = var->xres * bytes_per_pixel;
	/* Round-up the memory a little bit. Due to a bug in Linux, the
	 * cursor is sometimes set to and paint at the first position after
	 * the framebuffer. */
	fix->smem_len       = var->xres * bytes_per_pixel * 
	                      ((var->yres + 15) & ~15);
	fix->visual         = FB_VISUAL_TRUECOLOR;

	/* We cannot really set (smaller would work) screen paramenters
	 * when using con */
	xres  = var->xres;
	yres  = var->yres;
	if (var->bits_per_pixel == 15)
		var->bits_per_pixel = 16;
	depth = var->bits_per_pixel;

	if (con_vc_graph_get_rgb_call(&vc_id,
	                              &var->red.offset, &var->red.length,
				      &var->green.offset, &var->green.length,
				      &var->blue.offset, &var->blue.length,
				      &_env)
	    || DICE_HAS_EXCEPTION(&_env)) {
		LOG_printf("Cannot get RGB pixel values!\n");
		return -ENODEV;
	}

	LOG_printf("l4fb:con: %dx%d@%d %dbypp, size: %d\n",
	           var->xres, var->yres, var->bits_per_pixel,
	           bytes_per_pixel, fix->smem_len);
	LOG_printf("l4fb:con %d:%d:%d %d:%d:%d linelen=%d visual=%d\n",
	           var->red.length, var->green.length, var->blue.length,
	           var->red.offset, var->green.offset, var->blue.offset,
	           fix->line_length, fix->visual);

	/* Get memory for framebuffer */
	if ((res = l4dm_mem_open(L4DM_DEFAULT_DSM, fix->smem_len,
	                         L4_PAGESIZE, 0, "L4FB Con FB", &fbds))) {
		LOG_printf("%s: Can't get l4fb memory: %s(%d)!\n",
		            __func__, l4env_errstr(res), res);
		return -ENODEV;
	}

	if ((res = l4rm_attach(&fbds, fix->smem_len + L4_PAGESIZE*10, 0, L4DM_RW,
	                       (void **)&fix->smem_start))) {
		LOG_printf("%s: Error attaching to l4fb memory: %s(%d)\n",
		           __func__, l4env_errstr(res), res);
		return -ENODEV;
	}

	/* Share dataspace with con */
	if ((res = l4dm_share(&fbds, vc_id, L4DM_RO))) {
		LOG_printf("%s: Error sharing l4fb memory: %s(%d)\n",
		           __func__, l4env_errstr(res), res);
		return -ENODEV;
	}

	if ((res = con_vc_direct_setfb_call(&vc_id, &fbds, &_env)) ||
	    DICE_HAS_EXCEPTION(&_env)) {
		LOG_printf("%s: Can't register l4fb console: %s(%d)\n",
		           __func__, l4env_errstr(res), res);
		return -ENODEV;
	}

	l4fb_create_refresher_thread(l4fb_con_update_thread, "CON refresher");

	return 0;
}

static void l4fb_con_exit(void)
{
	DICE_DECLARE_ENV(_env);
	int res;

	if (con_vc_close_call(&vc_id, &_env)
	    || DICE_HAS_EXCEPTION(&_env))
		printk("Can't close console!\n");

	if ((res = l4rm_detach((void *)l4fb_fix.smem_start)))
		LOG_printf("%s: Error detaching from l4fb memory: %s(%d)\n",
		           __func__, l4env_errstr(res), res);

	if ((res = l4dm_close(&fbds)))
		LOG_printf("%s: Error closing l4fb dataspace: %s(%d)\n",
		           __func__, l4env_errstr(res), res);
}


/*
 * We need that for X or similar where no update events are available
 * with the fbdev X driver.
 */
static void l4fb_dope_update_thread(void *data)
{
	l4x_prepare_irq_thread(current_thread_info());
	while (1) {
		if (l4fb_refresh_enabled)
			dope_cmd(dope_app_id, "l4lxvscr.refresh()");
		l4lx_sleep(l4fb_refresh_sleep);
	}
}

static unsigned long l4fb_dope_init(struct fb_var_screeninfo *var,
                                    struct fb_fix_screeninfo *fix)
{
	int bytes_per_pixel;

	LOG_printf("Starting L4FB via DOpE\n");

	if (dope_init()) {
		LOG_printf("DOpE not available!\n");
		return 0;
	}

	dope_app_id = dope_init_app(dope_window_title);
	dope_cmd(dope_app_id, "l4lxwin=new Window()");
	dope_cmd(dope_app_id, "l4lxvscr=new VScreen()");
	dope_cmdf(dope_app_id,"l4lxvscr.setmode(%d,%d,\"RGB16\")", xres, yres);
	dope_cmd(dope_app_id, "l4lxvscr.set(-grabfocus yes)");
	if (!nograb)
		dope_cmd(dope_app_id, "l4lxvscr.set(-grabmouse yes)");
	dope_cmdf(dope_app_id,"l4lxwin.set(-x %d -y %d -workw %d -workh %d -background off -content l4lxvscr)", dope_xpos, dope_ypos, xres, yres);
	dope_cmd(dope_app_id, "l4lxwin.open()");

	/* hard-coded since DOpE doesn't support anything else right now */
	var->bits_per_pixel = 16; /* also 16 for 15bpp modi */
	bytes_per_pixel     = 2;
	var->xres           = xres;
	var->yres           = yres;

	var->red.length     = 5;
	var->red.offset     = 11;
	var->green.length   = 6;
	var->green.offset   = 5;
	var->blue.length    = 5;
	var->blue.offset    = 0;

	fix->line_length    = var->xres * bytes_per_pixel;
	fix->smem_len       = var->xres * bytes_per_pixel * var->yres;
	fix->visual         = FB_VISUAL_TRUECOLOR;
	fix->smem_start     = (unsigned long)vscr_get_fb(dope_app_id, "l4lxvscr");

	l4fb_create_refresher_thread(l4fb_dope_update_thread, "DOpE refresher");

	return l4fb_dope_input_setup();
}

static void l4fb_dope_exit(void)
{
	dope_deinit_app(dope_app_id);
}

/* ============================================ */

static void l4fb_shutdown(void)
{
	/* Shut down threads so that they do not use deactived funtionality */
	if (!l4_is_invalid_id(l4fb_refresher_thread)) {
		l4lx_thread_shutdown(l4fb_refresher_thread);
		l4fb_refresher_thread = L4_INVALID_ID;
	}

	if (!l4_is_invalid_id(l4fb_input_thread)) {
		l4lx_thread_shutdown(l4fb_input_thread);
		l4fb_input_thread = L4_INVALID_ID;
	}
	/* Also do not update anything anymore */
	l4fb_update_rect = NULL;

	if (mode == MODE_DOPE)
		l4fb_dope_exit();
	else if (mode == MODE_CON)
		l4fb_con_exit();
}

static int __init l4fb_probe(struct platform_device *dev)
{
	struct fb_info *info;
	int video_cmap_len;
	int dope_avail = 0, con_avail = 0, force_use_con, force_use_dope;
	int ret = -ENOMEM;

	if (disable)
		return -ENODEV;

	/* Process module parameters */
	if (refreshsleep >= 0)
		l4fb_refresh_sleep = refreshsleep;
	if (xpos >= 0)
		dope_xpos = xpos;
	if (ypos >= 0)
		dope_ypos = ypos;
	if (*window_title)
		dope_window_title = window_title;

	/* A quick self-made check to reduce waiting times at startup */
	force_use_dope = use_dope && !use_con;
	force_use_con  = use_con  && !use_dope;

	dope_avail = force_use_dope || names_query_name("DOpE", NULL);
	con_avail  = force_use_con  || names_query_name(CON_NAMES_STR, NULL);

	if (!force_use_con
	    && (dope_avail || (!dope_avail && !con_avail))
	    && !(ret = l4fb_dope_init(&l4fb_defined, &l4fb_fix))) {
		mode = MODE_DOPE;
		l4fb_update_rect = l4fb_dope_update_rect;
	}
	else if (!force_use_dope
	         && (con_avail || (!dope_avail && !con_avail))
		 && !(ret = l4fb_con_init(&l4fb_defined, &l4fb_fix))) {
		mode = MODE_CON;
		l4fb_update_rect = l4fb_con_update_rect;
	} else
		return ret;

	info = framebuffer_alloc(0, &dev->dev);
	if (!info)
		goto failed_framebuffer_alloc;

	info->screen_base = (void *)l4fb_fix.smem_start;
	if (!info->screen_base) {
		printk(KERN_ERR "l4fb: abort, graphic system could not be initialized.\n");
		ret = -EIO;
		goto failed_after_framebuffer_alloc;
	}

	printk(KERN_INFO "l4fb: %s framebuffer at 0x%p, size %dk\n",
	       mode == MODE_CON ? "Con" : "DOpE", info->screen_base,
	       l4fb_fix.smem_len >> 10);
	printk(KERN_INFO "l4fb: mode is %dx%dx%d, linelength=%d, pages=%d\n",
	       l4fb_defined.xres, l4fb_defined.yres, l4fb_defined.bits_per_pixel, l4fb_fix.line_length, screen_info.pages);

	l4fb_defined.xres_virtual = l4fb_defined.xres;
	l4fb_defined.yres_virtual = l4fb_defined.yres;

	/* some dummy values for timing to make fbset happy */
	l4fb_defined.pixclock     = 10000000 / l4fb_defined.xres * 1000 / l4fb_defined.yres;
	l4fb_defined.left_margin  = (l4fb_defined.xres / 8) & 0xf8;
	l4fb_defined.hsync_len    = (l4fb_defined.xres / 8) & 0xf8;

	l4fb_defined.transp.length = 0;
	l4fb_defined.transp.offset = 0;

	printk(KERN_INFO "l4fb: directcolor: "
	       "size=%d:%d:%d:%d, shift=%d:%d:%d:%d\n",
	       0,
	       l4fb_defined.red.length,
	       l4fb_defined.green.length,
	       l4fb_defined.blue.length,
	       0,
	       l4fb_defined.red.offset,
	       l4fb_defined.green.offset,
	       l4fb_defined.blue.offset);
	video_cmap_len = 16;

	l4fb_fix.ypanstep  = 0;
	l4fb_fix.ywrapstep = 0;

	info->fbops = &l4fb_ops;
	info->var   = l4fb_defined;
	info->fix   = l4fb_fix;
	info->pseudo_palette = pseudo_palette;
	info->flags = FBINFO_FLAG_DEFAULT;

	ret = fb_alloc_cmap(&info->cmap, video_cmap_len, 0);
	if (ret < 0)
		goto failed_after_framebuffer_alloc;

	if (register_framebuffer(info) < 0) {
		ret = -EINVAL;
		goto failed_after_fb_alloc_cmap;
	}
	dev_set_drvdata(&dev->dev, info);

	atexit(l4fb_shutdown);

	printk(KERN_INFO "l4fb%d: %s L4 frame buffer device (refresh: %ums)\n",
	       info->node, info->fix.id, l4fb_refresh_sleep);

	return 0;

failed_after_fb_alloc_cmap:
	fb_dealloc_cmap(&info->cmap);

failed_after_framebuffer_alloc:
	framebuffer_release(info);

failed_framebuffer_alloc:
	// deinit_{con,dope}
	return ret;
}

static int l4fb_remove(struct platform_device *device)
{
	struct fb_info *info = platform_get_drvdata(device);

	if (info) {
		unregister_framebuffer(info);
		framebuffer_release(info);
	}
	return 0;
}

static struct platform_driver l4fb_driver = {
	.probe   = l4fb_probe,
	.remove  = l4fb_remove,
	.driver  = {
		.name = "l4fb",
	},
};

static struct platform_device l4fb_device = {
	.name = "l4fb",
};

static int __init l4fb_init(void)
{
	int ret;
	char *option = NULL;

	/* Parse option string */
	fb_get_options("l4fb", &option);
	l4fb_setup(option);

	ret = platform_driver_register(&l4fb_driver);
	if (!ret) {
		ret = platform_device_register(&l4fb_device);
		if (ret)
			platform_driver_unregister(&l4fb_driver);
	}
	return ret;
}
module_init(l4fb_init);

static void __exit l4fb_exit(void)
{
	l4fb_shutdown();

	platform_device_unregister(&l4fb_device);
	platform_driver_unregister(&l4fb_driver);
}
module_exit(l4fb_exit);

MODULE_AUTHOR("Adam Lackorzynski <adam@os.inf.tu-dresden.de>");
MODULE_DESCRIPTION("Frame buffer driver for L4 con and DOpE");
MODULE_LICENSE("GPL");


module_param(refreshsleep, int, 0);
MODULE_PARM_DESC(refreshsleep, "Sleep between frame buffer refreshs in ms");
module_param(xpos, int, 0);
MODULE_PARM_DESC(xpos, "X position of the DOpE window");
module_param(ypos, int, 0);
MODULE_PARM_DESC(ypos, "Y position of the DOpE window");
module_param_string(title, window_title, sizeof(window_title), 0);
MODULE_PARM_DESC(title, "Title of the DOpE window");
module_param(xres, uint, 0);
MODULE_PARM_DESC(xres, "Width of DOpE window in pixels");
module_param(yres, uint, 0);
MODULE_PARM_DESC(yres, "Height of DOpE window in pixels");
module_param(depth, uint, 0);
MODULE_PARM_DESC(depth, "Color depth");
module_param(nograb, uint, 0);
MODULE_PARM_DESC(nograb, "Do not grab window focus with mouse (DOpE only)");
module_param(disable, bool, 0);
MODULE_PARM_DESC(disable, "Disable driver");
module_param(use_dope, bool, 0);
MODULE_PARM_DESC(use_dope, "Use DOpE only");
module_param(use_con, bool, 0);
MODULE_PARM_DESC(use_con, "Use l4con only");
