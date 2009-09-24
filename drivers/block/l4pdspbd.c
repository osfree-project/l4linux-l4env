/*
 * Block driver working on a dataspace.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/blkdev.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/hdreg.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include <asm/api/macros.h>

#include <asm/generic/l4lib.h>
#include <l4/sys/types.h>
#include <l4/sys/syscalls.h>
#include <l4/names/libnames.h>
#include <l4/dm_mem/dm_mem.h>
#include <l4/env/errno.h>

#include <l4/pers_dsp/pers_dsp.h>

MODULE_AUTHOR("Adam Lackorzynski <adam@os.inf.tu-dresden.de");
MODULE_DESCRIPTION("Block driver working on persistent dataspaces");
MODULE_LICENSE("GPL");

L4_EXTERNAL_FUNC(l4pdsp_open);
L4_EXTERNAL_FUNC(l4pdsp_close);

static char name[32];
module_param_string(name, name, sizeof(name), 0);
MODULE_PARM_DESC(name, "L4 PSD name to use (mandatory to enable driver)");

static int major_num = 0;        /* kernel chooses */
module_param(major_num, int, 0);

#define KERNEL_SECTOR_SIZE 512

static void *buffer_addr;

/*
 * Our request queue.
 */
static struct request_queue *queue;

/*
 * The internal representation of our device.
 */
static struct l4pdspbd_device {
	unsigned long size; /* Size in Kbytes */
	spinlock_t lock;
	u8 *data;
	struct gendisk *gd;
} device;


static void transfer(struct l4pdspbd_device *dev, unsigned long sector_start,
                     unsigned long sector_count, char *buffer, int write)
{
	unsigned long byte_start = sector_start * KERNEL_SECTOR_SIZE;
	unsigned long byte_count = sector_count * KERNEL_SECTOR_SIZE;

	if (((byte_start + byte_count) >> 10) > dev->size) {
		printk(KERN_NOTICE "l4pdspbd: access beyond end of device (%ld %ld)\n",
		       byte_start, byte_count);
		return;
	}

	if (write)
		memcpy(buffer_addr + byte_start, buffer, byte_count);
	else
		memcpy(buffer, buffer_addr + byte_start, byte_count);
}

static void request(struct request_queue *q)
{
	struct request *req;

	while ((req = blk_peek_request(q)) != NULL) {
		if (!blk_fs_request(req)) {
			printk (KERN_NOTICE "Skip non-CMD request\n");
			blk_end_request_all(req, -EIO);
			continue;
		}
		transfer(&device, blk_rq_pos(req),
		         blk_rq_cur_sectors(req),
		         req->buffer, rq_data_dir(req));
		blk_end_request_all(req, 0);
	}
}



static int getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	geo->cylinders = device.size << 5;
	geo->heads     = 4;
	geo->sectors   = 32;
	return 0;
}


/*
 * The device operations structure.
 */
static struct block_device_operations ops = {
	.owner  = THIS_MODULE,
	.getgeo = getgeo,
};

static int __init l4pdspbd_init(void)
{
	long ret;
	unsigned long size;

	if (!name[0]) {
		printk("l4pdspbd: No name given, not starting.\n");
		return 0;
	}

	if ((ret = l4pdsp_open(name, &buffer_addr, &size))) {
		printk("l4pdspbd: failed to open DS %s: %s (%ld)\n",
		       name, l4env_errstr(ret), ret);
		return -ENODEV;
	}

	printk("l4pdspbd: Found DS \'%s\'.\n", name);

	/* get number of disks */
	ret = -ENODEV;

	device.size = size >> 10; /* device.size is unsigned and in KBytes */

	printk("l4pdspbd: Disk size = %lu KB (%lu MB)\n",
	       device.size, device.size >> 10);

	spin_lock_init(&device.lock);
	device.data = NULL;

	/* Get a request queue. */
	queue = blk_init_queue(request, &device.lock);
	if (queue == NULL)
		goto out1;

	/* Register device */
	major_num = register_blkdev(major_num, "l4pdspbd");
	if (major_num <= 0) {
		printk(KERN_WARNING "l4pdspbd: unable to get major number\n");
		goto out2;
	}

	/* gendisk structure. */
	device.gd = alloc_disk(16);
	if (!device.gd)
		goto out3;
	device.gd->major        = major_num;
	device.gd->first_minor  = 0;
	device.gd->fops         = &ops;
	device.gd->private_data = &device;
	strcpy(device.gd->disk_name, "l4pdspbd0");
	set_capacity(device.gd, device.size * 2 /* 2 * kb = 512b-sectors */);
	device.gd->queue = queue;
	add_disk(device.gd);

	return 0;

out3:
	unregister_blkdev(major_num, "l4pdspbd");
out2:
	blk_cleanup_queue(queue);
out1:
	/* close L4 block driver instance */
	l4pdsp_close(name);

	return ret;
}

static void __exit l4pdspbd_exit(void)
{
	del_gendisk(device.gd);
	put_disk(device.gd);
	unregister_blkdev(major_num, "l4pdspbd0");
	blk_cleanup_queue(queue);

	l4pdsp_close(name);
}

module_init(l4pdspbd_init);
module_exit(l4pdspbd_exit);
