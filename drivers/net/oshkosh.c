/*
 * Oshkosh network driver stub.
 *
 * Based on the oshkosh network driver for Linux-2.2 by
 *   Jork Loeser <jork@os.inf.tu-dresden.de>
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <l4/dsi/dsi.h>
#include <l4/oshkosh/beapi.h>
#include <l4/semaphore/semaphore.h>
#include <l4/env/errno.h>

#include <asm/generic/setup.h>
#include <asm/generic/do_irq.h>
#include <asm/l4lxapi/irq.h>
#include <asm/l4lxapi/misc.h>
#include <asm/l4lxapi/thread.h>

MODULE_AUTHOR("Adam Lackorzynski <adam@os.inf.tu-dresden.de>");
MODULE_DESCRIPTION("Oshkosh stub driver");
MODULE_LICENSE("GPL");

static const char *oshkosh_devname = "eth0";

enum {
	RX_RING_SIZE = 31,
	TX_RING_SIZE = 32,
};

struct oshkosh_priv {
	struct net_device          *netdev;
	struct net_device_stats    net_stats;
	oshk_nic_stats_t           oshk_stats;

	oshk_client_conn_t         *conn;
	int                        rcvd_packets;
	struct sk_buff             *rx_ring[RX_RING_SIZE];
	struct oshk_client_be_rx_t rx_desc_ring[RX_RING_SIZE];
	struct sk_buff             *tx_ring[TX_RING_SIZE];
	struct oshk_client_tx_t    tx_desc_ring[TX_RING_SIZE];
	int                        tx_tail;
	int                        tx_head;

	l4semaphore_t              lock;       /* lock for rx/tx rings */
	l4_threadid_t              irq_thread;
	atomic_t                   snd_outstanding; /* number of packets in send state */
	struct hw_interrupt_type   *previous_interrupt_type;
};

static struct net_device *oshkosh_netdev;

/*
 * Send a packet to OshKosh.
 *
 * Do not call this function in parallel.
 */
static inline int oshkosh_send_packet(struct sk_buff *skb, struct net_device *netdev)
{
	struct oshkosh_priv *priv = netdev_priv(netdev);
	int nhead;

	atomic_inc(&priv->snd_outstanding);
	nhead = priv->tx_head + 1;
	if (nhead == TX_RING_SIZE)
		nhead = 0;
	if (nhead == priv->tx_tail)
		return 1;

	priv->tx_ring[priv->tx_head]           = skb;
	priv->tx_desc_ring[priv->tx_head].addr = skb->data;
	priv->tx_desc_ring[priv->tx_head].len  = skb->len;

	if (oshk_client_be_put_tx_desc(priv->conn,
	                               priv->tx_desc_ring + priv->tx_head)) {
		atomic_dec(&priv->snd_outstanding);
		return 1;
	}

	priv->tx_head = nhead;

	return 0;
}

static int oshkosh_xmit_frame(struct sk_buff *skb, struct net_device *netdev)
{
	struct oshkosh_priv *priv = netdev_priv(netdev);

	oshkosh_send_packet(skb, netdev);

	priv->net_stats.tx_packets++;
	priv->net_stats.tx_bytes += skb->len;
	netdev->trans_start = jiffies;

	return 0;
}

static struct net_device_stats *oshkosh_get_stats(struct net_device *netdev)
{
	struct oshkosh_priv *priv = netdev_priv(netdev);

	if (netif_running(netdev)) {
		int err;

		err = oshk_nic_get_stats(netdev->name, 0,
		                         oshk_client_get_rx_id(priv->conn),
		                         &priv->oshk_stats);
		if (err == 0) {
			priv->oshk_stats.dev.tx_dropped += priv->net_stats.tx_dropped;
			/* local rx_dropped is never set */
			return (struct net_device_stats *)&priv->oshk_stats.dev;
		}
	}

	return &priv->net_stats;
}

static void oshkosh_tx_timeout(struct net_device *netdev)
{
	printk("%s\n", __func__);
}

static inline void oshkosh_fill_rx_ring(struct net_device *netdev,
                                        int gfp_mask)
{
	struct oshkosh_priv *priv = netdev_priv(netdev);
	struct sk_buff **skbs;
	struct oshk_client_be_rx_t *rxs;
	int i;

	skbs = priv->rx_ring;
	rxs  = priv->rx_desc_ring;
	for (i = 0; i < RX_RING_SIZE; i++) {
		if (skbs[i] == 0) {
			skbs[i] = alloc_skb(ETH_FRAME_LEN + 2, gfp_mask);
			if (skbs[i] == 0) {
				printk("%s: Cannot alloc skb.\n", netdev->name);
				return;
			}
			skbs[i]->dev = netdev;
			rxs[i].addr = skbs[i]->data;
		}
	}
}

static inline void oshkosh_process_rx_ring(struct net_device *netdev, int count)
{
	struct oshkosh_priv *priv = netdev_priv(netdev);
	int i, j;

	for (i = j = 0; j < count && i < RX_RING_SIZE; i++) {
		struct sk_buff *skb = priv->rx_ring[i];

		if (skb && priv->rx_desc_ring[i].len) {
			skb_put(skb, priv->rx_desc_ring[i].len);
			skb->protocol = eth_type_trans(skb, netdev);

			priv->net_stats.rx_packets++;
			priv->net_stats.rx_bytes += skb->len;
			netif_rx(skb);
			priv->rx_ring[i] = 0;
			j++;
		}
	}
}

static inline int oshkosh_process_tx_ring(struct net_device *netdev)
{
	struct oshkosh_priv *priv = netdev_priv(netdev);
	int count = 0;

	while (priv->tx_tail != priv->tx_head) {
		if (oshk_client_check_tx(priv->conn,
		                         &priv->tx_desc_ring[priv->tx_tail]) == 0) {
			/* Element was sent */
			dev_kfree_skb_any(priv->tx_ring[priv->tx_tail]);
			atomic_dec(&priv->snd_outstanding);
			priv->tx_ring[priv->tx_tail] = 0;
			if (++priv->tx_tail == TX_RING_SIZE)
				priv->tx_tail = 0;
			count++;
		} else
			break;
	}

	return count;
}

/*
 * Interrupt.
 */
static irqreturn_t oshkosh_interrupt(int irq, void *dev_id)
{
	struct net_device *netdev = dev_id;
	struct oshkosh_priv *priv = netdev->priv;

	l4semaphore_down(&priv->lock);

	if (priv->rcvd_packets)
		oshkosh_process_rx_ring(netdev, priv->rcvd_packets);

	oshkosh_process_tx_ring(netdev);

	oshkosh_fill_rx_ring(netdev, GFP_ATOMIC);
	
	l4semaphore_up(&priv->lock);

	return IRQ_HANDLED;
}

/*
 * Receive thread to get packets from oshkosh
 */
static void oshkosh_irq_thread(void *data)
{
	struct net_device *netdev = *(struct net_device **)data;
	struct oshkosh_priv *priv = netdev_priv(netdev);
	struct thread_info *ctx = current_thread_info();
	int ret;

	l4x_prepare_irq_thread(ctx);

	l4semaphore_down(&priv->lock);
	oshkosh_fill_rx_ring(netdev, GFP_KERNEL);
	l4semaphore_up(&priv->lock);

	while (1) {
		ret = oshk_client_be_waitv(priv->conn, 1, 1, RX_RING_SIZE,
		                           priv->rx_desc_ring, -1, 10000);
		/* printk("New interrupt (%d)\n", ret); */
		if (unlikely(ret < 0)) {
			printk("%s: oshk_client_waitv failed: %s(%d)\n",
			       netdev->name, l4env_strerror(-ret), ret);
			break;
		}
		priv->rcvd_packets = ret;
		l4x_do_IRQ(netdev->irq, ctx);
	}
}

/* ----- */
static unsigned int oshkosh_irq_startup(unsigned int irq)
{
	return 1;
}

static void oshkosh_irq_dummy_void(unsigned int irq)
{
}

struct hw_interrupt_type oshkosh_irq_type = {
	.typename	= "Oshkosh IRQ",
	.startup	= oshkosh_irq_startup,
	.shutdown	= oshkosh_irq_dummy_void,
	.enable		= oshkosh_irq_dummy_void,
	.disable	= oshkosh_irq_dummy_void,
	.ack		= oshkosh_irq_dummy_void,
	.end		= oshkosh_irq_dummy_void,
};
/* ----- */

static int oshkosh_open(struct net_device *netdev)
{
	struct oshkosh_priv *priv = netdev_priv(netdev);
	int err;

	priv->lock   = L4SEMAPHORE_UNLOCKED;

	netif_carrier_off(netdev);

	if ((err = oshk_client_be_open(netdev->name, netdev->dev_addr,
	                               0, &priv->conn, 0))) {
		printk("%s: oshk_client_be_open failed: %s(%d)\n",
		       netdev->name, l4env_strerror(-err), err);
		err = -EBUSY;
		goto err_out_return;
	}

	printk("%s: Overwriting IRQ type for IRQ %d with oshkosh type!\n",
	       netdev->name, netdev->irq);

	priv->previous_interrupt_type = irq_desc[netdev->irq].chip;

	if (netdev->irq < NR_IRQS)
		irq_desc[netdev->irq].chip = &oshkosh_irq_type;
	else {
		printk("%s: irq(%d) > NR_IRQS(%d), failing\n",
		       netdev->name, netdev->irq, NR_IRQS);
		goto err_out_close;
	}

	if ((err = request_irq(netdev->irq, oshkosh_interrupt,
	                       SA_SAMPLE_RANDOM, netdev->name,
	                       netdev))) {
		printk("%s: request_irq(%d, ...) failed.\n",
		       netdev->name, netdev->irq);
		goto err_out_close;
	}

	priv->irq_thread = l4lx_thread_create(oshkosh_irq_thread,
	                                      NULL,
	                                      &netdev, sizeof(netdev),
	                                      -1, "OshkoshRcv");
	if (l4_is_invalid_id(priv->irq_thread)) {
		printk("%s: Cannot create thread\n", netdev->name);
		err = -EBUSY;
		goto err_out_free_irq;
	}

	netif_wake_queue(netdev);

	printk("%s: interface up.\n", netdev->name);

	return 0;

err_out_free_irq:
	free_irq(netdev->irq, netdev);

err_out_close:
	irq_desc[netdev->irq].chip = priv->previous_interrupt_type;
	oshk_client_be_close(priv->conn, 0);

err_out_return:
	priv->conn = NULL;
	return err;
}

static int oshkosh_close(struct net_device *netdev)
{
	struct oshkosh_priv *priv = netdev_priv(netdev);

	l4semaphore_down(&priv->lock);
	l4lx_thread_shutdown(priv->irq_thread);
	priv->irq_thread = L4_INVALID_ID;

	free_irq(netdev->irq, netdev);
	irq_desc[netdev->irq].chip = priv->previous_interrupt_type;
	netif_stop_queue(netdev);
	netif_carrier_off(netdev);


	oshkosh_process_rx_ring(netdev, RX_RING_SIZE);
	if (atomic_read(&priv->snd_outstanding))
		printk("%s: Dropping unsent packages...\n", netdev->name);

	oshk_client_be_close(priv->conn, 0);
	priv->conn = 0;

	printk("client conn gone\n");

	return 0;
}

static int __init oshkosh_init(void)
{
	struct oshkosh_priv *priv;
	int err;

	dsi_init();
	dsi_set_sync_thread_prio(0xa2);

	if (!(oshkosh_netdev = alloc_etherdev(sizeof(struct oshkosh_priv))))
		return -ENOMEM;

	oshkosh_netdev->open            = oshkosh_open;
	oshkosh_netdev->stop            = oshkosh_close;
	oshkosh_netdev->hard_start_xmit = oshkosh_xmit_frame;
	oshkosh_netdev->get_stats       = oshkosh_get_stats;
	oshkosh_netdev->tx_timeout      = oshkosh_tx_timeout;

	priv = netdev_priv(oshkosh_netdev);
	priv->netdev = oshkosh_netdev;

	if (oshk_nic_be_new(oshkosh_devname, oshkosh_netdev->dev_addr,
	                    &oshkosh_netdev->irq, &oshkosh_netdev->mtu)) {
		printk("oshkosh: Cannot contact Oshkosh server \n");
		err = -ENODEV;
		goto err_out_free_dev;
	}

	if ((err = register_netdev(oshkosh_netdev))) {
		printk("oshkosh: Cannot register net device, aborting.\n");
		goto err_out_free_dev;
	}

	printk(KERN_INFO "%s: Oshkosh card found with "
			 "%02X:%02X:%02X:%02X:%02X:%02X\n",
			 oshkosh_netdev->name,
	                 oshkosh_netdev->dev_addr[0], oshkosh_netdev->dev_addr[1],
			 oshkosh_netdev->dev_addr[2], oshkosh_netdev->dev_addr[3],
			 oshkosh_netdev->dev_addr[4], oshkosh_netdev->dev_addr[5]);

	return 0;

err_out_free_dev:
	free_netdev(oshkosh_netdev);
	
	return err;
}

static void __exit oshkosh_exit(void)
{
	unregister_netdev(oshkosh_netdev);
	free_netdev(oshkosh_netdev);
}

module_init(oshkosh_init);
module_exit(oshkosh_exit);
