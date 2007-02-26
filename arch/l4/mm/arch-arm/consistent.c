
#include <l4/sys/kdebug.h>

#include <linux/device.h>
#include <linux/dma-mapping.h>

void *
dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *handle, gfp_t gfp)
{
	int order = get_order(size);
	void *ret;

	if (dev) {
		enter_kdebug("dev != 0 not there yet");
		return NULL;
	}

	gfp |= GFP_DMA;

	ret = (void *)__get_free_pages(gfp, order);

	if (ret) {
		memset(ret, 0, size);
		*handle = virt_to_phys(ret);
	}

	return ret;
}

void dma_free_coherent(struct device *dev, size_t size, void *cpu_addr, dma_addr_t handle)
{
	enter_kdebug("dma_free_coherent");
}
