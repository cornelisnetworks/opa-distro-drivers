// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 *
 * Copyright(c) 2017 Intel Corporation.
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * BSD LICENSE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  - Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  - Neither the name of Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <linux/kref.h>
#include <linux/overflow.h>

#include <nvidia/nv-p2p.h>

#include "device.h"
#include "user_exp_rcv.h"
#include "pinning.h"

#define NV_GPU_PAGE_SHIFT 16
#define NV_GPU_PAGE_SIZE BIT(NV_GPU_PAGE_SHIFT)
#define NV_GPU_PAGE_MASK (~(NV_GPU_PAGE_SIZE - 1))

#define GPU_PAGE_TO_PFN(page) ((page)->physical_address >> NV_GPU_PAGE_SHIFT)

static struct nvidia_rdma_interface {
	int (*free_page_table)(struct nvidia_p2p_page_table *page_table);
	int (*free_dma_mapping)(struct nvidia_p2p_dma_mapping *dma_mapping);
	int (*dma_map_pages)(struct pci_dev *peer, struct nvidia_p2p_page_table *page_table,
			     struct nvidia_p2p_dma_mapping **dma_mapping);
	int (*dma_unmap_pages)(struct pci_dev *peer, struct nvidia_p2p_page_table *page_table,
			       struct nvidia_p2p_dma_mapping *dma_mapping);
	int (*put_pages)(u64 p2p_token, u32 va_space, u64 virtual_address,
			 struct nvidia_p2p_page_table *page_table);
	int (*get_pages)(u64 p2p_token, u32 va_space, u64 virtual_address, u64 length,
			 struct nvidia_p2p_page_table **page_table,
			 void (*free_callback)(void *), void *data);
} rdma_interface = { 0 };

struct nvidia_tid_user_buf {
	struct tid_user_buf common;
	struct hfi1_filedata *fd;
	struct nvidia_p2p_page_table *pages;
	struct nvidia_p2p_dma_mapping *mapping;
	bool invalidated;
	bool destroyed;
	struct kref ref;
	/* list of nodes to notify when CUDA memory range is invalidated */
	struct list_head nodes;
	/* Protects .nodes and .invalidated */
	spinlock_t nodes_lock;
};

/*
 * Individual nodes do not store page info on them; they share page, DMA data
 * in the nvidia_tid_user_buf.
 */
struct nvidia_tid_node {
	struct tid_rb_node common;
	struct list_head list;
	struct nvidia_tid_user_buf *userbuf;
	unsigned int pageidx;
};

static void nvidia_user_buf_kref_cb(struct kref *ref);

static int nvidia_node_register_notify(struct tid_rb_node *node)
{
	/* No-op; individual nvidia_tid_nodes do not have notifier registrations. */
	return 0;
}

static void nvidia_node_unregister_notify(struct tid_rb_node *node)
{
	struct nvidia_tid_node *nvnode =
		container_of(node, struct nvidia_tid_node, common);

	spin_lock(&nvnode->userbuf->nodes_lock);
	list_del(&nvnode->list);
	spin_unlock(&nvnode->userbuf->nodes_lock);
}

static void nvidia_node_dma_unmap(struct tid_rb_node *node)
{
	/* No-op; NVIDIA doesn't support unmapping single pages in mapped-memory range. */
}

static void nvidia_node_unpin_pages(struct hfi1_filedata *fd,
				    struct tid_rb_node *node)
{
	/* No-op; NVIDIA doesn't support unpinning single pages in mapped-memory range. */
}

/*
 * Get page-size shift based on @pages. Page size is 1<<(page-size shift).
 *
 * Any page-size shift < EXPECTED_ADDR_SHIFT won't work with the implementation
 * and is considered an error.
 *
 * @return non-zero page-size shift on success, 0 on error.
 */
static unsigned int nvidia_pgt_shift(const struct nvidia_p2p_page_table *pages)
{
	switch (pages->page_size) {
	case NVIDIA_P2P_PAGE_SIZE_4KB:
		return 12;
	case NVIDIA_P2P_PAGE_SIZE_64KB:
		return 16;
	case NVIDIA_P2P_PAGE_SIZE_128KB:
		return 17;
	}
	return 0;
}

static struct tid_node_ops nvidia_nodeops;

static int nvidia_node_init(struct hfi1_filedata *fd,
			    struct tid_user_buf *tbuf,
			    u32 rcventry,
			    struct tid_group *grp,
			    u16 pageidx,
			    unsigned int npages,
			    struct tid_rb_node **node)
{
	struct nvidia_tid_user_buf *nvbuf =
		container_of(tbuf, struct nvidia_tid_user_buf, common);
	struct nvidia_tid_node *nvnode;
	unsigned int page_shift;
	u32 pgsz;
	int ret = 0;

	/* As long as fd is passed in separately, sanity-check */
	if (nvbuf->fd != fd)
		return -EINVAL;
	if (!nvbuf->pages || !nvbuf->mapping)
		return -EINVAL;
	if (pageidx > nvbuf->pages->entries ||
	    (pageidx + npages) > nvbuf->pages->entries)
		return -EINVAL;

	page_shift = nvidia_pgt_shift(nvbuf->pages);
	/* Only 64KiB pages supported right now */
	if (page_shift != NV_GPU_PAGE_SHIFT)
		return -EIO;
	pgsz = 1 << page_shift;

	spin_lock(&nvbuf->nodes_lock);
	if (nvbuf->invalidated) {
		ret = -EFAULT;
		goto unlock;
	}
	nvnode = kzalloc(sizeof(*nvnode), GFP_KERNEL);
	if (!nvnode) {
		ret = -ENOMEM;
		goto unlock;
	}
	*node = &nvnode->common;

	kref_get(&nvbuf->ref);
	nvnode->userbuf = nvbuf;

	mutex_init(&nvnode->common.invalidate_mutex);
	nvnode->common.fdata = fd;
	nvnode->common.grp = grp;
	nvnode->common.ops = &nvidia_nodeops;
	nvnode->common.rcventry = rcventry;
	nvnode->pageidx = pageidx;
	nvnode->common.npages = npages;
	nvnode->common.page_shift = page_shift;
	nvnode->common.phys = nvbuf->pages->pages[pageidx]->physical_address;
	nvnode->common.dma_addr = nvbuf->mapping->dma_addresses[pageidx];
	nvnode->common.vaddr = tbuf->vaddr + (pageidx * pgsz);
	nvnode->common.use_mn = nvbuf->common.use_mn;
	nvnode->common.type = HFI1_MEMINFO_TYPE_NVIDIA;

	list_add_tail(&nvnode->list, &nvbuf->nodes);
unlock:
	spin_unlock(&nvbuf->nodes_lock);
	return ret;
}

static void nvidia_node_free(struct tid_rb_node *node)
{
	struct nvidia_tid_node *nvnode =
		container_of(node, struct nvidia_tid_node, common);

	kref_put(&nvnode->userbuf->ref, nvidia_user_buf_kref_cb);
	kfree(nvnode);
}

static struct tid_node_ops nvidia_nodeops = {
	.init = nvidia_node_init,
	.free = nvidia_node_free,
	.register_notify = nvidia_node_register_notify,
	.unregister_notify = nvidia_node_unregister_notify,
	.dma_unmap = nvidia_node_dma_unmap,
	.unpin_pages = nvidia_node_unpin_pages,
};

static unsigned int nvidia_page_size(struct tid_user_buf *tbuf)
{
	struct nvidia_tid_user_buf *nvbuf =
		container_of(tbuf, struct nvidia_tid_user_buf, common);

	return 1 << nvidia_pgt_shift(nvbuf->pages);
}

static struct tid_user_buf_ops nvidia_bufops;

static int nvidia_user_buf_init(u16 expected_count,
				bool notify,
				unsigned long vaddr,
				unsigned long length,
				struct tid_user_buf **tbuf)
{
	struct nvidia_tid_user_buf *nvbuf;
	int ret;

	/* nv-p2p.h nvidia_p2p_get_pages() says vaddr, length must be 64KiB aligned, multiple */
	if (vaddr % NV_GPU_PAGE_SIZE)
		return -EINVAL;
	if (length % NV_GPU_PAGE_SIZE)
		return -EINVAL;

	nvbuf = kzalloc(sizeof(*nvbuf), GFP_KERNEL);
	if (!nvbuf)
		return -ENOMEM;
	kref_init(&nvbuf->ref);
	*tbuf = &nvbuf->common;
	/* Cannot check vaddr alignment here; store for now. */
	nvbuf->common.vaddr = vaddr;
	nvbuf->common.length = length;
	nvbuf->common.use_mn = notify;
	nvbuf->common.psets = kcalloc(expected_count, sizeof(*nvbuf->common.psets),
				      GFP_KERNEL);
	if (!nvbuf->common.psets) {
		ret = -ENOMEM;
		goto fail_release_mem;
	}
	nvbuf->common.ops = &nvidia_bufops;
	nvbuf->common.type = HFI1_MEMINFO_TYPE_NVIDIA;
	INIT_LIST_HEAD(&nvbuf->nodes);
	spin_lock_init(&nvbuf->nodes_lock);
	return 0;
fail_release_mem:
	// No need to do kref_put here, just kfree()
	kfree(nvbuf);
	return ret;
}

/*
 * Destructor.
 *
 * Locking in nvidia guarantees that nvidia_p2p_dma_unmap_pages() and
 * nvidia_p2p_put_pages() won't return before the invalidation callback has
 * returned if the former are called during the latter.
 */
static void nvidia_user_buf_kref_cb(struct kref *ref)
{
	struct nvidia_tid_user_buf *nvbuf =
		container_of(ref, struct nvidia_tid_user_buf, ref);

	spin_lock(&nvbuf->nodes_lock);
	/* Putting back final ref, there should be no nodes left */
	WARN_ON(!list_empty(&nvbuf->nodes));
	nvbuf->destroyed = true;
	spin_unlock(&nvbuf->nodes_lock);

	if (nvbuf->fd && nvbuf->mapping)
		WARN_ON(rdma_interface.dma_unmap_pages(nvbuf->fd->dd->pcidev, nvbuf->pages,
						       nvbuf->mapping));
	/*
	 * Even if nvidia locking prevents dma_unmap_pages() from returning
	 * before invalidate_cb() completes, not guaranteed that
	 * nvbuf->pages=NULL will be visible to this CPU.
	 */
	if (nvbuf->pages)
		WARN_ON(rdma_interface.put_pages(0, 0, nvbuf->common.vaddr, nvbuf->pages));
	kfree(nvbuf->common.psets);
	kfree(nvbuf);
}

static void nvidia_user_buf_free(struct tid_user_buf *tbuf)
{
	struct nvidia_tid_user_buf *nvbuf =
		container_of(tbuf, struct nvidia_tid_user_buf, common);

	kref_put(&nvbuf->ref, nvidia_user_buf_kref_cb);
}

static void nvidia_invalidate_cb(void *ctxt)
{
	struct nvidia_tid_user_buf *nvbuf = ctxt;
	struct nvidia_tid_node *n;

	/*
	 * nvidia internal locking guarantees that if this function was called,
	 * nvidia_user_buf_kref_cb() could not have gotten past
	 * rdma_interface.put_pages(). I.e. kfree(nvbuf) could not have
	 * occurred yet and *nvbuf is still valid.
	 */
	spin_lock(&nvbuf->nodes_lock);
	/* Prevent any new TID nodes being created against this memory */
	nvbuf->invalidated = true;
	/* Destructor entered; return so nvidia locking will release and destructor can return. */
	if (nvbuf->destroyed) {
		/* All nvidia_tid_node should do list_del() before kref_put(). */
		WARN_ON(!list_empty(&nvbuf->nodes));
		goto unlock;
	}

	list_for_each_entry(n, &nvbuf->nodes, list)
		hfi1_user_exp_rcv_invalidate(&n->common);

	WARN_ON(rdma_interface.free_dma_mapping(nvbuf->mapping));
	WARN_ON(rdma_interface.free_page_table(nvbuf->pages));
	nvbuf->mapping = NULL;
	nvbuf->pages = NULL;
unlock:
	spin_unlock(&nvbuf->nodes_lock);
}

static int nvidia_pin_pages(struct hfi1_filedata *fd,
			    struct tid_user_buf *tbuf)
{
	struct nvidia_tid_user_buf *nvbuf =
		container_of(tbuf, struct nvidia_tid_user_buf, common);
	int ret;

	nvbuf->fd = fd;
	ret = rdma_interface.get_pages(0, 0, nvbuf->common.vaddr,
				       nvbuf->common.length, &nvbuf->pages,
				       nvidia_invalidate_cb, nvbuf);
	/* Don't WARN on these cases */
	if (ret == -EINVAL || ret == -ENOMEM)
		return ret;
	if (WARN_ON(ret))
		return ret;
	if (WARN_ON(!NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE(nvbuf->pages))) {
		ret = -EIO;
		goto fail_put_pages;
	}

	if (nvbuf->pages->entries > fd->uctxt->expected_count) {
		ret = -EINVAL;
		goto fail_put_pages;
	}

	ret = rdma_interface.dma_map_pages(fd->dd->pcidev, nvbuf->pages, &nvbuf->mapping);
	if (WARN_ON(ret))
		goto fail_put_pages;
	if (WARN_ON(!NVIDIA_P2P_DMA_MAPPING_VERSION_COMPATIBLE(nvbuf->mapping))) {
		ret = -EIO;
		goto fail_unmap;
	}

	return nvbuf->pages->entries;

fail_unmap:
	WARN_ON(rdma_interface.dma_unmap_pages(fd->dd->pcidev, nvbuf->pages, nvbuf->mapping));
	nvbuf->mapping = NULL;
fail_put_pages:
	WARN_ON(rdma_interface.put_pages(0, 0, nvbuf->common.vaddr, nvbuf->pages));
	nvbuf->pages = NULL;
	return ret;
}

static void nvidia_unpin_pages(struct hfi1_filedata *fd,
			       struct tid_user_buf *tbuf,
			       unsigned int pageidx,
			       unsigned int npages)
{
	/*
	 * No-op; NVIDIA doesn't support partial-unpinning.
	 * Pages will be unmapped and unpinned when last ref to
	 * nvidia_tid_user_buf is released.
	 */
}

static int nvidia_find_phys_blocks(struct tid_user_buf *tbuf,
				   unsigned int npages)
{
	struct nvidia_tid_user_buf *nvbuf =
		container_of(tbuf, struct nvidia_tid_user_buf, common);
	struct tid_pageset *list = tbuf->psets;
	struct nvidia_p2p_page_table *page_table = nvbuf->pages;
	unsigned int pagecount, pageidx, setcount = 0, i;
	unsigned long pfn, this_pfn;

	/* NVIDIA doesn't do partial-mapping */
	if (WARN_ON(npages != page_table->entries))
		return -EFAULT;

	if (!npages)
		return -EINVAL;

	/*
	 * Look for sets of physically contiguous pages in the user buffer.
	 * This will allow us to optimize Expected RcvArray entry usage by
	 * using the bigger supported sizes.
	 */
	pfn = GPU_PAGE_TO_PFN(page_table->pages[0]);
	for (pageidx = 0, pagecount = 1, i = 1; i <= npages; i++) {
		this_pfn = i < npages ?
				GPU_PAGE_TO_PFN(page_table->pages[i]) : 0;

		/*
		 * If the pfn's are not sequential, pages are not physically
		 * contiguous.
		 */
		if (this_pfn != ++pfn) {
			/*
			 * At this point we have to loop over the set of
			 * physically contiguous pages and break them down into
			 * sizes supported by the HW.
			 * There are two main constraints:
			 *     1. The max buffer size is MAX_EXPECTED_BUFFER.
			 *        If the total set size is bigger than that
			 *        program only a MAX_EXPECTED_BUFFER chunk.
			 *     2. The buffer size has to be a power of two. If
			 *        it is not, round down to the closes power of
			 *        2 and program that size.
			 */
			while (pagecount) {
				int maxpages = pagecount;
				u32 bufsize = pagecount * NV_GPU_PAGE_SIZE;

				if (bufsize > MAX_EXPECTED_BUFFER)
					maxpages =
						MAX_EXPECTED_BUFFER >>
						NV_GPU_PAGE_SHIFT;
				else if (!is_power_of_2(bufsize))
					maxpages =
						rounddown_pow_of_two(bufsize) >>
						NV_GPU_PAGE_SHIFT;
				list[setcount].idx = pageidx;
				list[setcount].count = maxpages;
				pagecount -= maxpages;
				pageidx += maxpages;
				setcount++;
			}
			pageidx = i;
			pagecount = 1;
			pfn = this_pfn;
		} else {
			pagecount++;
		}
	}
	tbuf->n_psets = setcount;
	return 0;
}

static bool nvidia_invalidated(struct tid_user_buf *tbuf)
{
	struct nvidia_tid_user_buf *nvbuf =
		container_of(tbuf, struct nvidia_tid_user_buf, common);
	bool ret;

	spin_lock(&nvbuf->nodes_lock);
	ret = nvbuf->invalidated;
	spin_unlock(&nvbuf->nodes_lock);
	return ret;
}

static void nvidia_unnotify(struct tid_user_buf *tbuf)
{
	/*
	 * No-op; callback deregistration happens when NVIDIA put_pages() is
	 * called, which happens when the last kref to nvidia_tid_user_buf is
	 * released.
	 */
}

static struct tid_user_buf_ops nvidia_bufops = {
	.init = nvidia_user_buf_init,
	.free = nvidia_user_buf_free,
	.page_size = nvidia_page_size,
	.pin_pages = nvidia_pin_pages,
	.unpin_pages = nvidia_unpin_pages,
	.find_phys_blocks = nvidia_find_phys_blocks,
	.invalidated = nvidia_invalidated,
	.unnotify = nvidia_unnotify,
};

int register_nvidia_tid_ops(void)
{
	const char *err_str;
	int ret;

#define GET_SYMBOL(name)					\
	rdma_interface.name = symbol_get(nvidia_p2p_##name);	\
	if (!rdma_interface.name) {				\
		err_str = "missing symbol nvidia_p2p_"#name;	\
		ret = -EOPNOTSUPP;					\
		goto fail;					\
	}

	GET_SYMBOL(free_page_table);
	GET_SYMBOL(free_dma_mapping);
	GET_SYMBOL(dma_map_pages);
	GET_SYMBOL(dma_unmap_pages);
	GET_SYMBOL(put_pages);
	GET_SYMBOL(get_pages);

#undef GET_SYMBOL

	ret = register_tid_ops(HFI1_MEMINFO_TYPE_NVIDIA, &nvidia_bufops, &nvidia_nodeops);
	if (ret)
		goto fail;
	pr_info("%s Nvidia p2p TID-DMA support enabled\n", class_name());
	return 0;
fail:
	deregister_nvidia_tid_ops();
	pr_info("%s Nvidia p2p TID-DMA support disabled\n", class_name());
	return ret;
}

void deregister_nvidia_tid_ops(void)
{
	deregister_tid_ops(HFI1_MEMINFO_TYPE_NVIDIA);

#define PUT_SYMBOL(name)			\
	do { \
		if (rdma_interface.name)		\
			symbol_put(nvidia_p2p_##name);  \
	} while (0)

	PUT_SYMBOL(free_page_table);
	PUT_SYMBOL(free_dma_mapping);
	PUT_SYMBOL(dma_map_pages);
	PUT_SYMBOL(dma_unmap_pages);
	PUT_SYMBOL(put_pages);
	PUT_SYMBOL(get_pages);

#undef PUT_SYMBOL
}
