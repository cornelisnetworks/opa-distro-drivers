// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 */

/*
 * AMD GPU TID implementation.
 * AMD does not support partial unpinning or even separate pinning and
 * DMA-mapping. So this is a simple implementation.
 */

#include <linux/kref.h>
#include <linux/scatterlist.h>

#include <drm/amd_rdma.h>

#include "device.h"
#include "hfi.h"
#include "user_exp_rcv.h"
#include "trace.h"

static const struct amd_rdma_interface *rdma_ops;

static struct tid_node_ops amd_nodeops;

struct amd_tid_user_buf {
	struct tid_user_buf common;
	struct amd_p2p_info *pages;
	bool invalidated;
	unsigned int pgsz;

	/* Covers .pages and .invalidated */
	spinlock_t pages_lock;

	struct kref ref;
	struct list_head nodes;
	/* Covers .nodes */
	spinlock_t nodes_lock;
};

/**
 * Advance over ROCm DMA-mapped memory in TID-compatible fashion.
 *
 * "TID-compatible fashion" means:
 * 1. DMA address is always 4KiB-aligned.
 * 2. DMA range length is in the range [4KiB,2MiB].
 * 3. DMA range length is a power-of-two.
 *
 * Here are the rules for amd_page_iter:
 * 1.  iter->sg is initialized to amdbuf->pages->pages->sgl, the first element
 *     in the scatterlist of DMA-mapped pages.
 * 2.  iter->offset is offset into iter->sg.
 * 3.  iter->offset is initialized to 0.
 * 4.  iter is initialized with respect to an amdbuf.
 * 5.  Starting DMA address must be valid. I.e. cannot be 0, length of DMA range cannot be 0.
 * 6.  dma_addr(iter) = sg_dma_address(iter->sg) + iter->offset.
 * 7.  dma_addr(iter) must be 4KiB aligned for TID hardware.
 * 8.  dma_len(iter) = rounddown_pow_of_two(min(sg_dma_len(iter->sg) - iter->offset, 2MiB)).
 * 9.  dma_len(iter) must be a power-of-two, must not be less than 4096.
 * 10. amd_page_iter_next(iter) advances iter->offset by dma_len(iter).
 * 11. If, in the process of advancing iter iter->offset >= sg_dma_len(iter),
 *     iter->sg is advanced to the next sg with sg_next(iter->sg), iter->offset
 *     is set to 0.
 * 12. iter->offset will never == sg_dma_len(iter) after amd_page_iter_next().
 * 13. If after iter->sg is NULL after 'iter->sg = sg_next(iter->sg)', iterator
 *     is at the end and no is no longer valid.
 * 14. amd_page_iter*() shall hold iter->buf->pages_lock and shall check that
 *     iter->buf->invalidated == false before calling any sg_*() functions on
 *     iter->sg.
 *
 *     This is necessary because iter->sg is not NULLed out when amdbuf is
 *     invalidated, so iter->sg will be non-NULL but no longer refers to a
 *     valid scatterlist in the amd_p2p_info memory.
 * 15. amd_page_iter does not take a kref to amdbuf. So amd_page_iter must only
 *     be used in places where amdbuf is guaranteed not to be freed for the life of
 *     the amd_page_iter.
 */
struct amd_page_iter {
	struct hfi1_page_iter common;
	struct amd_tid_user_buf *buf;

	/* Current pageset pointer. */
	struct scatterlist *sg;

	/* VA corresponding sg_dma_address(iter->sg) + iter->offset */
	unsigned long va;

	/* Offset into iter->sg's pageset. Used for > 2MiB pagesets. */
	unsigned int offset;
};

/**
 * Must hold iter->buf->pages_lock when calling.
 *
 * @return true if @iter is invalidated or at end of iteration.
 */
static bool __amd_page_iter_at_end(struct amd_page_iter *iter)
{
	/*
	 * If iter->buf->invalidated, unsafe to dereference iter->sg even if
	 * not NULL.
	 */
	return (iter->buf->invalidated || !iter->sg);
}

/**
 * Get length of current DMA range, rounded down to a power of two.
 *
 * Must be called with @iter->buf->pages_lock held.
 *
 * @return size >= 4096 && <= 2MiB on success, 0 if iterator is at end of
 * current DMA range.
 */
static unsigned int __amd_page_iter_dma_len(struct amd_page_iter *iter)
{
	unsigned int len;

	len = sg_dma_len(iter->sg);
	if (iter->offset >= len)
		return 0;

	len = min_t(size_t, len - iter->offset, MAX_EXPECTED_BUFFER);
	/* At end of current DMA range */
	if (!len)
		return 0;

	len = rounddown_pow_of_two(len);
	/* This shouldn't happen; DMA should operate in units of PAGE_SIZE */
	if (WARN_ON(len < PAGE_SIZE))
		return 0;

	return len;
}

/**
 * Must be called with @iter->buf->pages_lock held.
 */
static dma_addr_t __amd_page_iter_dma_addr(struct amd_page_iter *iter)
{
	return (sg_dma_address(iter->sg) + iter->offset);
}

/**
 * Advance iterator to next TID-compatible DMA address.
 *
 * When current pageset is > 2MiB, offset into current range by up to 2MiB
 * before advancing to next pageset.
 *
 * When current pageset is <= 2MiB in length, advances to start of next
 * pageset.
 *
 * @return 1 if iterator is still valid after advancing, 0 if iterator advanced
 * and is no longer valid (at-end), error if error occurred while advancing
 * iterator (iterator already at-end, backing AMD pages invalidated/freed).
 */
static int amd_page_iter_next(struct hfi1_page_iter *diter)
{
	struct amd_page_iter *iter =
		container_of(diter, struct amd_page_iter, common);
	unsigned int len;
	unsigned long adv;
	int ret = 0;

	/*
	 * Ensure that amd_free_cb() can't run concurrent to advancing
	 * iterator.
	 *
	 * This protects iter from amd_free_cb(), not from concurrent
	 * amd_page_iter_next(iter) calls on same iter, which you shouldn't be
	 * doing.
	 */
	spin_lock(&iter->buf->pages_lock);
	if (iter->buf->invalidated || unlikely(!iter->buf->pages)) {
		hfi1_cdbg(TID, "iter %p invalidated %d pages %p", iter, iter->buf->invalidated,
			  iter->buf->pages);
		ret = -EINVAL;
		goto unlock;
	}

	if (__amd_page_iter_at_end(iter)) {
		ret = -EINVAL;
		goto unlock;
	}

	len = sg_dma_len(iter->sg);

	/*
	 * It doesn't look like gpu/drm/amd uses SG_CHAIN at all but if they
	 * do, we don't handle it.
	 */
	if (WARN_ON(sg_is_chain(iter->sg))) {
		ret = -EINVAL;
		goto unlock;
	}

	/*
	 * Advance offset inside current pageset, up to 2MiB.  If offset
	 * reaches the end of the current pageset, the next step will reset
	 * offset to the start of the next pageset.
	 */
	adv = __amd_page_iter_dma_len(iter);
	iter->offset += adv;
	iter->va += adv;

	/*
	 * pageset is <= 2MiB or offset has reached the end of pageset;
	 * advance to next sg.
	 */
	if (iter->offset >= len) {
		iter->offset = 0;
		iter->sg = sg_next(iter->sg);
	}

	/*
	 * This really shouldn't happen but make sure that current DMA address
	 * is TID-compatible.
	 */
	if (iter->sg && !IS_ALIGNED(__amd_page_iter_dma_addr(iter), EXPECTED_ADDR_SIZE))
		ret = -EFAULT;
	else
		ret = !(__amd_page_iter_at_end(iter));
unlock:
	spin_unlock(&iter->buf->pages_lock);

	return ret;
}

static void amd_page_iter_free(struct hfi1_page_iter *diter)
{
	struct amd_page_iter *iter =
		container_of(diter, struct amd_page_iter, common);

	hfi1_cdbg(TID, "iter %p .sg %p .offset %u .buf.invalidated %d",
		  iter, iter->sg, iter->offset, iter->buf->invalidated);

	kfree(iter);
}

static struct hfi1_page_iter_ops amd_page_iter_ops = {
	.next = amd_page_iter_next,
	.free = amd_page_iter_free
};

static struct hfi1_page_iter *amd_page_iter_begin(struct tid_user_buf *tbuf)
{
	struct amd_tid_user_buf *abuf =
		container_of(tbuf, struct amd_tid_user_buf, common);
	struct amd_page_iter *iter;
	void *ret;

	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter)
		return ERR_PTR(-ENOMEM);

	spin_lock(&abuf->pages_lock);

	/*
	 * Was not mapped or was invalidated prior/concurrent calling this
	 * function.
	 */
	if (!abuf->pages || abuf->invalidated) {
		ret = ERR_PTR(-EINVAL);
		goto unlock;
	}

	iter->common.ops = &amd_page_iter_ops;
	iter->buf = abuf;
	iter->sg = abuf->pages->pages->sgl;

	/*
	 * amd_pin_pages() already ensures that
	 *   abuf->common.vaddr == abuf->pages->va
	 */
	iter->va = abuf->pages->va;
	ret = &iter->common;

unlock:
	spin_unlock(&abuf->pages_lock);
	if (IS_ERR(ret))
		kfree(iter);

	return ret;
}

/* TID node code */

/*
 * Actual pinned/DMA memory information stored in amd_tid_user_buf.
 */
struct amd_tid_node {
	struct tid_rb_node common;
	struct list_head list;
	struct amd_tid_user_buf *buf;
};

static void amd_user_buf_kref_cb(struct kref *ref);

static struct tid_rb_node *amd_node_init(struct hfi1_filedata *fd,
					 struct tid_user_buf *tbuf,
					 u32 rcventry,
					 struct tid_group *grp,
					 struct hfi1_page_iter *diter)
{
	struct amd_page_iter *iter =
		container_of(diter, struct amd_page_iter, common);
	struct amd_tid_user_buf *abuf = iter->buf;
	struct amd_tid_node *amdnode;
	dma_addr_t dma_addr;
	unsigned int ps;
	int ret;

	amdnode = kzalloc(sizeof(*amdnode), GFP_KERNEL);
	if (!amdnode)
		return ERR_PTR(-ENOMEM);

	/*
	 * Node creation and mapping-invalidation must occur atomically w.r.t.
	 * each other.
	 */
	spin_lock(&abuf->pages_lock);
	if (abuf->invalidated) {
		ret = -EFAULT;
		goto fail;
	}

	ps = ilog2(abuf->pgsz);
	dma_addr = __amd_page_iter_dma_addr(iter);
	if (dma_addr % abuf->pgsz) {
		ret = -EINVAL;
		goto fail;
	}

	kref_get(&abuf->ref);
	amdnode->buf = abuf;

	mutex_init(&amdnode->common.invalidate_mutex);
	amdnode->common.fdata = fd;
	amdnode->common.grp = grp;
	amdnode->common.ops = &amd_nodeops;
	amdnode->common.rcventry = rcventry;
	/* Just use system page size for .npages, .page_shift */
	amdnode->common.npages = __amd_page_iter_dma_len(iter) >> ps;
	amdnode->common.page_shift = ps;

	/* Can't get phys address; doesn't matter, user_exp_rcv only uses it for tracing. */
	amdnode->common.phys = 0;
	amdnode->common.dma_addr = dma_addr;
	amdnode->common.vaddr = iter->va;
	amdnode->common.use_mn = abuf->common.use_mn;
	amdnode->common.type = HFI1_MEMINFO_TYPE_AMD;

	/*
	 * Keep holding pages_lock so invalidation cannot occur while grabbing
	 * nodes_lock and inserting into nodes_list.
	 */
	spin_lock(&abuf->nodes_lock);
	list_add_tail(&amdnode->list, &abuf->nodes);
	spin_unlock(&abuf->nodes_lock);
	spin_unlock(&abuf->pages_lock);

	return &amdnode->common;
fail:
	spin_unlock(&abuf->pages_lock);
	kfree(amdnode);

	return ERR_PTR(ret);
}

static void amd_node_free(struct tid_rb_node *node)
{
	struct amd_tid_node *amdnode =
		container_of(node, struct amd_tid_node, common);

	/*
	 * amd_node_unregister_notify() should have been called before this
	 * function and removed this node from its buffer's notification list.
	 */
	spin_lock(&amdnode->buf->nodes_lock);
	WARN_ON(!list_empty(&amdnode->list));
	spin_unlock(&amdnode->buf->nodes_lock);

	kref_put(&amdnode->buf->ref, amd_user_buf_kref_cb);
	kfree(amdnode);
}

/**
 * No-op; individual amd_tid_nodes do not have notifier registrations.
 */
static int amd_node_register_notify(struct tid_rb_node *node)
{
	return 0;
}

/**
 * amd_tid_node->buf->kref will be put back when node is destroyed.
 */
static void amd_node_unregister_notify(struct tid_rb_node *node)
{
	struct amd_tid_node *amdnode =
		container_of(node, struct amd_tid_node, common);

	spin_lock(&amdnode->buf->nodes_lock);
	/*
	 * Use list_del_init() instead of list_del() for debug code in
	 * amd_node_free() that tests list_empty(&amdnode->list).
	 */
	list_del_init(&amdnode->list);
	spin_unlock(&amdnode->buf->nodes_lock);
}

/**
 * No-op; AMD does not support unmapping single pages in mapped-memory range.
 */
static void amd_node_dma_unmap(struct tid_rb_node *node)
{
}

/**
 * No-op; AMD does not support unpinning single pages in pinned-memory range.
 */
static void amd_node_unpin_pages(struct hfi1_filedata *fd, struct tid_rb_node *node)
{
}

static struct tid_node_ops amd_nodeops = {
	.init = amd_node_init,
	.free = amd_node_free,
	.register_notify = amd_node_register_notify,
	.unregister_notify = amd_node_unregister_notify,
	.dma_unmap = amd_node_dma_unmap,
	.unpin_pages = amd_node_unpin_pages
};

/* AMD TID user-buf code */
static struct tid_user_buf_ops amd_bufops;

static int amd_user_buf_init(u16 expected_count,
			     bool notify,
			     unsigned long vaddr,
			     unsigned long length,
			     bool allow_unaligned,
			     struct tid_user_buf **tbuf)
{
	struct amd_tid_user_buf *abuf;
	int ret;

	/* Enforce TID-entry alignment. */
	if (!IS_ALIGNED(vaddr, EXPECTED_ADDR_SIZE))
		return -EINVAL;

	abuf = kzalloc(sizeof(*abuf), GFP_KERNEL);
	if (!abuf)
		return -ENOMEM;
	kref_init(&abuf->ref);
	*tbuf = &abuf->common;

	ret = tid_user_buf_init(expected_count, vaddr, length, notify, &amd_bufops,
				HFI1_MEMINFO_TYPE_AMD, *tbuf);
	if (ret)
		goto fail;

	INIT_LIST_HEAD(&abuf->nodes);
	spin_lock_init(&abuf->nodes_lock);
	spin_lock_init(&abuf->pages_lock);

	return 0;

fail:

	/* No need to do kref_put(), no outside abuf->ref holders */
	tid_user_buf_free(&abuf->common);
	kfree(abuf);
	return ret;
}

static void amd_user_buf_kref_cb(struct kref *ref)
{
	struct amd_tid_user_buf *abuf =
		container_of(ref, struct amd_tid_user_buf, ref);
	struct amd_p2p_info *pages;

	/*
	 * All nodes should have unregistered from abuf by the time last ref
	 * is released.
	 */
	spin_lock(&abuf->nodes_lock);
	WARN_ON(!list_empty(&abuf->nodes));
	spin_unlock(&abuf->nodes_lock);

	/* Update to .pages, .invalidated must be atomic to other CPUs. */
	spin_lock(&abuf->pages_lock);
	hfi1_cdbg(TID, "abuf %p pages %p invalidated %d freeing",
		  abuf, abuf->pages, abuf->invalidated);
	pages = abuf->pages;
	abuf->pages = NULL;
	abuf->invalidated = true;
	spin_unlock(&abuf->pages_lock);

	/*
	 * This assumes that amdgpu's free-callback does not kfree()
	 * outstanding amd_p2p_info held by peer drivers.
	 *
	 * If it does, then storing pages locally and calling
	 * rdma_ops->put_pages() is a bad idea.
	 */
	if (pages)
		rdma_ops->put_pages(&pages);

	tid_user_buf_free(&abuf->common);
	kfree(abuf);
}

static void amd_user_buf_free(struct tid_user_buf *tbuf)
{
	struct amd_tid_user_buf *abuf =
		container_of(tbuf, struct amd_tid_user_buf, common);

	kref_put(&abuf->ref, amd_user_buf_kref_cb);
}

static unsigned int amd_page_size(struct tid_user_buf *tbuf)
{
	struct amd_tid_user_buf *abuf =
		container_of(tbuf, struct amd_tid_user_buf, common);

	return abuf->pgsz;
}

static void amd_free_cb(void *priv)
{
	struct amd_tid_user_buf *abuf = priv;
	struct amd_tid_node *n;

	spin_lock(&abuf->pages_lock);
	hfi1_cdbg(TID, "abuf %p pages %p invalidated asynchronously", abuf, abuf->pages);
	abuf->pages = NULL;
	abuf->invalidated = true;
	spin_unlock(&abuf->pages_lock);

	spin_lock(&abuf->nodes_lock);
	list_for_each_entry(n, &abuf->nodes, list)
		hfi1_user_exp_rcv_invalidate(&n->common);
	spin_unlock(&abuf->nodes_lock);
}

/**
 * Pin and DMA map the pages for the ROCm virtual address range
 * [@tbuf->vaddr, @tbuf->vaddr + @tbuf->length).
 *
 * @return number of pages pinned & DMA-mapped > 0 on success, < 0 on error.
 */
static int amd_pin_pages(struct hfi1_filedata *fd,
			 struct tid_user_buf *tbuf)
{
	struct amd_tid_user_buf *abuf =
		container_of(tbuf, struct amd_tid_user_buf, common);
	unsigned long pgsz;
	unsigned int ps;
	int ret;

	ret = rdma_ops->get_pages(tbuf->vaddr, tbuf->length, task_pid(current),
				  &fd->dd->pcidev->dev, &abuf->pages,
				  amd_free_cb, abuf);

	if (ret)
		goto fail;

	/* Can't handle different VA start than what we requested. */
	if (WARN_ON(tbuf->vaddr != abuf->pages->va)) {
		ret = -EFAULT;
		goto fail_put_pages;
	}

	ret = rdma_ops->get_page_size(tbuf->vaddr, tbuf->length,
				      task_pid(current), &pgsz);
	if (ret)
		goto fail_put_pages;

	if (!pgsz || WARN_ON(pgsz > type_max(typeof(abuf->pgsz)))) {
		ret = -EFAULT;
		goto fail_put_pages;
	}
	abuf->pgsz = (unsigned int)pgsz;
	ps = ilog2(pgsz);

	/* type overflow; shouldn't happen */
	if (WARN_ON((abuf->pages->size >> ps) > type_max(typeof(ret)))) {
		ret = -EFAULT;
		goto fail_put_pages;
	}
	ret = (abuf->pages->size >> ps);

	trace_pin_rcv_pages_gpu(HFI1_MEMINFO_TYPE_AMD, tbuf->vaddr, abuf->pages->va,
				tbuf->length, abuf->pages->size, ret, tbuf);

	return ret;

fail_put_pages:
	rdma_ops->put_pages(&abuf->pages);
fail:
	abuf->pages = NULL;
	trace_recv_pin_gpu_pages_fail(HFI1_MEMINFO_TYPE_AMD, ret, tbuf->vaddr, tbuf->length);

	return ret;
}

/**
 * No-op; AMD does not support partial-unpinning.
 * Pages will be unmapped/unpinned when last ref to
 * amd_tid_user_buf is released.
 */
static void amd_unpin_pages(struct hfi1_filedata *fd,
			    struct tid_user_buf *tbuf,
			    unsigned int pageidx,
			    unsigned int npages)
{
}

static bool amd_invalidated(struct tid_user_buf *tbuf)
{
	struct amd_tid_user_buf *abuf =
		container_of(tbuf, struct amd_tid_user_buf, common);
	bool ret;

	spin_lock(&abuf->pages_lock);
	ret = abuf->invalidated;
	spin_unlock(&abuf->pages_lock);
	return ret;
}

/*
 * No-op.
 */
static void amd_unnotify(struct tid_user_buf *tbuf)
{
}

static struct tid_user_buf_ops amd_bufops = {
	.init = amd_user_buf_init,
	.free = amd_user_buf_free,
	.page_size = amd_page_size,
	.pin_pages = amd_pin_pages,
	.unpin_pages = amd_unpin_pages,
	.find_phys_blocks = NULL,
	.invalidated = amd_invalidated,
	.unnotify = amd_unnotify,
	.iter_begin = amd_page_iter_begin
};

int register_amd_tid_ops(void)
{
	int ret;

	ret = amdkfd_query_rdma_interface(&rdma_ops);
	if (WARN_ON(ret))
		goto bail;

	pr_info("%s AMD p2p TID-DMA support enabled\n", class_name());
	return register_tid_ops(HFI1_MEMINFO_TYPE_AMD, &amd_bufops, &amd_nodeops);
bail:
	pr_info("%s AMD p2p TID-DMA support disabled\n", class_name());
	return ret;
}

void deregister_amd_tid_ops(void)
{
	deregister_tid_ops(HFI1_MEMINFO_TYPE_AMD);
}
