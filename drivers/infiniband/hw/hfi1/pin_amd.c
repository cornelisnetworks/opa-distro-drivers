// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2022 - Cornelis Networks, Inc.
 */

#include <linux/types.h>
#include <linux/slab.h>

#include "hfi.h"
#include "common.h"
#include "device.h"
#include "pinning.h"
#include "sdma.h"
#include "user_sdma.h"
#include "trace.h"

#include <drm/amd_rdma.h>

#ifdef CONFIG_HFI1_AMD_SOFTDEP
MODULE_SOFTDEP("pre: amdgpu");
#endif

/*
 * Estimate of the maximum number of pin caches that will be established in
 * the system for a single GPU. The cap on pin cache size is set to
 * amd_cache_size divided by this number, where amd_cache_size represents
 * the maximum amount of memory the AMD driver will allow to be pinned for a
 * given GPU.
 *
 * If the application's approach is to allocate one HFI packet queue per
 * core (as opposed to sharing a packet queue among multiple cores), then
 * this value is equivalent to the expected maximum number of cores using a
 * given GPU.
 *
 * If the actual number of pin caches established for a given GPU exceeds
 * this number, it becomes possible for a subset of the pin caches to absorb
 * all of the pinning capacity of the device, in which case all I/O attempts
 * to the device on the remainder of the packet queues would fail. For example,
 * if the value is set to N, but N + 1 packet queues are used to access the
 * device, and the first N perform I/O against the device that fills their
 * respective pin caches to the limit, then when I/O is issued against the
 * device on the (N + 1)th packet queue, it will fail due to the refusal of the
 * AMD driver to pin more pages at that point. The (N+1)th packet queue will
 * not be able to address this condition by on-demand eviction from its pin
 * cache because its pin cache will be empty, and the condition will persist
 * until at least one of the other N packet queues is closed.
 */
#define AMD_PIN_CACHES_PER_GPU 8

/*
 * Effectively disable the backend's per-queue size limit as experiments
 * with a 32 GiB MI100 and driver version 5.16.9.22.20 showed nearly all of
 * the on-board memory can be allocated by the application and subsequently
 * pinned via the kernel p2p interface.
 */
static unsigned long amd_cache_size = ~0UL;
module_param(amd_cache_size, ulong, 0644);
MODULE_PARM_DESC(amd_cache_size, "Per-context AMD pin cache size limit (in MB)");

#define AMD_MAX_DEVICES 16
#define AMD_DEVICE_HASH_OVERSUBSCRIBE 2
#define AMD_DEVICE_HASH_BITS ilog2(AMD_MAX_DEVICES * AMD_DEVICE_HASH_OVERSUBSCRIBE)

struct amd_pq_state {
	/* on its own cacheline */
	spinlock_t lock; /* protects num_pintrees and pintree_hash */

	/* new cacheline starts here */
	struct hfi1_user_sdma_pkt_q *pq ____cacheline_aligned_in_smp;
	struct device *dma_device;
	unsigned int num_pintrees;
	DECLARE_HASHTABLE(pintree_hash, AMD_DEVICE_HASH_BITS);
};

struct amd_pintree {
	/* on its own cacheline */
	spinlock_t lock;

	/* new cacheline starts here */
	uint32_t device_id ____cacheline_aligned_in_smp;
	struct hlist_node hash_node;
	struct rb_root_cached root;
	struct list_head lru_list;
	struct amd_pq_state *state;
	size_t size;
	size_t hits;
	size_t misses;
	size_t internal_evictions;
	size_t external_evictions;
};

struct amd_pintree_node {
	struct interval_tree_node node;
	struct list_head lru_node;
	/* Needed to handle the driver calling back to free a pinned region. */
	struct amd_pintree *pintree;
	size_t size;
	struct amd_p2p_info *p2p_info;
	atomic_t refcount;
	bool invalidated;
};

static void unpin_amd_node(struct amd_pintree_node *node);

static const struct amd_rdma_interface *rdma_ops;
static struct kmem_cache *pq_state_kmem_cache;
static struct kmem_cache *pintree_kmem_cache;

static struct amd_pintree *init_amd_pintree(struct amd_pq_state *state, uint32_t device_id)
{
	struct amd_pintree *pintree;

	/*
	 * Prevent application from allocating arbitrary amounts of kernel
	 * memory.
	 */
	spin_lock(&state->lock);
	if (state->num_pintrees == AMD_MAX_DEVICES) {
		spin_unlock(&state->lock);
		return NULL;
	}
	state->num_pintrees++;
	spin_unlock(&state->lock);

	pintree = kmem_cache_zalloc(pintree_kmem_cache, GFP_KERNEL);
	if (!pintree) {
		spin_lock(&state->lock);
		state->num_pintrees--;
		spin_unlock(&state->lock);
		return NULL;
	}
	spin_lock_init(&pintree->lock);
	pintree->root = RB_ROOT_CACHED;
	INIT_LIST_HEAD(&pintree->lru_list);
	pintree->state = state;
	pintree->device_id = device_id;

	spin_lock(&state->lock);
	hash_add(state->pintree_hash, &pintree->hash_node, device_id);
	spin_unlock(&state->lock);

	return pintree;
}

static void cleanup_amd_pintree(struct amd_pintree *pintree)
{
	struct amd_pq_state *state = pintree->state;
	struct hfi1_user_sdma_pkt_q *pq = state->pq;
	struct interval_tree_node *found_node;
	struct amd_pintree_node *found;

	PIN_PQ_DBG(pq, "enter");

	spin_lock(&state->lock);
	hash_del(&pintree->hash_node);
	spin_unlock(&state->lock);

	while (1) {
		/*
		 * Although there must not be any activity on the pq at this
		 * point, the locks are still necessary as the AMD driver
		 * may invoke remove_amd_pages() on a pintree node at any
		 * point before the invocation of put_pages() for that node
		 * occurs below.
		 */
		spin_lock(&pintree->lock);
		found_node = interval_tree_iter_first(&pintree->root, 0UL, ~0UL);
		if (!found_node) {
			spin_unlock(&pintree->lock);
			break;
		}

		found = container_of(found_node, struct amd_pintree_node, node);
		if (atomic_read(&found->refcount) > 0) {
			spin_unlock(&pintree->lock);
			PIN_PQ_DBG(pq, "spinning until node refcount is zero (%u)",
				   atomic_read(&found->refcount));
			cond_resched();
			continue;
		}

		interval_tree_remove(&found->node, &pintree->root);
		spin_unlock(&pintree->lock);

		unpin_amd_node(found);
		/*
		 * It is necessary to wait until after put_pages() is called
		 * to free the node in order to cleanly resolve races
		 * between cleanup_amd_pintree() completing and calls to
		 * remove_amd_pages() by the AMD driver.
		 */
		kfree(found);
	}

	kmem_cache_free(pintree_kmem_cache, pintree);
}

static struct amd_pintree *get_amd_pintree(struct amd_pq_state *state, uint32_t device_id)
{
	struct amd_pintree *pintree;

	spin_lock(&state->lock);
	hash_for_each_possible(state->pintree_hash, pintree, hash_node, device_id) {
		if (pintree->device_id == device_id) {
			spin_unlock(&state->lock);
			return pintree;
		}
	}
	spin_unlock(&state->lock);

	return init_amd_pintree(state, device_id);
}

static struct amd_pintree *get_nth_amd_pintree(struct amd_pq_state *state, unsigned int n)
{
	struct amd_pintree *pintree;
	size_t bucket_index;
	unsigned int index;

	index = 0;
	spin_lock(&state->lock);
	hash_for_each(state->pintree_hash, bucket_index, pintree, hash_node) {
		if (index == n) {
			spin_unlock(&state->lock);
			return pintree;
		}
		index++;
	}
	spin_unlock(&state->lock);

	return NULL;
}

static int init_amd_pinning_interface(struct hfi1_user_sdma_pkt_q *pq)
{
	struct amd_pq_state *state;

	state = kmem_cache_zalloc(pq_state_kmem_cache, GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	state->pq = pq;
	state->dma_device = &pq->dd->pcidev->dev;
	spin_lock_init(&state->lock);
	hash_init(state->pintree_hash);

	PINNING_STATE(pq, HFI1_MEMINFO_TYPE_AMD) = state;
	return 0;
}

static void free_amd_pinning_interface(struct hfi1_user_sdma_pkt_q *pq)
{
	struct amd_pq_state *state = PINNING_STATE(pq, HFI1_MEMINFO_TYPE_AMD);
	struct amd_pintree *pintree;
	struct hlist_node *tmp;
	size_t bucket_index;

	/*
	 * The pinning interface must not be cleaned up while it is still in
	 * use, so there is no need to acquire the state lock before
	 * accessing the hash table as this call is now the only accessor.
	 */
	lockdep_assert_not_held(&state->lock);

	hash_for_each_safe(state->pintree_hash, bucket_index, tmp, pintree, hash_node)
		cleanup_amd_pintree(pintree);

	kmem_cache_free(pq_state_kmem_cache, state);
}

/* This is the free callback passed to rdma_ops->get_pages() */
static void remove_amd_pages(void *data)
{
	struct amd_pintree_node *node = data;
	struct interval_tree_node *found_node;
	struct amd_pintree_node *found;
	struct amd_pintree *pintree = node->pintree;
	struct amd_pq_state *state = pintree->state;

	/*
	 * amd_rdma_interface->get_pages() takes a pages-freed callback but at
	 * the time this was implemented, there was no indication that amdgpu
	 * actually calls the callback.
	 */
	WARN_ONCE(true, "Unexpected callback");

	/*
	 * The ROCmRDMA API documentation indicates this may be called as a
	 * result of GECC events (the name of on-board ECC functionality)
	 * and also says that I/O must be stopped 'immediately', raising the
	 * question of whether that means this may be called from within an
	 * interrupt handler. Review of the ROCK-Kernel-Driver source code
	 * as of version 5.16.9.22.20 revealed that this callback is only
	 * invoked as a result of an ioctl used by userspace to free GPU
	 * memory so being called in interrupt context does not need to be
	 * considered at this time.
	 */
	WARN_ON(in_interrupt());

	/* Remove from the tree so that it's not found anymore. */
	spin_lock(&pintree->lock);
	node->invalidated = true;

	found_node = interval_tree_iter_first(&pintree->root, node->node.start, node->node.last);
	found = container_of(found_node, struct amd_pintree_node, node);
	if (found == node) {
		interval_tree_remove(&node->node, &pintree->root);
		list_del(&node->lru_node);
		pintree->size -= node->size;
		pintree->external_evictions++;
		spin_unlock(&pintree->lock);

		/* Spin until I/O is done. */
		while (atomic_read(&node->refcount) > 0)
			rep_nop();

		/*
		 * The AMD driver will free all of its associated resources
		 * upon return from this function.
		 */
		kfree(found);
	} else {
		spin_unlock(&pintree->lock);
		/*
		 * This can happen during free_amd_pinning_interface() if
		 * the AMD driver calls remove_amd_pages() for a pintree
		 * node that cleanup_...() has removed from the tree but
		 * hasn't yet called put_pages() for.  As cleanup_...() does
		 * not free the node until after it calls put_pages(), the
		 * node will always still be valid through this point.
		 * However, there is no further work to be done here in this
		 * case.
		 */
		dd_dev_info(state->pq->dd, "node %p not found in %s: found %p\n",
			    node, __func__, found);
	}
}

static int insert_amd_pinning(struct amd_pintree *pintree, struct amd_pintree_node *node)
{
	struct interval_tree_node *existing;
	int result = 0;

	spin_lock(&pintree->lock);
	if (WARN_ON(node->invalidated)) {
		spin_unlock(&pintree->lock);
		return -EFAULT;
	}

	/*
	 * The lookup is required because interval trees can support overlap, but
	 * we don't want overlap here.
	 */
	existing = interval_tree_iter_first(&pintree->root, node->node.start, node->node.last);
	if (existing) {
		result = -EEXIST;
		goto unlock;
	}

	/*
	 * Take safety ref; release after sdma_txadd_daddr() when any
	 * per-descriptor references have been taken.
	 */
	atomic_inc(&node->refcount);
	interval_tree_insert(&node->node, &pintree->root);
	list_add_tail(&node->lru_node, &pintree->lru_list);
	pintree->size += node->size;

unlock:
	spin_unlock(&pintree->lock);
	return result;
}

static void unpin_amd_node(struct amd_pintree_node *node)
{
	struct amd_pintree *pintree = node->pintree;
	struct amd_pq_state *state = pintree->state;
	struct hfi1_user_sdma_pkt_q *pq = state->pq;
	int result;

	/* There must be no I/O referencing this node. */
	WARN_ON(atomic_read(&node->refcount) != 0);

	result = rdma_ops->put_pages(&node->p2p_info);
	if (result)
		dd_dev_info(pq->dd, "ROCmRDMA put_pages() failed while unwinding pinning: %d\n",
			    result);
}

static bool evict_amd_pinnings(struct amd_pintree *pintree, size_t goal, bool internal)
{
	struct amd_pintree_node *cur;
	struct amd_pintree_node *tmp;
	struct list_head evict_list;
	size_t *stat;
	size_t total;

	INIT_LIST_HEAD(&evict_list);
	stat = internal ? &pintree->internal_evictions : &pintree->external_evictions;

	total = 0;
	spin_lock(&pintree->lock);
	list_for_each_entry_safe(cur, tmp, &pintree->lru_list, lru_node) {
		if (atomic_read(&cur->refcount) == 0) {
			interval_tree_remove(&cur->node, &pintree->root);
			list_move(&cur->lru_node, &evict_list);
			(*stat)++;
			total += cur->size;
			if (total >= goal)
				break;
		}
	}
	pintree->size -= total;
	spin_unlock(&pintree->lock);

	list_for_each_entry_safe(cur, tmp, &evict_list, lru_node) {
		unpin_amd_node(cur);
		kfree(cur);
	}

	return total >= goal;
}

static int pin_amd_region(struct amd_pintree *pintree, struct pid *pid,
			  u64 start, u64 last, struct amd_pintree_node *node)
{
	struct amd_pq_state *state = pintree->state;
	struct hfi1_user_sdma_pkt_q *pq = state->pq;
	size_t len;
	int result;
	bool retry = true;

	len = (last + 1) - start;
retry:
	result = rdma_ops->get_pages(start, len, pid, state->dma_device,
				     &node->p2p_info, remove_amd_pages, node);
	if (result == -ENOSPC && retry) {
		PIN_PQ_DBG(pq, "get_pages failed with ENOSPC, trying eviction");
		retry = false;
		if (evict_amd_pinnings(pintree, len, false))
			goto retry;
		PIN_PQ_DBG(pq, "eviction failed");
	}

	if (result) {
		PIN_PQ_DBG(pq, "get_pages failed with %d start=0x%llx length=%zu",
			   result, start, len);
		return result;
	}

	node->node.start = start;
	node->node.last = last;
	node->size = len;

	result = insert_amd_pinning(pintree, node);
	if (result)
		unpin_amd_node(node);

	return result;
}

static struct amd_pintree_node *find_amd_pinning(struct amd_pintree *pintree,
						 u64 start, u64 last,
						 size_t *tree_size)
{
	struct interval_tree_node *tree_node;
	struct amd_pintree_node *node = NULL;

	spin_lock(&pintree->lock);
	tree_node = interval_tree_iter_first(&pintree->root, start, last);
	if (tree_node) {
		node = container_of(tree_node, struct amd_pintree_node, node);
		list_move_tail(&node->lru_node, &pintree->lru_list);
		/*
		 * Take safety ref; release after sdma_txadd_daddr() when any
		 * per-descriptor references have been taken.
		 */
		atomic_inc(&node->refcount);
		pintree->hits++;
	} else {
		pintree->misses++;
	}
	*tree_size = pintree->size;
	spin_unlock(&pintree->lock);

	return node;
}

static int add_amd_pinning(struct amd_pintree *pintree, struct pid *pid,
			   struct amd_pintree_node **node_p, u64 start,
			   u64 last, size_t tree_size)
{
	struct amd_pq_state *state = pintree->state;
	struct hfi1_user_sdma_pkt_q *pq = state->pq;
	unsigned long page_size;
	u64 start_page, end_page;
	struct amd_pintree_node *node;
	size_t len;
	size_t limit;
	int result;

	len = (last + 1) - start;
	limit = amd_cache_size * 1024 * 1024 / AMD_PIN_CACHES_PER_GPU;
	if (tree_size + len > limit) {
		if (!evict_amd_pinnings(pintree, tree_size + len - limit, true)) {
			PIN_PQ_DBG(pq, "failed to evict %zu bytes from full cache",
				   tree_size + len - limit);
			return -ENOMEM;
		}
	}

	/*
	 * The page size is checked here because the documentation says:
	 *    Return the single page size to be used when bulding the scatter/gather table.
	 *
	 * This indicated it is a per-pinning value.
	 */
	result = rdma_ops->get_page_size(start, len, pid, &page_size);
	if (result) {
		PIN_PQ_DBG(pq, "get_page_size failed %d", result);
		return result;
	}

	if (page_size & (page_size - 1))
		dd_dev_info(pq->dd, "ROCmRDMA returned page size 0x%lx (not a power of 2)\n",
			    page_size);

	start_page = (uint64_t)start & (~(page_size - 1));
	end_page = (uint64_t)((last + 1) + (page_size - 1)) & (~(page_size - 1));

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->pintree = pintree;
	result = pin_amd_region(pintree, pid, start_page, end_page - 1, node);
	if (result)
		kfree(node);
	else
		*node_p = node;

	return result;
}

static int incremental_pin_amd_region(struct amd_pintree *pintree, struct pid *pid,
				      struct amd_pintree_node **node_p,
				      u64 start, u64 last)
{
	int ret;

	while (1) {
		size_t tree_size;
		struct amd_pintree_node *node = find_amd_pinning(pintree, start, last, &tree_size);

		if (!node) {
			ret = add_amd_pinning(pintree, pid, node_p, start, last, tree_size);
			if (ret == -EEXIST) {
				/*
				 * Another execution context has inserted a conficting entry
				 * first.
				 */
				continue;
			}
			return ret;
		}

		if (node->node.start <= start) {
			*node_p = node;
			return 0;
		}

		/*
		 * This node will not be returned, instead a new node will be.
		 * So release the reference.
		 */
		atomic_dec(&node->refcount);

		/* Prepend a node to cover the beginning of the allocation */
		ret = add_amd_pinning(pintree, pid, node_p, start, node->node.start - 1,
				      tree_size);
		if (ret == -EEXIST) {
			/*
			 * Another execution context has inserted a conficting
			 * entry first.
			 */
			continue;
		}
		return ret;
	}
}

static int get_amd_cache_entry(struct amd_pintree *pintree, struct pid *pid,
			       struct amd_pintree_node **node, size_t start, size_t len)
{
	if (len == 0)
		return -EINVAL;
	return incremental_pin_amd_region(pintree, pid, node, start, (start + len) - 1);
}

static void amd_node_get(void *ctx)
{
	atomic_inc(&((struct amd_pintree_node *)ctx)->refcount);
}

static void amd_node_put(void *ctx)
{
	atomic_dec(&((struct amd_pintree_node *)ctx)->refcount);
}

static int add_amd_mapping_to_sdma_packet(struct pid *pid,
					  struct hfi1_user_sdma_pkt_q *pq,
					  struct user_sdma_txreq *tx,
					  struct amd_pintree_node *cache_entry,
					  size_t start, size_t from_this_cache_entry)
{
	struct sg_table *sgt = cache_entry->p2p_info->pages;
	unsigned long sgl_start;
	struct scatterlist *sg;
	unsigned int sgl_offset;
	unsigned int i;
	unsigned int from_this_sgl;
	size_t dma_start;
	void *ctx;
	int result;

	sgl_start = cache_entry->node.start;
	/*
	 * Find first sgl where end(sgl) > start.
	 * Virtual address ranges starting at start, sgl_start should be
	 * contiguous but sgl DMA addresses may not be. So update sgl_start
	 * rather than using sg_dma_address().
	 */
	for_each_sgtable_sg(sgt, sg, i) {
		if (start < sgl_start + sg_dma_len(sg))
			break;
		sgl_start += sg_dma_len(sg);
	}

	/* Offset only applies to first sg */
	sgl_offset = start - sgl_start;
	while (from_this_cache_entry) {
		from_this_sgl = sg_dma_len(sg) - sgl_offset;
		from_this_sgl = (from_this_sgl <= from_this_cache_entry) ?
			from_this_sgl : from_this_cache_entry;

		dma_start = sg_dma_address(sg) + sgl_offset;
		sgl_offset = 0; /* Offset N/A for subsequent sg */
		ctx = (from_this_sgl < from_this_cache_entry) ? NULL : cache_entry;

		result = sdma_txadd_daddr(pq->dd, &tx->txreq, dma_start,
					  from_this_sgl, ctx, amd_node_get,
					  amd_node_put);
		if (result) {
			/*
			 * When there's a failure, the entire request is freed by
			 * user_sdma_send_pkts().
			 */
			return result;
		}
		sg = sg_next(sg);
		from_this_cache_entry -= from_this_sgl;
	}
	return 0;
}

static int add_amd_iovec_to_sdma_packet(struct amd_pq_state *state,
					struct pid *pid,
					struct user_sdma_request *req,
					struct user_sdma_txreq *tx,
					struct user_sdma_iovec *iovec,
					size_t from_this_iovec)
{
	struct amd_pintree *pintree;
	u32 device_id;

	device_id = iovec->context;
	pintree = get_amd_pintree(state, device_id);
	if (!pintree)
		return -ENOMEM;

	SDMA_DBG(req, "start=0x%llx len=%zu device_id=0x%08x", (uintptr_t)iovec->iov.iov_base + iovec->offset,
		 from_this_iovec, device_id);

	while (from_this_iovec > 0) {
		struct amd_pintree_node *cache_entry;
		size_t from_this_cache_entry;
		size_t start;
		int ret;

		start = (uintptr_t)iovec->iov.iov_base + iovec->offset;
		ret = get_amd_cache_entry(pintree, pid, &cache_entry, start, from_this_iovec);
		if (ret) {
			SDMA_DBG(req, "SDMA pin AMD segment failed %d", ret);
			return ret;
		}

		from_this_cache_entry = (cache_entry->node.last + 1) - start;
		if (from_this_cache_entry > from_this_iovec)
			from_this_cache_entry = from_this_iovec;

		ret = add_amd_mapping_to_sdma_packet(pid, req->pq, tx, cache_entry, start,
						     from_this_cache_entry);

		/* Release safety ref */
		atomic_dec(&cache_entry->refcount);
		if (ret) {
			SDMA_DBG(req, "SDMA txreq add amd segment failed %d", ret);
			return ret;
		}

		iovec->offset += from_this_cache_entry;
		from_this_iovec -= from_this_cache_entry;
	}

	return 0;
}

static int add_amd_pages_to_sdma_packet(struct user_sdma_request *req,
					struct user_sdma_txreq *tx,
					struct user_sdma_iovec *iovec,
					u32 *pkt_data_remaining)
{
	struct amd_pq_state *state = PINNING_STATE(req->pq, HFI1_MEMINFO_TYPE_AMD);
	size_t remaining_to_add;

	/*
	 * Walk through iovec entries, ensure the associated pages are
	 * pinned and mapped, add data to the packet until no more
	 * data remains to be added or the iovec entry type changes.
	 */
	remaining_to_add = *pkt_data_remaining;
	while ((remaining_to_add > 0) && (iovec->type == HFI1_MEMINFO_TYPE_AMD)) {
		struct user_sdma_iovec *cur_iovec;
		size_t from_this_iovec;
		int ret;

		cur_iovec = iovec;
		from_this_iovec = iovec->iov.iov_len - iovec->offset;
		if (from_this_iovec > remaining_to_add) {
			from_this_iovec = remaining_to_add;
		} else {
			/* The current iovec entry will be consumed by this pass. */
			req->iov_idx++;
			iovec++;
		}

		ret = add_amd_iovec_to_sdma_packet(state, current->thread_pid, req, tx, cur_iovec,
						   from_this_iovec);
		if (ret)
			return ret;

		remaining_to_add -= from_this_iovec;
	}
	*pkt_data_remaining = remaining_to_add;

	return 0;
}

static int get_amd_stats(struct hfi1_user_sdma_pkt_q *pq, int index,
			 struct hfi1_pin_stats *stats)
{
	struct amd_pq_state *state = PINNING_STATE(pq, HFI1_MEMINFO_TYPE_AMD);
	struct amd_pintree *pintree;
	u64 next = 0;
	struct interval_tree_node *interval_node;
	unsigned int num_caches;

	spin_lock(&state->lock);
	num_caches = state->num_pintrees;
	spin_unlock(&state->lock);

	if (index == -1) {
		spin_lock(&state->lock);
		stats->index = num_caches;
		spin_unlock(&state->lock);
		return 0;
	}

	if (index < 0 || index >= num_caches)
		return -EINVAL;

	pintree = get_nth_amd_pintree(state, index);
	if (!pintree)
		return -EINVAL;

	stats->id = pintree->device_id;
	while ((interval_node = interval_tree_iter_first(&pintree->root, next, ~0UL - next))) {
		struct amd_pintree_node *node =
			container_of(interval_node, struct amd_pintree_node, node);
		u64 len;

		stats->cache_entries++;
		stats->total_refcounts += atomic_read(&node->refcount);
		len = interval_node->last - interval_node->start + 1;
		stats->total_bytes += len;
		next = interval_node->start + len;
	}

	stats->hits = pintree->hits;
	stats->misses = pintree->misses;
	stats->internal_evictions = pintree->internal_evictions;
	stats->external_evictions = pintree->external_evictions;

	return 0;
};

static struct pinning_interface amd_pinning_interface = {
	.init = init_amd_pinning_interface,
	.free = free_amd_pinning_interface,
	.add_to_sdma_packet = add_amd_pages_to_sdma_packet,
	.get_stats = get_amd_stats,
};

#ifdef CONFIG_HFI1_AMD_SOFTDEP
static int (*query_rdma)(const struct amd_rdma_interface **);
#endif

void register_amd_pinning_interface(void)
{
	int result;
	const char *err_str;
	char name_buf[64];

#ifdef CONFIG_HFI1_AMD_SOFTDEP
	query_rdma = symbol_get(amdkfd_query_rdma_interface);
	if (!query_rdma) {
		err_str = "missing symbol amdkfd_query_rdma_interface";
		goto fail;
	}
	result = query_rdma(&rdma_ops);
#else
	result = amdkfd_query_rdma_interface(&rdma_ops);
#endif
	if (result != 0) {
		err_str = "failed to obtain RDMA interface";
		goto fail;
	}

	snprintf(name_buf, sizeof(name_buf), "hfi1-amd-pq-state-kmem-cache");
	pq_state_kmem_cache = kmem_cache_create(name_buf,
						sizeof(struct amd_pq_state),
						cache_line_size(),
						0,
						NULL);
	if (!pq_state_kmem_cache) {
		err_str = "failed to allocate pq state pool";
		goto fail;
	}

	snprintf(name_buf, sizeof(name_buf), "hfi1-amd-pintree-kmem-cache");
	pintree_kmem_cache = kmem_cache_create(name_buf,
					       sizeof(struct amd_pintree),
					       cache_line_size(),
					       0,
					       NULL);
	if (!pintree_kmem_cache) {
		err_str = "failed to allocate pintree pool";
		goto fail;
	}

	register_pinning_interface(HFI1_MEMINFO_TYPE_AMD, &amd_pinning_interface);
	pr_info("%s AMD p2p DMA support enabled\n", class_name());
	return;
fail:
	pr_info("%s AMD p2p DMA support disabled (%s)\n", class_name(), err_str);
}

void deregister_amd_pinning_interface(void)
{
	deregister_pinning_interface(HFI1_MEMINFO_TYPE_AMD);

	kmem_cache_destroy(pintree_kmem_cache);
	kmem_cache_destroy(pq_state_kmem_cache);
#ifdef CONFIG_HFI1_AMD_SOFTDEP
	if (query_rdma)
		symbol_put(amdkfd_query_rdma_interface);
#endif
}
