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
#include "pin_nvidia.h"
#include "user_sdma.h"
#include "trace.h"

MODULE_SOFTDEP("pre: nvidia");

/*
 * Estimate of the maximum number of pin caches that will be established in
 * the system for a single GPU.  The cap on pin cache size is set to
 * nvidia_cache_size divided by this number, where nvidia_cache_size
 * represents the maximum amount of memory the Nvidia driver will allow to
 * be pinned for a given GPU.
 *
 * If the application's approach is to allocate one HFI packet queue per
 * core (as opposed to sharing a packet queue among multiple cores), then
 * this value is equivalent to the expected maximum number of cores using a
 * given GPU.
 *
 * If the actual number of pin caches established for a given GPU exceeds
 * this number, it becomes possible for a subset of the pin caches to absorb
 * all of the pinning capacity of the device, in which case all I/O attempts
 * to the device on the remainder of the packet queues would fail.  For
 * example, if the value is set to N, but N + 1 packet queues are used to
 * access the device, and the first N perform I/O against the device that
 * fills their respective pin caches to the limit, then when I/O is issued
 * against the device on the (N + 1)th packet queue, it will fail due to the
 * refusal of the Nvidia driver to pin more pages at that point.  The
 * (N+1)th packet queue will not be able to address this condition by
 * on-demand eviction from its pin cache because its pin cache will be
 * empty, and the condition will persist until at least one of the other N
 * packet queues is closed.
 */
#define NVIDIA_PIN_CACHES_PER_GPU 8

/*
 * The 2 GiB value is based on testing with driver version 515.43.04 and an
 * Nvidia A40 with 48 GiB of memory on board.
 */
static unsigned long nvidia_cache_size = 2 * 1024;
module_param(nvidia_cache_size, ulong, 0644);
MODULE_PARM_DESC(nvidia_cache_size, "Per-context Nvidia pin cache size limit (in MB)");

/*
 * The Nvidia documentation (https://docs.nvidia.com/cuda/gpudirect-rdma/index.html)
 * indicates that addresses used in pinning should be rounded to 64k boundaries.
 */
#define NVIDIA_PAGE_SHIFT	16
#define NVIDIA_PAGE_SIZE	BIT(NVIDIA_PAGE_SHIFT)
#define NVIDIA_PAGE_OFFSET_MASK	(NVIDIA_PAGE_SIZE - 1)
#define NVIDIA_PAGE_MASK	(~(u64)NVIDIA_PAGE_OFFSET_MASK)

static const u8 nvidia_page_shift[] = { 12, 16, 17 };
static_assert(ARRAY_SIZE(nvidia_page_shift) == NVIDIA_P2P_PAGE_SIZE_COUNT);
#define NVIDIA_PAGE_SHIFT_X(x)	(nvidia_page_shift[x])
#define NVIDIA_PAGE_SIZE_X(x)	(1U << NVIDIA_PAGE_SHIFT_X(x))
#define NVIDIA_PAGE_OFFSET_MASK_X(x)	(NVIDIA_PAGE_SIZE_X(x) - 1)
#define NVIDIA_PAGE_MASK_X(x)	(~(u64)NVIDIA_OFFSET_MASK_X(x))

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

static void unpin_nvidia_node(struct nvidia_pintree_node *node);

static struct kmem_cache *pq_state_kmem_cache;
static struct kmem_cache *pintree_kmem_cache;

static struct nvidia_pintree *init_nvidia_pintree(struct nvidia_pq_state *state, u32 device_id)
{
	struct nvidia_pintree *pintree;
	struct nvidia_pintree *existing;

	/*
	 * Prevent application from allocating arbitrary amounts of kernel
	 * memory.
	 */
	spin_lock(&state->lock);
	if (state->num_pintrees == NVIDIA_MAX_DEVICES) {
		spin_unlock(&state->lock);
		return NULL;
	}
	state->num_pintrees++;
	spin_unlock(&state->lock);

	pintree = kmem_cache_zalloc(pintree_kmem_cache, GFP_KERNEL);
	if (!pintree) {
		spin_lock(&state->lock);
		state->num_pintrees--;
		goto unlock_ret;
	}
	spin_lock_init(&pintree->lock);
	pintree->root = RB_ROOT_CACHED;
	INIT_LIST_HEAD(&pintree->lru_list);
	pintree->state = state;
	pintree->device_id = device_id;

	spin_lock(&state->lock);
	/*
	 * Check if another CPU added a pintree for device_id between holding
	 * state->lock
	 */
	hash_for_each_possible(state->pintree_hash, existing, hash_node, device_id) {
		if (existing->device_id == device_id) {
			kmem_cache_free(pintree_kmem_cache, pintree);
			state->num_pintrees--;
			pintree = existing;
			goto unlock_ret;
		}
	}
	hash_add(state->pintree_hash, &pintree->hash_node, device_id);

unlock_ret:
	spin_unlock(&state->lock);
	return pintree;
}

static void free_pintree(struct nvidia_pintree *pintree)
{
	struct nvidia_pq_state *state = pintree->state;
	struct hfi1_user_sdma_pkt_q *pq = state->pq;
	struct interval_tree_node *found_node;
	struct nvidia_pintree_node *found;

	PIN_PQ_DBG(pq, "enter");

	spin_lock(&state->lock);
	hash_del(&pintree->hash_node);
	spin_unlock(&state->lock);

	while (1) {
		/*
		 * Although there must not be any activity on the pq at this
		 * point, the locks are still necessary as the Nvidia driver
		 * may invoke remove_nvidia_pages() on a pintree node at any
		 * point before the invocation of put_pages() for that node
		 * occurs below.
		 */
		spin_lock(&pintree->lock);
		found_node = interval_tree_iter_first(&pintree->root, 0UL, ~0UL);
		if (!found_node) {
			spin_unlock(&pintree->lock);
			break;
		}

		found = container_of(found_node, struct nvidia_pintree_node, node);
		WARN_ON(atomic_read(&found->refcount) < 0);
		if (atomic_read(&found->refcount) > 0) {
			spin_unlock(&pintree->lock);
			cond_resched();
			continue;
		}

		interval_tree_remove(&found->node, &pintree->root);
		spin_unlock(&pintree->lock);

		unpin_nvidia_node(found);
		/*
		 * It is necessary to wait until after put_pages() is called to
		 * free the node in order to cleanly resolve races between
		 * free_pintree() completing and calls to remove_nvidia_pages()
		 * by the Nvidia driver.
		 */
		kfree(found);
	}

	kmem_cache_free(pintree_kmem_cache, pintree);
}

static struct nvidia_pintree *get_nvidia_pintree(struct nvidia_pq_state *state, u32 device_id)
{
	struct nvidia_pintree *pintree;

	spin_lock(&state->lock);
	hash_for_each_possible(state->pintree_hash, pintree, hash_node, device_id) {
		if (pintree->device_id == device_id) {
			spin_unlock(&state->lock);
			return pintree;
		}
	}
	spin_unlock(&state->lock);

	return init_nvidia_pintree(state, device_id);
}

static struct nvidia_pintree *get_nth_nvidia_pintree(struct nvidia_pq_state *state, unsigned int n)
{
	struct nvidia_pintree *pintree;
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

static int init_nvidia_pinning_interface(struct hfi1_user_sdma_pkt_q *pq)
{
	struct nvidia_pq_state *state;

	hfi1_cdbg(SDMA, "Initializing nvidia pinning module for pq %p", pq);

	state = kmem_cache_zalloc(pq_state_kmem_cache, GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	state->pq = pq;
	state->hfi_dev = pq->dd->pcidev;
	spin_lock_init(&state->lock);
	hash_init(state->pintree_hash);

	PINNING_STATE(pq, HFI1_MEMINFO_TYPE_NVIDIA) = state;
	return 0;
}

static void free_nvidia_pinning_interface(struct hfi1_user_sdma_pkt_q *pq)
{
	struct nvidia_pq_state *state = PINNING_STATE(pq, HFI1_MEMINFO_TYPE_NVIDIA);
	struct nvidia_pintree *pintree;
	struct hlist_node *tmp;
	size_t bucket_index;

	/*
	 * The pinning interface must not be cleaned up while it is still in
	 * use, so there is no need to acquire the state lock before
	 * accessing the hash table as this call is now the only accessor.
	 */
	lockdep_assert_not_held(&state->lock);

	hash_for_each_safe(state->pintree_hash, bucket_index, tmp, pintree, hash_node)
		free_pintree(pintree);

	kmem_cache_free(pq_state_kmem_cache, state);
}

static void free_nvidia_node_from_cb(struct nvidia_pintree_node *node)
{
	struct nvidia_pintree *pintree = node->pintree;
	struct nvidia_pq_state *state = pintree->state;
	struct hfi1_user_sdma_pkt_q *pq = state->pq;
	int result;

	/* If this happens, we will spin indefinitely. */
	WARN_ON(atomic_read(&node->refcount) < 0);

	/*
	 * Spin until I/O is done.
	 */
	while (atomic_read(&node->refcount) > 0)
		rep_nop();

	result = rdma_interface.free_dma_mapping(node->mapping);
	if (result) {
		dd_dev_err(pq->dd, "nvidia_p2p_free_dma_mapping failed: %lx-%lx\n",
			   node->node.start, node->node.last);
	}

	result = rdma_interface.free_page_table(node->page_table);
	if (result) {
		dd_dev_err(pq->dd, "nvidia_p2p_free_page_table failed: %lx-%lx\n",
			   node->node.start, node->node.last);
	}

	kfree(node);
}

/*
 * This is the free callback passed to nvidia_p2p_get_pages.
 *
 * Should not be called in an interrupt context but that is out of our control.
 */
static void remove_nvidia_pages(void *data)
{
	struct nvidia_pintree_node *node = data;
	struct nvidia_pintree_node *found;
	struct interval_tree_node *found_node;
	struct nvidia_pintree *pintree = node->pintree;
	struct nvidia_pq_state *state = pintree->state;

	WARN_ON(in_interrupt());

	/* Remove from the tree so that it's not found anymore. */
	spin_lock(&pintree->lock);

	trace_hfi1_nvidia_node_invalidated(node, 0);

	found_node = interval_tree_iter_first(&pintree->root, node->node.start, node->node.last);
	found = container_of(found_node, struct nvidia_pintree_node, node);
	if (found == node) {
		interval_tree_remove(&node->node, &pintree->root);
		list_del(&node->lru_node);
		pintree->size -= node->size;
		pintree->external_evictions++;
		spin_unlock(&pintree->lock);
		free_nvidia_node_from_cb(node);
	} else {
		BUG_ON(!node->inserted);
		/*
		 * This can happen during free_nvidia_pinning_interface() if
		 * the Nvidia driver calls remove_nvidia_pages() for a pintree
		 * node that cleanup_...() has removed from the tree but hasn't
		 * yet called put_pages() for.  As cleanup_...() does not free
		 * the node until after it calls put_pages(), the node will
		 * always still be valid through this point.  However, there is
		 * no further work to be done here in this case.
		 */
		spin_unlock(&pintree->lock);
		PIN_PQ_DBG(state->pq, ": node %p not found in %s: found %p",
			   node, __func__, found);
	}
}

static int insert_nvidia_pinning(struct nvidia_pintree *pintree,
				 struct nvidia_pintree_node *node)
{
	struct interval_tree_node *existing;
	int result = 0;

	spin_lock(&pintree->lock);
	/*
	 * The lookup is required because interval trees can support overlap,
	 * but we don't want overlap here.
	 */
	existing = interval_tree_iter_first(&pintree->root, node->node.start, node->node.last);
	if (existing) {
		result = -EEXIST;
	} else {
		interval_tree_insert(&node->node, &pintree->root);
		list_add_tail(&node->lru_node, &pintree->lru_list);
		pintree->size += node->size;
		node->inserted = 1;
	}
	trace_hfi1_nvidia_node_insert(node, result);
	spin_unlock(&pintree->lock);
	return result;
}

static void unpin_nvidia_node(struct nvidia_pintree_node *node)
{
	struct nvidia_pintree *pintree = node->pintree;
	struct nvidia_pq_state *state = pintree->state;
	struct hfi1_user_sdma_pkt_q *pq = state->pq;
	int result;

	/* There must be no I/O referencing this node. */
	WARN_ON(atomic_read(&node->refcount) != 0);

	PIN_PQ_DBG(pq, "unmapping node pages");
	result = rdma_interface.dma_unmap_pages(state->hfi_dev,
						node->page_table, node->mapping);
	WARN_ON(result);
	PIN_PQ_DBG(pq, "putting node pages");
	result = rdma_interface.put_pages(/* uint64_t p2p_token */ 0, /* va_space_token */ 0,
					  node->node.start, node->page_table);
	WARN_ON(result);
}

static bool evict_nvidia_pinnings(struct nvidia_pintree *pintree, size_t goal, bool internal)
{
	struct nvidia_pintree_node *cur;
	struct nvidia_pintree_node *tmp;
	struct list_head evict_list;
	size_t *stat;
	size_t total;

	INIT_LIST_HEAD(&evict_list);
	stat = internal ? &pintree->internal_evictions : &pintree->external_evictions;

	total = 0;
	spin_lock(&pintree->lock);
	list_for_each_entry_safe(cur, tmp, &pintree->lru_list, lru_node) {
		if (atomic_read(&cur->refcount) == 0) {
			trace_hfi1_nvidia_node_evict(cur, 0);

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
		unpin_nvidia_node(cur);
		kfree(cur);
	}

	return total >= goal;
}

static int pin_region(struct nvidia_pintree *pintree,
		      u64 start, u64 last,
		      struct nvidia_pintree_node *node)
{
	struct nvidia_pq_state *state = pintree->state;
	size_t len;
	int result;
	bool retry = true;

	len = (last + 1) - start;
retry:
	result = rdma_interface.get_pages(/* uint64_t p2p_token */ 0, /* va_space_token */ 0,
					  start, len, &node->page_table, remove_nvidia_pages, node);

	if (result != 0) {
		dd_dev_err(state->pq->dd, "node %p nvidia get_pages failed with %d",
			   node, result);
	} else {
		result = rdma_interface.dma_map_pages(state->hfi_dev, node->page_table,
						      &node->mapping);
		if (result != 0) {
			int r;

			dd_dev_err(state->pq->dd, "node %p nvidia map_pages failed with %d",
				   node, result);
			r = rdma_interface.put_pages(/* uint64_t p2p_token */ 0,
						     /* va_space_token */ 0,
						     start, node->page_table);
			WARN_ON(r);
		}
	}
	if ((result == -ENOMEM) && retry) {
		retry = false;
		if (evict_nvidia_pinnings(pintree, len, false))
			goto retry;
	}

	trace_hfi1_nvidia_node_pin(node, start, last, result);

	if (result != 0)
		return result;

	/*
	 * We use page_size_type as an index into the nvidia_page_shift array;
	 * verify value is in bounds.
	 */
	if (WARN_ON((unsigned int)node->mapping->page_size_type >= NVIDIA_P2P_PAGE_SIZE_COUNT)) {
		unpin_nvidia_node(node);
		return -EINVAL;
	}

	node->node.start = start;
	node->node.last = last;
	node->size = len;
	/*
	 * Initial refcount of 1 prevents node from being evicted as LRU while
	 * user_sdma request is being processed.
	 */
	atomic_set(&node->refcount, 1);

	result = insert_nvidia_pinning(pintree, node);
	if (result)
		unpin_nvidia_node(node);

	return result;
}

static int add_nvidia_pinning(struct nvidia_pintree *pintree,
			      struct nvidia_pintree_node **node_p,
			      u64 start, u64 last,
			      size_t tree_size)

{
	u64 first_page;
	u64 page_after_last_page;
	struct nvidia_pintree_node *node;
	size_t len;
	size_t limit;
	int ret;

	len = (last + 1) - start;
	limit = nvidia_cache_size * 1024 * 1024 / NVIDIA_PIN_CACHES_PER_GPU;
	if (tree_size + len > limit) {
		if (!evict_nvidia_pinnings(pintree, tree_size + len - limit, true))
			return -ENOMEM;
	}

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->pintree = pintree;
	first_page = (u64)start & NVIDIA_PAGE_MASK;
	page_after_last_page =
		(u64)((start + len) + NVIDIA_PAGE_OFFSET_MASK) & NVIDIA_PAGE_MASK;

	ret = pin_region(pintree, first_page, page_after_last_page - 1, node);
	if (ret == 0)
		*node_p = node;
	else
		kfree(node);

	return ret;
}

static struct nvidia_pintree_node *find_nvidia_pinning(struct nvidia_pintree *pintree,
						       u64 start, u64 last,
						       size_t *tree_size)
{
	struct interval_tree_node *tree_node;
	struct nvidia_pintree_node *node = NULL;

	spin_lock(&pintree->lock);
	tree_node = interval_tree_iter_first(&pintree->root, start, last);
	if (tree_node) {
		node = container_of(tree_node, struct nvidia_pintree_node, node);
		list_move_tail(&node->lru_node, &pintree->lru_list);
		/*
		 * Add the reference count to avoid the node disappearing
		 * while we are processing it.
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

static int get_cache_entry(struct nvidia_pintree *pintree,
			   struct nvidia_pintree_node **node_p,
			   u64 start, u64 len)
{
	int ret;
	u64 last;

	if (len == 0)
		return -EINVAL;

	last = (start + len) - 1;

	while (1) {
		size_t tree_size;
		struct nvidia_pintree_node *node = find_nvidia_pinning(pintree, start, last,
								       &tree_size);
		if (!node) {
			ret = add_nvidia_pinning(pintree, node_p, start, last, tree_size);
			if (ret == -EEXIST) {
				/*
				 * Another CPU has inserted a conflicting
				 * entry first.
				 */
				continue;
			}
			return ret;
		}

		if (WARN_ON(atomic_read(&node->refcount) < 1))
			return -EIO;

		if (node->node.start <= start) {
			*node_p = node;
			return 0;
		}

		/*
		 * This node will not be returned, instead a new node will be
		 * allocated to cover the [start, node->node.start) gap. But
		 * hold onto node until after we've used node->node.start in
		 * this call.
		 */
		ret = add_nvidia_pinning(pintree, node_p, start, node->node.start - 1,
					 tree_size);

		atomic_dec(&node->refcount);
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

static void nvidia_node_get(void *ctx)
{
	struct nvidia_pintree_node *n = ctx;

	atomic_inc(&n->refcount);
}

static void nvidia_node_put(void *ctx)
{
	struct nvidia_pintree_node *n = ctx;

	atomic_dec(&n->refcount);
}

static int add_nvidia_mapping_to_sdma_packet(struct hfi1_user_sdma_pkt_q *pq,
					     struct user_sdma_txreq *tx,
					     struct nvidia_pintree_node *cache_entry,
					     size_t start, size_t from_this_cache_entry)
{
	unsigned int page_offset;
	unsigned int from_this_page;
	size_t page_index;
	size_t dma_start;
	void *ctx;
	int ret;

	while (from_this_cache_entry) {
		page_index = (start - cache_entry->node.start) >>
				NVIDIA_PAGE_SHIFT_X(cache_entry->mapping->page_size_type);
		page_offset =
			start & NVIDIA_PAGE_OFFSET_MASK_X(cache_entry->mapping->page_size_type);
		from_this_page =
			NVIDIA_PAGE_SIZE_X(cache_entry->mapping->page_size_type) - page_offset;
		if (from_this_page > from_this_cache_entry)
			from_this_page = from_this_cache_entry;

		dma_start = cache_entry->mapping->dma_addresses[page_index] + page_offset;
		ctx = (from_this_page < from_this_cache_entry) ? NULL : cache_entry;

		ret = sdma_txadd_daddr(pq->dd, &tx->txreq, dma_start,
				       from_this_page, ctx, nvidia_node_get,
				       nvidia_node_put);

		if (ret) {
			/*
			 * When there's a failure, the entire request is freed
			 * by user_sdma_send_pkts().
			 */
			return ret;
		}
		start += from_this_page;
		from_this_cache_entry -= from_this_page;
	}
	return 0;
}

static int add_nvidia_iovec_to_sdma_packet(struct nvidia_pq_state *state,
					   struct user_sdma_request *req,
					   struct user_sdma_txreq *tx,
					   struct user_sdma_iovec *iovec,
					   size_t from_this_iovec)
{
	struct nvidia_pintree *pintree;
	u32 device_id;

	device_id = iovec->context;
	pintree = get_nvidia_pintree(state, device_id);
	if (!pintree)
		return -ENOMEM;

	while (from_this_iovec > 0) {
		struct nvidia_pintree_node *cache_entry;
		size_t from_this_cache_entry;
		size_t start;
		int ret;

		start = (uintptr_t)iovec->iov.iov_base + iovec->offset;
		ret = get_cache_entry(pintree, &cache_entry, start, from_this_iovec);
		if (ret) {
			SDMA_DBG(req, "SDMA pin nvidia segment failed %d", ret);
			return ret;
		}

		from_this_cache_entry = (cache_entry->node.last + 1) - start;
		if (from_this_cache_entry > from_this_iovec)
			from_this_cache_entry = from_this_iovec;

		ret = add_nvidia_mapping_to_sdma_packet(req->pq, tx, cache_entry,
							start, from_this_cache_entry);
		/*
		 * sdma_txadd_daddr() will have taken 1 or more references to
		 * cache_entry; release the reference taken to prevent
		 * cache_entry from being destroyed up until now.
		 */
		atomic_dec(&cache_entry->refcount);

		if (ret) {
			SDMA_DBG(req, "SDMA txreq add nvidia segment failed %d", ret);
			return ret;
		}

		iovec->offset += from_this_cache_entry;
		from_this_iovec -= from_this_cache_entry;
	}

	return 0;
}

static int add_nvidia_pages_to_sdma_packet(struct user_sdma_request *req,
					   struct user_sdma_txreq *tx,
					   struct user_sdma_iovec *iovec,
					   u32 *pkt_data_remaining)
{
	struct nvidia_pq_state *state = PINNING_STATE(req->pq, HFI1_MEMINFO_TYPE_NVIDIA);
	size_t remaining_to_add;

	/*
	 * Walk through iovec entries, ensure the associated pages are
	 * pinned and mapped, add data to the packet until no more
	 * data remains to be added or the iovec entry type changes.
	 */
	remaining_to_add = *pkt_data_remaining;
	while ((remaining_to_add > 0) && (iovec->type == HFI1_MEMINFO_TYPE_NVIDIA)) {
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

		ret = add_nvidia_iovec_to_sdma_packet(state, req, tx, cur_iovec, from_this_iovec);
		if (ret)
			return ret;

		remaining_to_add -= from_this_iovec;
	}
	*pkt_data_remaining = remaining_to_add;

	return 0;
}

static int get_nvidia_stats(struct hfi1_user_sdma_pkt_q *pq, int index,
			    struct hfi1_pin_stats *stats)
{
	struct nvidia_pq_state *state = PINNING_STATE(pq, HFI1_MEMINFO_TYPE_NVIDIA);
	struct nvidia_pintree *pintree;
	u64 next = 0;
	struct interval_tree_node *interval_node;
	unsigned int num_caches;

	spin_lock(&state->lock);
	num_caches = state->num_pintrees;
	spin_unlock(&state->lock);

	if (index == -1) {
		stats->index = num_caches;
		return 0;
	}

	if (index < 0 || index >= num_caches)
		return -EINVAL;

	pintree = get_nth_nvidia_pintree(state, index);
	if (!pintree)
		return -EINVAL;

	stats->id = pintree->device_id;
	while ((interval_node = interval_tree_iter_first(&pintree->root, next, ~0UL - next))) {
		struct nvidia_pintree_node *node =
			container_of(interval_node, struct nvidia_pintree_node, node);
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

static struct pinning_interface nvidia_pinning_interface = {
	.init = init_nvidia_pinning_interface,
	.free = free_nvidia_pinning_interface,
	.add_to_sdma_packet = add_nvidia_pages_to_sdma_packet,
	.get_stats = get_nvidia_stats,
};

void register_nvidia_pinning_interface(void)
{
	const char *err_str;
	char name_buf[64];

#define GET_SYMBOL(name)					\
	rdma_interface.name = symbol_get(nvidia_p2p_##name);	\
	if (!rdma_interface.name) {				\
		err_str = "missing symbol nvidia_p2p_"#name;	\
		goto fail;					\
	}

	GET_SYMBOL(free_page_table);
	GET_SYMBOL(free_dma_mapping);
	GET_SYMBOL(dma_map_pages);
	GET_SYMBOL(dma_unmap_pages);
	GET_SYMBOL(put_pages);
	GET_SYMBOL(get_pages);

#undef GET_SYMBOL

	snprintf(name_buf, sizeof(name_buf), "hfi1-nvidia-pq-state-kmem-cache");
	pq_state_kmem_cache = kmem_cache_create(name_buf,
						sizeof(struct nvidia_pq_state),
						cache_line_size(),
						0,
						NULL);
	if (!pq_state_kmem_cache) {
		err_str = "failed to allocate pq state pool";
		goto fail;
	}

	snprintf(name_buf, sizeof(name_buf), "hfi1-nvidia-pintree-kmem-cache");
	pintree_kmem_cache = kmem_cache_create(name_buf,
					       sizeof(struct nvidia_pintree),
					       cache_line_size(),
					       0,
					       NULL);
	if (!pintree_kmem_cache) {
		err_str = "failed to allocate pintree pool";
		goto fail;
	}

	register_pinning_interface(HFI1_MEMINFO_TYPE_NVIDIA, &nvidia_pinning_interface);
	pr_info("%s Nvidia p2p DMA support enabled\n", class_name());
	return;
fail:
	deregister_nvidia_pinning_interface();
	pr_info("%s Nvidia p2p DMA support disabled (%s)\n", class_name(), err_str);
}

void deregister_nvidia_pinning_interface(void)
{
	deregister_pinning_interface(HFI1_MEMINFO_TYPE_NVIDIA);

	kmem_cache_destroy(pintree_kmem_cache);
	pintree_kmem_cache = NULL;
	kmem_cache_destroy(pq_state_kmem_cache);
	pq_state_kmem_cache = NULL;

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
