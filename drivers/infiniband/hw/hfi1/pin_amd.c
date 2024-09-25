// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2022 - Cornelis Networks, Inc.
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kref.h>
#include <linux/refcount.h>
#include <linux/workqueue.h>

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

static unsigned int amd_use_cache = 1;
module_param(amd_use_cache, uint, 0444);
MODULE_PARM_DESC(amd_use_cache, "Enabled: use user SDMA ROCm VA:DMA cache when handling user SDMA requests. Disabled: do not use ROCm VA:DMA cache; do rdma_get_pages()/rdma_put_pages() for each (iovec,VA) in user SDMA request.");

static unsigned int amd_use_mmu = 1;
module_param(amd_use_mmu, uint, 0444);
MODULE_PARM_DESC(amd_use_mmu, "Enabled: use mmu_notifier to maintain user SDMA ROCm VA:DMA cache; not applicable when amd_use_cache=0. Disabled: do not use mmu_notifier to maintain user SDMA ROCm VA:DMA cache; do not use with amd_use_cache=1.");

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
	/*
	 * Number of existing nodes that reference this pintree; wait to reach zero
	 * before destroying pintree.
	 */
	refcount_t ref;

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
	/* There are two groups of ref holders: the pintree and SDMA descriptors */
	struct kref ref;

	/* For rdma_put_pages() queued from interrupt context */
	struct execute_work cleanup_work;

	/* For mmu_interval_notifier notifications on ROCm VA range */
	struct mmu_interval_notifier notifier;
	bool in_mmu;
	bool in_cache;
};

static const struct amd_rdma_interface *rdma_ops;
static struct kmem_cache *pq_state_kmem_cache;
static struct kmem_cache *pintree_kmem_cache;

static bool amd_mmu_invalidate_cb(struct mmu_interval_notifier *mni,
				  const struct mmu_notifier_range *range,
				  unsigned long cur_seq);

static struct mmu_interval_notifier_ops mmu_ops = {
	.invalidate = amd_mmu_invalidate_cb,
};

/**
 * Must be called in concurrency-safe context w.r.t. @*n
 */
static int amd_node_mmu_register(struct amd_pintree_node *n)
{
	int ret;

	if (!amd_use_mmu)
		return 0;

	/* Double-insert should not happen */
	if (WARN_ON(n->in_mmu))
		return -EINVAL;

	ret = mmu_interval_notifier_insert(&n->notifier, current->mm, n->node.start,
					   n->size, &mmu_ops);
	if (ret)
		return ret;
	n->in_mmu = true;
	return 0;
}

/**
 * Must be called in concurrency-safe (single CPU, inside critical-section)
 * context w.r.t. @*n.
 */
static void amd_node_mmu_unregister(struct amd_pintree_node *n)
{
	if (!amd_use_mmu)
		return;

	if (n->in_mmu) {
		mmu_interval_notifier_remove(&n->notifier);
		n->in_mmu = false;
	}
}

/**
 * Must call holding @n->pintree->lock.
 *
 * @n node to remove
 * @list to move @n->lru_node to if @list is non-NULL
 * @external_eviction count this removal as an external eviction in
 *                    @n->pintree->external_evictions?
 */
static bool _amd_pintree_remove(struct amd_pintree_node *n, struct list_head *list,
				bool external_eviction)
{
	struct amd_pintree *cache = n->pintree;

	if (!n->in_cache)
		return false;

	interval_tree_remove(&n->node, &cache->root);
	if (list)
		list_move(&n->lru_node, list);
	else
		list_del(&n->lru_node);
	n->in_cache = false;
	cache->size -= n->size;
	if (external_eviction)
		cache->external_evictions++;

	return true;
}

/**
 * Must call holding @n->pintree->lock.
 */
static void amd_pintree_remove(struct amd_pintree_node *n, struct list_head *list)
{
	_amd_pintree_remove(n, list, false);
}

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
	/* One ref taken for the pq/state */
	refcount_set(&pintree->ref, 1);
	pintree->state = state;
	pintree->device_id = device_id;

	spin_lock(&state->lock);
	hash_add(state->pintree_hash, &pintree->hash_node, device_id);
	spin_unlock(&state->lock);

	return pintree;
}

static unsigned long get_dma_addr(struct amd_pintree_node *n)
{
	return sg_dma_address(n->p2p_info->pages->sgl);
}

static unsigned long get_dma_len(struct amd_pintree_node *n)
{
	struct sg_table *sgt = n->p2p_info->pages;
	struct scatterlist *sg;
	unsigned long l = 0;
	int i;

	for_each_sgtable_sg(sgt, sg, i)
		l += sg_dma_len(sg);

	return l;
}

static void unpin_amd_node(struct amd_pintree_node *node)
{
	struct amd_pintree *pintree = node->pintree;
	struct amd_pq_state *state = pintree->state;
	struct hfi1_user_sdma_pkt_q *pq = state->pq;
	/* Save off VA, DMA for tracing after memory is freed */
	unsigned long va, va_len;
	unsigned long dma, dma_len;
	int ret;

	if (!node->p2p_info)
		return;

	va = node->p2p_info->va;
	va_len = node->p2p_info->size;
	dma = get_dma_addr(node);
	dma_len = get_dma_len(node);

	ret = rdma_ops->put_pages(&node->p2p_info);
	node->p2p_info = NULL;
	trace_unpin_sdma_pages_gpu(pintree, HFI1_MEMINFO_TYPE_AMD, ret, node, va, va_len,
				   dma, dma_len);

	if (ret)
		dd_dev_info(pq->dd, "ROCmRDMA put_pages() failed while unwinding pinning: %d\n",
			    ret);
}

/*
 * pintree->ref will prevent cleanup_amd_pintree() from destroying pintree
 * until all deferred amd_pintree_node work has completed.
 */
static void free_amd_node(struct work_struct *work)
{
	struct amd_pintree_node *n = container_of(work, struct amd_pintree_node, cleanup_work.work);

	/*
	 * free_amd_node() is called by destructor triggered by final
	 * kref_put(&n->ref,...) and so will always be executed on one CPU.
	 * I.e. there should be no risk of concurrent access to node n.
	 *
	 * However, without locking here, the only thing that is guaranteed to
	 * be visible to the CPU executing free_amd_node() is n->ref.refcount.
	 * Other updates to *n made before the kref_put() may not be visible to
	 * this CPU. This is a particular risk if something like this happened:
	 *
	 * Begin: node n->ref.refcount=2
	 * CPU0                                      CPU1
	 * amd_mmu_invalidate_cb()
	 *   spin_lock(&n->lock)
	 *   interval_tree_remove(&n->node,...)
	 *   n->in_cache = false
	 *   spin_unlock(&n->lock)
	 *   kref_put(&n->ref,amd_node_kref_defer)
	 *   // refcount=1
	 *                                           // not changing
	 *                                           // anything on n so no
	 *                                           // lock needed, right?
	 *                                           kref_put(&n->ref,amd_node_kref_cb)
	 *                                           // refcount=0, destroy
	 *                                           amd_node_kref_cb()
	 *                                             if (n->in_cache)
	 *                                               // Bad things!
	 *                                               // in_cache is actually
	 *                                               // false but write not
	 *                                               // visible to CPU1
	 *
	 * So use a memory barrier here to make any changes to *n visible.
	 */
	smp_mb();

	amd_node_mmu_unregister(n);
	unpin_amd_node(n);
	refcount_dec(&n->pintree->ref);
	kfree(n);
}

/*
 * Process and interrupt context destructor.
 */
static void amd_node_kref_cb(struct kref *kref)
{
	struct amd_pintree_node *n = container_of(kref, struct amd_pintree_node, ref);

	execute_in_process_context(free_amd_node, &n->cleanup_work);
}

/**
 * kref destructor for amd_mmu_invalidate_cb().
 *
 * Calling mmu_interval_notifier_remove() under the mmu_interval_notifier
 * callback will deadlock. So defer destructor call that includes
 * mmu_interval_notifier_remove().
 */
static void amd_node_kref_defer(struct kref *kref)
{
	struct amd_pintree_node *n = container_of(kref, struct amd_pintree_node, ref);

	INIT_WORK(&n->cleanup_work.work, free_amd_node);
	schedule_work(&n->cleanup_work.work);
}

/**
 * AMD ROCm VA mmu_interval_notifier callback function.
 *
 * Must work correctly whether or not callback context object (struct
 * amd_pintree_node) is in the cache.
 *
 * struct amd_pintree_node reference-counting/lifetime management code must
 * also assume that amd_mmu_invalidate_cb() may never be called in the life of
 * a node.
 */
static bool amd_mmu_invalidate_cb(struct mmu_interval_notifier *mni,
				  const struct mmu_notifier_range *range,
				  unsigned long cur_seq)
{
	struct amd_pintree_node *n = container_of(mni, struct amd_pintree_node, notifier);
	struct amd_pintree *cache = n->pintree;
	bool removed;

	if (range->event != MMU_NOTIFY_UNMAP)
		return true;

	trace_invalidate_sdma_pages_gpu(cache, HFI1_MEMINFO_TYPE_AMD, n->node.start,
					n->size, n);

	spin_lock(&cache->lock);
	removed = _amd_pintree_remove(n, NULL, true);
	spin_unlock(&cache->lock);

	/*
	 * Cannot call mmu_interval_notifier_remove() in callback; defer
	 * possible destruction.
	 */
	if (removed)
		kref_put(&n->ref, amd_node_kref_defer);

	return true;
}

static void cleanup_amd_pintree(struct amd_pintree *pintree)
{
	struct amd_pq_state *state = pintree->state;
	struct hfi1_user_sdma_pkt_q *pq = state->pq;
	struct amd_pintree_node *n;

	PIN_PQ_DBG(pq, "enter");

	spin_lock(&state->lock);
	hash_del(&pintree->hash_node);
	spin_unlock(&state->lock);

	/* Release pintree refs to nodes still in cache */
	while (1) {
		spin_lock(&pintree->lock);
		if (list_empty(&pintree->lru_list)) {
			spin_unlock(&pintree->lock);
			break;
		}
		n = list_first_entry(&pintree->lru_list, struct amd_pintree_node, lru_node);
		amd_pintree_remove(n, NULL);
		spin_unlock(&pintree->lock);

		kref_put(&n->ref, amd_node_kref_cb);
	}

	PIN_PQ_DBG(pq, "spinning until no outstanding AMD SDMA nodes (current:%u)",
		   refcount_read(&pintree->ref));
	/*
	 * Wait for outstanding SDMA requests referencing nodes that reference
	 * pintree to complete. Only ref left will be for pq/state.
	 */
	while (refcount_read(&pintree->ref) > 1)
		cond_resched();

	PIN_PQ_DBG(pq, "all outstanding AMD SDMA nodes destroyed");

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

/**
 * Must call in context where n cannot be destroyed, i.e. another CPU cannot do
 * final kref_put(&n->ref,...).
 *
 * @return number of outstanding I/O ref holders to @n.
 */
static unsigned int outstanding_io(struct amd_pintree_node *n)
{
	unsigned int c = kref_read(&n->ref);

	WARN_ON(!c);
	return (!c ? 0 : c - 1);
}

/**
 * Takes additional transaction "safety" kref with kref_get(&node->ref). This
 * prevents @node from being destroyed until after sdma_txadd_daddr() when any
 * per descriptor kref_get(&node->ref) should have been done.
 *
 * Safety ref should be kref_put() after all sdma_txadd_daddr() for @node.
 *
 * Safety ref not taken when function returns !0.
 */
static int insert_amd_pinning(struct amd_pintree *pintree, struct amd_pintree_node *node)
{
	struct interval_tree_node *existing;
	int result;

	if (!amd_use_cache)
		return 0;

	spin_lock(&pintree->lock);
	/*
	 * Register with mmu_notifier inside critical section so
	 * amd_mmu_invalidate_cb() cannot run until after spin_unlock() at the
	 * earliest.
	 *
	 * Destructor called by final kref_put() in caller's error-handling will
	 * call amd_node_mmu_unregister() in the event that this function
	 * returns an error.
	 */
	result = amd_node_mmu_register(node);
	if (result)
		goto unlock;

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
	kref_get(&node->ref);
	interval_tree_insert(&node->node, &pintree->root);
	list_add_tail(&node->lru_node, &pintree->lru_list);
	pintree->size += node->size;
	node->in_cache = true;

unlock:
	spin_unlock(&pintree->lock);
	return result;
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
		if (!outstanding_io(cur)) {
			amd_pintree_remove(cur, &evict_list);
			(*stat)++;
			total += cur->size;
			if (total >= goal)
				break;
		}
	}
	spin_unlock(&pintree->lock);

	list_for_each_entry_safe(cur, tmp, &evict_list, lru_node)
		kref_put(&cur->ref, amd_node_kref_cb);
	trace_evict_sdma_pages_gpu(pintree, HFI1_MEMINFO_TYPE_AMD, total, goal);

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
				     &node->p2p_info, NULL, node);

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
		node->p2p_info = NULL;
		return result;
	}

	node->node.start = start;
	node->node.last = last;
	node->size = len;

	return insert_amd_pinning(pintree, node);
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
		kref_get(&node->ref);
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

	/*
	 * When amd_use_cache is true, this ref becomes the cache's ref.
	 * When amd_use_cache is false, this ref is the safety ref that is
	 * kref_put() in add_amd_iovec_to_sdma_packet() after the pinning is
	 * added to all applicable SDMA descriptors.
	 */
	kref_init(&node->ref);
	node->pintree = pintree;
	refcount_inc(&pintree->ref);
	result = pin_amd_region(pintree, pid, start_page, end_page - 1, node);
	if (result)
		kref_put(&node->ref, amd_node_kref_cb);
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

			trace_pin_sdma_pages_gpu(pintree, HFI1_MEMINFO_TYPE_AMD, start,
						 last + 1 - start, ret, 0, *node_p,
						 (!ret ? get_dma_addr(*node_p) : 0),
						 (!ret ? get_dma_len(*node_p) : 0));

			return ret;
		}

		if (node->node.start <= start) {
			*node_p = node;
			trace_pin_sdma_pages_gpu(pintree, HFI1_MEMINFO_TYPE_AMD, start,
						 last + 1 - start, 0, 1, node,
						 get_dma_addr(node),
						 get_dma_len(node));

			return 0;
		}

		/*
		 * This node will not be returned, instead a new node will be.
		 * So release the safety ref.
		 */
		kref_put(&node->ref, amd_node_kref_cb);

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
		trace_pin_sdma_pages_gpu(pintree, HFI1_MEMINFO_TYPE_AMD, start,
					 (node->node.start - 1), ret, 0, *node_p,
					 (!ret ? get_dma_addr(*node_p) : 0),
					 (!ret ? get_dma_len(*node_p) : 0));

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
	kref_get(&((struct amd_pintree_node *)ctx)->ref);
}

static void amd_node_put(void *ctx)
{
	struct amd_pintree_node *n = ctx;

	kref_put(&n->ref, amd_node_kref_cb);
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
	if (!pintree) {
		SDMA_DBG(req, "Failed to get pintree");
		return -ENOMEM;
	}

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

		/*
		 * When amd_use_cache is true, this releases the safety ref.
		 * When amd_use_cache is false, this releases the kref that would have become the
		 * cache's ref.
		 */
		kref_put(&cache_entry->ref, amd_node_kref_cb);
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
		stats->total_refcounts += outstanding_io(node);
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
