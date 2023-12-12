/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2020-2024 Cornelis Networks, Inc.
 * Copyright(c) 2016 - 2017 Intel Corporation.
 * Copyright(c) 2016 Intel Corporation.
 */

#ifndef _HFI1_MMU_RB_H
#define _HFI1_MMU_RB_H

#include "hfi.h"

struct mmu_rb_node {
	unsigned long addr;
	unsigned long len;
	unsigned long __last;
	struct rb_node node;
	struct mmu_rb_handler *handler;
	struct list_head list;
	struct kref refcount;
};

/* filter and evict must not sleep. Only remove is allowed to sleep. */
struct mmu_rb_ops {
	bool (*filter)(struct mmu_rb_node *node, unsigned long addr,
		       unsigned long len);
/* For hfi1-GDRCopy */
#ifdef NVIDIA_GPU_DIRECT
	int (*insert)(void *ops_arg, struct mmu_rb_node *mnode);
#endif
	void (*remove)(void *ops_arg, struct mmu_rb_node *mnode);
/* For hfi1-GDRCopy */
#ifdef NVIDIA_GPU_DIRECT
	int (*invalidate)(void *ops_arg, struct mmu_rb_node *node);
#endif
	int (*evict)(void *ops_arg, struct mmu_rb_node *mnode,
		     void *evict_arg, bool *stop);
};

struct mmu_rb_handler {
	/*
	 * struct mmu_notifier is 56 bytes, and spinlock_t is 4 bytes, so
	 * they fit together in one cache line.  mn is relatively rarely
	 * accessed, so co-locating the spinlock with it achieves much of
	 * the cacheline contention reduction of giving the spinlock its own
	 * cacheline without the overhead of doing so.
	 */
	struct mmu_notifier mn;
	spinlock_t lock;        /* protect the RB tree */

	/* Begin on a new cachline boundary here */
	struct rb_root_cached root ____cacheline_aligned_in_smp;
	void *ops_arg;
	const struct mmu_rb_ops *ops;
	struct list_head lru_list;
	struct work_struct del_work;
	struct list_head del_list;
	struct workqueue_struct *wq;
	size_t hits;
	size_t misses;
	size_t internal_evictions;
	size_t external_evictions;
	void *free_ptr;
};

int hfi1_mmu_rb_register(void *ops_arg,
			 struct mmu_rb_ops *ops,
			 struct workqueue_struct *wq,
			 struct mmu_rb_handler **handler);
void hfi1_mmu_rb_unregister(struct mmu_rb_handler *handler);
int hfi1_mmu_rb_insert(struct mmu_rb_handler *handler,
		       struct mmu_rb_node *mnode);
void hfi1_mmu_rb_release(struct kref *refcount);

void hfi1_mmu_rb_evict(struct mmu_rb_handler *handler, void *evict_arg);
struct mmu_rb_node *hfi1_mmu_rb_get_first(struct mmu_rb_handler *handler,
					  unsigned long addr,
					  unsigned long len);
unsigned long hfi1_mmu_rb_for_n(struct mmu_rb_handler *handler,
				unsigned long start, int count,
				void (*fn)(const struct mmu_rb_node *rb_node, void *),
				void *arg);

/* For hfi1-GDRCopy */
#ifdef NVIDIA_GPU_DIRECT
void hfi1_mmu_rb_remove(struct mmu_rb_handler *handler,
			struct mmu_rb_node *mnode);
int hfi1_mmu_rb_register_gpu(void *ops_arg,
			     struct mmu_rb_ops *ops,
			     struct workqueue_struct *wq,
			     struct mmu_rb_handler **handler);
struct mmu_rb_node *hfi1_mmu_rb_first_cached(struct mmu_rb_handler *handler);
struct mmu_rb_node *hfi1_mmu_rb_search_addr(struct mmu_rb_handler *handler,
					    unsigned long addr,
					    unsigned long len);
void hfi1_gpu_cache_invalidate(struct mmu_rb_handler *handler,
			       unsigned long start, unsigned long end);
#endif /* NVIDIA_GPU_DIRECT */

#endif /* _HFI1_MMU_RB_H */
