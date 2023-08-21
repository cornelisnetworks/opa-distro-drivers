/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2023 Cornelis Networks, Inc.
 */
#ifndef _HFI1_PIN_NVIDIA_H
#define _HFI1_PIN_NVIDIA_H

#include <linux/hashtable.h>

#include "hfi.h"

#include <nvidia/nv-p2p.h>

#define NVIDIA_MAX_DEVICES 16
#define NVIDIA_DEVICE_HASH_OVERSUBSCRIBE 2
#define NVIDIA_DEVICE_HASH_BITS ilog2(NVIDIA_MAX_DEVICES * NVIDIA_DEVICE_HASH_OVERSUBSCRIBE)

struct nvidia_pq_state {
	/* on its own cacheline */
	spinlock_t lock; /* protects num_pintrees and pintree_hash */

	/* new cacheline starts here */
	struct hfi1_user_sdma_pkt_q *pq ____cacheline_aligned_in_smp;
	struct pci_dev *hfi_dev;
	unsigned int num_pintrees;
	DECLARE_HASHTABLE(pintree_hash, NVIDIA_DEVICE_HASH_BITS);
};

struct nvidia_pintree {
	/* on its own cacheline */
	spinlock_t lock;

	/* new cacheline starts here */
	u32 device_id ____cacheline_aligned_in_smp;
	struct hlist_node hash_node;
	struct rb_root_cached root;
	struct list_head lru_list;
	struct nvidia_pq_state *state;
	size_t size;
	size_t hits;
	size_t misses;
	size_t internal_evictions;
	size_t external_evictions;
};

struct nvidia_pintree_node {
	struct interval_tree_node node;
	struct list_head lru_node;
	/* Needed to handle the driver calling back to free a pinned region. */
	struct nvidia_pintree *pintree;
	size_t size;

	/*
	 * These entries can't be combined because the table
	 * and mapping fields can't be combined. There's little
	 * value in building a list of these inside a combined node
	 * as there's little shared, and in the pathological case,
	 * it turns into one entry in the tree with all the pinnings
	 * in an attached linked list.
	 */
	struct nvidia_p2p_page_table *page_table;
	struct nvidia_p2p_dma_mapping *mapping;

	atomic_t refcount;

	/*
	 * For debug only; should only be read in pintree->lock critical
	 * section
	 */
	int inserted;
};

#endif /* _HFI1_PIN_NVIDIA_H */
