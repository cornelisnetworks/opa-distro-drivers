// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2025 - Cornelis Networks, Inc.
 */

#ifndef _HFI1_MEM_REGION_H
#define _HFI1_MEM_REGION_H

#include "mmu_rb.h"
#include <linux/types.h>

struct hfi1_mem_region {
	struct mmu_rb_node rb;
	struct page **pages;
	dma_addr_t *dma_list;
	unsigned int npages_total;
	unsigned int npages_pinned;
};

int init_bulksvc_mmu(struct hfi1_bulksvc_user_info *uinfo);
int uninit_bulksvc_mmu(struct hfi1_bulksvc_user_info *uinfo);

struct hfi1_mem_region *hfi1_mem_region_pin(struct mmu_rb_handler *handler,
					    uintptr_t vaddr, u64 len);

// return 0 (success) if the requested pages have been pinned.
// return -1 otherwise
int hfi1_mem_region_pinned_check(struct hfi1_mem_region *mr, unsigned int start_page_index, unsigned int npages_to_request);

static inline void hfi1_mem_region_put(struct hfi1_mem_region *mr) {
	kref_put(&mr->rb.refcount, hfi1_mmu_rb_release);
}

#endif /* _HFI1_MEM_REGION_H */