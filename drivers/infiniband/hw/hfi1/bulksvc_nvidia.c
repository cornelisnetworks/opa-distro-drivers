// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2025 Cornelis Networks, Inc.
 */

#include <linux/types.h>
#include <nvidia/nv-p2p.h>

#include "bulksvc_nvidia.h"

#ifdef CONFIG_HFI1_NVIDIA_P2P_MEMCPY_SOFTDEP
MODULE_SOFTDEP("pre: nvidia");
#endif

#define GPU_PAGE_SHIFT 16
#define GPU_PAGE_SIZE BIT(GPU_PAGE_SHIFT)
#define GPU_PAGE_MASK (~(GPU_PAGE_SIZE - 1))

static struct nvidia_rdma_ops {
	int (*free_page_table)(struct nvidia_p2p_page_table *page_table);
	int (*get_pages_persistent)(u64 virtual_address, u64 length,
				    struct nvidia_p2p_page_table **page_table,
				    u32 flags);
	int (*put_pages_persistent)(u64 virtual_address, struct nvidia_p2p_page_table *page_table,
				    u32 flags);
} rdma_ops;

/**
 * Initialize bulksvc_nvidia.
 *
 * Returns: 0 on success, -EOPNOTSUPP if getting nvidia symbols failed.
 */
int bulksvc_nvidia_init(void)
{
#define GET_SYMBOL(name)					\
	do {							\
		rdma_ops.name = symbol_get(nvidia_p2p_##name);	\
		if (!rdma_ops.name)				\
			goto fail;				\
	} while (0)
	GET_SYMBOL(free_page_table);
	GET_SYMBOL(get_pages_persistent);
	GET_SYMBOL(put_pages_persistent);
#undef GET_SYMBOL
	pr_info("bulksvc: NVIDIA P2P support enabled\n");
	return 0;
fail:
	bulksvc_nvidia_free();
	pr_info("bulksvc: NVIDIA P2P support disabled\n");
	return -EOPNOTSUPP;
}

void bulksvc_nvidia_free(void)
{
#define PUT_SYMBOL(name)				\
	do {						\
		if (rdma_ops.name)			\
			symbol_put(nvidia_p2p_##name);  \
		rdma_ops.name = NULL;			\
	} while (0)
	PUT_SYMBOL(free_page_table);
	PUT_SYMBOL(get_pages_persistent);
	PUT_SYMBOL(put_pages_persistent);
#undef PUT_SYMBOL
}

int bulksvc_nvidia_pin(struct hfi1_bulksvc_nv_pt_info *nv_pt_info, uintptr_t vaddr, u64 len)
{
	u64 start = ALIGN_DOWN(vaddr, GPU_PAGE_SIZE);
	u64 end = ALIGN(vaddr + len, GPU_PAGE_SIZE);
	int ret;

	if (!nv_pt_info)
		return -EINVAL;
	if (!rdma_ops.get_pages_persistent || !rdma_ops.put_pages_persistent)
		return -EOPNOTSUPP;
	if (WARN_ON(start == end))
		return -EINVAL;

	nv_pt_info->nv_start = start;
	nv_pt_info->nv_end = end;
	ret = rdma_ops.get_pages_persistent(start, end - start, &nv_pt_info->nv_pt,
					    NVIDIA_P2P_FLAGS_DEFAULT);

	/*
	 * On error after &umr->mem_region.nv_pt is assigned-to, nvidia frees
	 * the memory but does not NULL out *page_table. So NULL out here to
	 * avoid double-free.
	 */
	if (ret)
		nv_pt_info->nv_pt = NULL;

	if (WARN_ON(!NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE(nv_pt_info->nv_pt))) {
		rdma_ops.put_pages_persistent(start, nv_pt_info->nv_pt,
					      NVIDIA_P2P_FLAGS_DEFAULT);
		nv_pt_info->nv_pt = NULL;
		return -EIO;
	}
	return ret;
}

void bulksvc_unpin_nvidia(struct hfi1_bulksvc_nv_pt_info *nv_pt_info)
{
	if (!nv_pt_info || !nv_pt_info->nv_pt)
		return;

	WARN_ON(rdma_ops.put_pages_persistent(nv_pt_info->nv_start, nv_pt_info->nv_pt, 0));
	nv_pt_info->nv_pt = NULL;
}

/**
 */
int bulksvc_nvidia_memcpy(struct hfi1_dms_mr *mr, u64 offset, u64 size,
			  void *data, const bool is_read)
{
	struct hfi1_bulksvc_user_mr_record *umr;
	struct nvidia_p2p_page_table *pt;
	u64 vaddr;
	u64 start;
	u64 end;
	u64 gpu_off;

	if (WARN_ON(!mr))
		return -EINVAL;
	if (WARN_ON(!size))
		return -EINVAL;

	umr = container_of(mr, struct hfi1_bulksvc_user_mr_record, dms_mr);
	if (WARN_ON(umr->mr_type != HFI1_BULKSVC_MR_TYPE_DMABUF))
		return -EINVAL;

	if (WARN_ON(umr->mem_region.fixup_mapping_type != HFI1_BULKSVC_FIXUP_CPU_MAPPING_NVPT))
		return -EINVAL;

	pt = umr->mem_region.fixup_mapping.nv_pt_info->nv_pt;
	vaddr = mr->extended_vaddr.addr;
	start = umr->mem_region.fixup_mapping.nv_pt_info->nv_start;
	end = umr->mem_region.fixup_mapping.nv_pt_info->nv_end;
	gpu_off = vaddr + offset;
	if (WARN_ON(vaddr + offset + size >= end))
		return -EINVAL;

	/*
	 * GPU pages may not be physically contiguous. So must visit each page
	 * and determine if addresses are physically contiguous.
	 *
	 * Offset is relative to mr->extended_vaddr.addr. But
	 * GPU_PAGE_SIZE-aligned start may not be same as PAGE_SIZE aligned
	 * start. So compute pgidx based on difference between
	 * PAGE_SIZE-aligned vaddr+offset and GPU_PAGE_SIZE-aligned start.
	 */
	while (size) {
		phys_addr_t pa;
		u64 pgidx = (gpu_off - start) / GPU_PAGE_SIZE;
		u64 pgoff = gpu_off % GPU_PAGE_SIZE;
		u64 to_cpy;
		void __iomem *ipa;
		void *va;

		if (WARN_ON(pgidx >= pt->entries))
			return -EFAULT;

		pa = pt->pages[pgidx]->physical_address;
		ipa = ioremap(pa, GPU_PAGE_SIZE);
		va = ipa + pgoff;
		to_cpy = min(GPU_PAGE_SIZE - pgoff, size);
		if (WARN_ON(!to_cpy)) {
			iounmap(ipa);
			return -ENOMEM;
		}

		if (is_read)
			memcpy_fromio(data, va, to_cpy);
		else
			memcpy_toio(va, data, to_cpy);

		size -= to_cpy;
		gpu_off += to_cpy;
		data += to_cpy;
		iounmap(ipa);
	}

	return 0;
}
