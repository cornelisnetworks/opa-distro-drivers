/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2025 Cornelis Networks, Inc.
 */
#ifndef _BULKSVC_NVIDIA_H
#define _BULKSVC_NVIDIA_H

#include <linux/dma-buf.h>

#include "bulksvc_user.h"

/* bulksvc-NVIDIA p2p/peermem copy support */

/*
 * TODO this is hacky; there's an enum passed in from userspace,
 * HFI1_HFISVC_HMEM_IFACE_CUDA, that can be used to tell the specific subtype.
 * But use this for now.
 */
static inline bool bulksvc_is_nvidia(struct dma_buf *dmabuf)
{
	return dmabuf && !dmabuf->ops->vmap;
}

#ifdef CONFIG_HFI1_NVIDIA_P2P_MEMCPY
int bulksvc_nvidia_init(void);
void bulksvc_nvidia_free(void);
int bulksvc_nvidia_pin(struct hfi1_bulksvc_nv_pt_info *nv_pt_info, uintptr_t vaddr, u64 len);
void bulksvc_unpin_nvidia(struct hfi1_bulksvc_nv_pt_info *nv_pt_info);
int bulksvc_nvidia_memcpy(struct hfi1_dms_mr *mr, u64 offset, u64 size,
			  void *data, const bool is_read);
#else
static inline int bulksvc_nvidia_init(void)
{
	return -EOPNOTSUPP;
}

static inline void bulksvc_nvidia_free(void)
{
}

static inline int bulksvc_nvidia_pin(struct hfi1_bulksvc_nv_pt_info *nv_pt_info, uintptr_t vaddr,
				     u64 len)
{
	return -EFAULT;
}

static inline void bulksvc_unpin_nvidia(struct hfi1_bulksvc_nv_pt_info *nv_pt_info)
{
}

static inline int bulksvc_nvidia_memcpy(struct hfi1_dms_mr *mr, u64 offset, u64 size,
					void *data, const bool is_read)
{
	return -EIO;
}
#endif /* CONFIG_HFI1_NVIDIA_P2P_MEMCPY */

#endif /* _BULKSVC_NVIDIA_H */
