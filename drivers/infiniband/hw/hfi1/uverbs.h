/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 */

#ifndef HFI1_UVERBS_H
#define HFI1_UVERBS_H

#include <rdma/uverbs_ioctl.h>

int hfi1_alloc_ucontext(struct ib_ucontext *ucontext, struct ib_udata *udata);
void hfi1_dealloc_ucontext(struct ib_ucontext *ucontext);
int hfi1_rdma_mmap(struct ib_ucontext *ucontext, struct vm_area_struct *vma);
ssize_t hfi1_uverbs_write_iter(struct ib_ucontext *ucontext,
			       struct iov_iter *from);

extern const struct uapi_definition hfi1_ib_defs[];

#endif /* HFI1_UVERBS_H */
