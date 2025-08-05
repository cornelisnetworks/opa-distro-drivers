/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 */

#ifndef _HFI1_FILE_OPS_H
#define _HFI1_FILE_OPS_H

#include "hfi.h"

int hfi1_set_uevent_bits(struct hfi1_pportdata *ppd, const int evtbit);
int hfi1_device_create(struct hfi1_devdata *dd);
void hfi1_device_remove(struct hfi1_devdata *dd);
struct hfi1_filedata *hfi1_alloc_filedata(struct hfi1_devdata *dd);
void hfi1_dealloc_filedata(struct hfi1_filedata *fdata);
int hfi1_do_assign_ctxt(struct hfi1_filedata *fd,
			const struct hfi1_assign_ctxt_cmd *uinfo);
int manage_rcvq(struct hfi1_ctxtdata *uctxt, u16 subctxt, int start_stop);
int user_event_ack(struct hfi1_ctxtdata *uctxt, u16 subctxt,
		   unsigned long events);
int set_ctxt_pkey(struct hfi1_ctxtdata *uctxt, u16 pkey);
int ctxt_reset(struct hfi1_ctxtdata *uctxt);
int hfi1_get_pinning_stats(struct hfi1_filedata *fd,
			   struct hfi1_pin_stats *stats);
int hfi1_do_mmap(struct hfi1_filedata *fd, u8 type, struct vm_area_struct *vma);
ssize_t hfi1_do_write_iter(struct hfi1_filedata *fd, struct iov_iter *from);

/*
 * Types of memories mapped into user processes' space
 */
enum mmap_types {
	PIO_BUFS = 1,
	PIO_BUFS_SOP,
	PIO_CRED,
	RCV_HDRQ,
	RCV_EGRBUF,
	UREGS,
	EVENTS,
	STATUS,
	RTAIL,
	SUBCTXT_UREGS,
	SUBCTXT_RCV_HDRQ,
	SUBCTXT_EGRBUF,
	SDMA_COMP,
	RCV_RHEQ,
	BULKSVC_CMPLQ_CTRL,
	BULKSVC_CMPLQ_BUF,
	BULKSVC_CMDQ_CTRL,
	BULKSVC_CMDQ_BUF,
};

#endif /* _HFI1_FILE_OPS_H */
