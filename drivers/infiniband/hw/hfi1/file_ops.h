/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 */

#ifndef _HFI1_FILE_OPS_H
#define _HFI1_FILE_OPS_H

#include "hfi.h"

#include "bulksvc_user.h"

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

int create_bulksvc_queue(struct hfi1_devdata* dd, struct hfi1_bulksvc_user_info* const bulksvc_user_info,
			 bool is_cmplq, bool is_uverbs,
			 struct hfi1_bulksvc_queue_info ** output_info);
int init_bulksvc_client(struct hfi1_filedata *fd,
			struct hfi1_bulksvc_client_init *out);
int do_bulksvc_synccmd(struct hfi1_filedata *fd,
		       struct hfi1_bulksvc_cmd *cmd);
int do_bulksvc_doorbell_mmap(struct hfi1_filedata *fd, struct vm_area_struct *vma);
int do_bulksvc_mmap(struct hfi1_bulksvc_user_info* info, int type,
		    struct vm_area_struct *vma);


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
	BULKSVC_FAST_DOORBELL,
	// Range of values reserved for each bulksvc queue-related mmap type
	BULKSVC_QUEUE_TYPES_FIRST,
	BULKSVC_CMPLQ_CTRL0 = BULKSVC_QUEUE_TYPES_FIRST,
	BULKSVC_CMPLQ_BUF0 = BULKSVC_CMPLQ_CTRL0 + BULKSVC_USER_MAX_NUM_CMPLQS,
	BULKSVC_CMDQ_CTRL0 = BULKSVC_CMPLQ_BUF0 + BULKSVC_USER_MAX_NUM_CMPLQS,
	BULKSVC_CMDQ_BUF0 = BULKSVC_CMDQ_CTRL0 + BULKSVC_USER_MAX_NUM_CMDQS,
	BULKSVC_QUEUE_TYPES_LAST = BULKSVC_CMDQ_BUF0 + BULKSVC_USER_MAX_NUM_CMDQS - 1,
	// End of range of values reserved for each bulksvc queue-related mmap type
};

#endif /* _HFI1_FILE_OPS_H */
