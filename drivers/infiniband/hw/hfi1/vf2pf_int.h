/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 *
 * Internal defs for SRIOV support for VFs making requests to PF0.
 */

#ifndef _VF2PF_INT_H
#define _VF2PF_INT_H

#include "vf2pf.h"

/*
 * This selects the loopback port implementation for
 * VF-PF communication in SRIOV.
 */
#define HFI_VF2PF_LOOPBACK

enum {
	VF2PF_OP_PING = 0,
};

#define VF2PF_OP_RESP	0x80

/*
 * prefix area of 'msg' object to 'send', return from 'msg_alloc'.
 * must be qword multiple (following element aligned u64).
 */
struct vf2pf_prefix {
	u8 type;
	u8 _pad[7];
	union {
		wait_queue_head_t wait;	/* for sending requests */
		struct semaphore sema;	/* for sending MAD requests */
		struct {		/* for recvd requests */
			struct work_struct work;
			struct hfi1_devdata *dd;
			u32 len;
		};
	};
};

#define VF2PF_PFX_TYPE_RESP    0
#define VF2PF_PFX_TYPE_WAIT    1
#define VF2PF_PFX_TYPE_SEMA    2

struct vf2pf_hdr {
	u8 op;		/* response is ored with VF2PF_OP_RESP */
	u8 si;		/* sender SI - from */
	u16 len;	/* payload length, bytes (based on op) */
	s16 status;	/* -errno or 0 - valid on response */
	u16 tid;	/* tid for matching resp */
};

struct vf2pf_ping_msg {
	struct vf2pf_hdr hdr;
	u8 data[256];
};

struct vf2pf_devops {
	int num_ctxts;
	int num_irq;
	int (*init)(struct hfi1_devdata *dd, u8 si);
	void (*deinit)(struct hfi1_devdata *dd, u8 si);
	int (*send)(struct hfi1_devdata *dd, u8 si, void *msg);
	void *(*msg_alloc)(struct hfi1_devdata *dd, struct vf2pf_hdr **msg);
	u16 (*set_tid)(struct hfi1_devdata *dd, void *tok);
	void *(*get_tid)(struct hfi1_devdata *dd, u16 tid);
	struct vf2pf_hdr *(*get_msg)(struct hfi1_devdata *dd, void *buf);
	int (*probe_si)(struct hfi1_devdata *dd);
	void (*init_sysfs)(struct hfi1_devdata *dd, struct device *class_dev);
	int (*sysfs_emit_at)(struct hfi1_devdata *dd, char *buf, int at);
	int (*init_irq)(struct hfi1_devdata *dd);
	void (*deinit_irq)(struct hfi1_devdata *dd);
	int (*rcv_wait)(struct hfi1_devdata *dd, void *buf, long timeout);
	void (*set_si_enables)(struct hfi1_devdata *dd, int si, u64 *csrs,
			       void (*si_enables)(struct hfi1_devdata *dd,
						  u64 *csrs, u32 start, u32 end));
};

#define VF2PF_INIT_ALL	((u8)-1)

/* call-outs from implementations to vf2pf main */
void vf2pf_rcv_msg(struct hfi1_devdata *dd, struct vf2pf_hdr *hdr, void *msg);
void vf2pf_rsp_msg(struct hfi1_devdata *dd, void *buf);

#endif /* _VF2PF_INT_H */
