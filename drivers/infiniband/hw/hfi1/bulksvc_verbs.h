/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2025 Cornelis Networks.
 */
#ifndef DEF_HFI1_BULKSVC_VERBS_H
#define DEF_HFI1_BULKSVC_VERBS_H

#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "dms.h"

struct hfi1_bulksvc;

enum hfi1_bulksvc_verbs_write_flags {
	HFI1_BULKSVC_VERBS_WRITE_FLAGS_IMMDT = (1 << 0),
	HFI1_BULKSVC_VERBS_WRITE_FLAGS_SOLICITED = (1 << 1),
};

struct hfi1_bulksvc_verbs_rdma_cmd {
	struct hfi1_bulksvc_qp_info *qp_info;
	struct rvt_qp* qp;
	struct verbs_txreq* txreq;
};

struct hfi1_bulksvc_verbs_mr_reg_cmd {
	struct rvt_mregion *mr;
};

struct hfi1_bulksvc_verbs_mr_dereg_cmd {
	struct rvt_mregion *mr;
};

enum hfi1_bulksvc_verbs_cmd_op {
	HFI1_BULKSVC_VERBS_CMD_OP_RDMA,
	HFI1_BULKSVC_VERBS_CMD_OP_MR_REG,
	HFI1_BULKSVC_VERBS_CMD_OP_MR_DEREG,
};

struct hfi1_bulksvc_verbs_cmd {
	struct list_head node;
	struct kref refcount;
	enum hfi1_bulksvc_verbs_cmd_op op;
	union {
		struct hfi1_bulksvc_verbs_rdma_cmd rdma;
		struct hfi1_bulksvc_verbs_mr_reg_cmd mr_reg;
		struct hfi1_bulksvc_verbs_mr_dereg_cmd mr_dereg;
	};
};

struct hfi1_bulksvc_mpsc_verbs_cmd_queue {
	struct list_head list;
	spinlock_t lock;
};

enum hfi1_bulksvc_verbs_cmpl_type {
	HFI1_BULKSVC_VERBS_CMPL_TYPE_CMD,
	HFI1_BULKSVC_VERBS_CMPL_TYPE_ACCESS,
};

struct hfi1_bulksvc_verbs_cmpl {
	struct list_head node;
	struct kref refcount;

	enum hfi1_bulksvc_verbs_cmpl_type type;

	union {
		struct {
			struct hfi1_bulksvc_verbs_cmd *bts_cmd;
			u32 status;
		} cmd;
		struct {
			struct rvt_qp* qp;
			u32 lkey;
			u32 user_immdt_be;
			u16 flags;
		} access;
	};
};

struct hfi1_bulksvc_verbs_cmpl_queue {
	struct list_head list;
	struct mutex lock;
};

struct hfi1_bulksvc_qp_info {
	// Held by the hfi1_qp_priv, as well as active dms ops
	struct kref refcount;
	struct list_head node;
	u32 rdma_ops_sched; /* n ops in DMS, protected by s_lock */

	struct hfi1_qp_priv *qp_priv;

	struct hfi1_bulksvc_verbs_state* verbs_state;

	u16 num_rx_transfers_seen_for_current_transaction;
};


struct hfi1_bulksvc_verbs_state {
	struct hfi1_dms* dms;

	struct mutex qp_infos_lock;
	struct list_head qp_infos;

	struct list_head mr_info_records; // bts_verbs_mr_record

	struct hfi1_bulksvc_mpsc_verbs_cmd_queue cmd_queue;

	struct hfi1_bulksvc_verbs_cmpl_queue bulksvc_cmplq;
	struct work_struct cmpl_work;
};

int hfi1_bulksvc_verbs_state_init(struct hfi1_bulksvc_verbs_state *state, struct hfi1_dms* dms);
int hfi1_bulksvc_verbs_state_teardown(struct hfi1_bulksvc_verbs_state *state);

int hfi1_bulksvc_poll_verbs_cmds(struct hfi1_bulksvc * const svc);

struct hfi1_bulksvc_qp_info* hfi1_bulksvc_qp_info_create(struct hfi1_bulksvc_verbs_state* verbs_state, struct hfi1_qp_priv *qp_priv);
void hfi1_bulksvc_qp_info_get(struct hfi1_bulksvc_qp_info *qp_info);
void hfi1_bulksvc_qp_info_put(struct hfi1_bulksvc_qp_info *qp_info);

struct hfi1_bulksvc_verbs_cmd * hfi1_bulksvc_verbs_cmd_rdma_create(
				 struct hfi1_bulksvc_qp_info *qp_info,
				 struct rvt_qp* qp,
				 struct verbs_txreq *txreq);
struct hfi1_bulksvc_verbs_cmd * hfi1_bulksvc_verbs_cmd_mr_reg_create(
				 struct rvt_mregion *mr);
struct hfi1_bulksvc_verbs_cmd *
hfi1_bulksvc_verbs_cmd_mr_dereg_create(struct rvt_mregion *mr);

void hfi1_bulksvc_verbs_cmd_get(struct hfi1_bulksvc_verbs_cmd *);
void hfi1_bulksvc_verbs_cmd_put(struct hfi1_bulksvc_verbs_cmd *);
void hfi1_bulksvc_verbs_cmpl_put(struct hfi1_bulksvc_verbs_cmpl *cmpl);

int hfi1_bulksvc_verbs_dms_reg_client_id(struct hfi1_dms* dms);
void hfi1_bulksvc_verbs_release_client_id(struct hfi1_dms* dms);

void bulksvc_on_cmd_uverbs_post_send(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_user_info * const user_info,
	struct hfi1_bulksvc_cmd_uverbs_post_send const * const cmd);

#endif