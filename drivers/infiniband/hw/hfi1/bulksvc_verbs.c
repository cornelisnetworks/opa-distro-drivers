#include <rdma/rdmavt_qp.h>
#include "verbs_txreq.h"

#include "bulksvc.h"
#include "bulksvc_rvt.h"
#include "dms.h"

#include "bulksvc_verbs.h"

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define VERBS_CLIENT_ID_START (((1 << 8) - 1) << 24)
// TODO partition by some notion of "client"
// #define VERBS_PD_TO_CLIENT_ID(id) (VERBS_CLIENT_ID_START + id)
#define VERBS_PD_TO_CLIENT_ID(id) (VERBS_CLIENT_ID_START)

struct bts_verbs_mr_record {
	struct list_head list_entry;
	struct kref refcount;
	u32 client_id;
	u32 rkey;
	enum bts_verbs_mr_record_type {
		BTS_VERBS_MR_RECORD_TYPE_PERSISTENT,
		BTS_VERBS_MR_RECORD_TYPE_ONETIME,
	} type;
	union {
		struct rvt_mregion *rvt_mr;
		struct hfi1_bulksvc_qp_info *qp_info;
	};
	struct hfi1_dms_mr dms_mr;
};

static struct bts_verbs_mr_record *bts_verbs_mr_record_create_from_rvtmr(
	struct hfi1_devdata *dd,
	struct rvt_mregion * const rvt_mr);

static void bts_verbs_mr_record_get(struct bts_verbs_mr_record * const mr_record);
static void bts_verbs_mr_record_put(struct bts_verbs_mr_record * const mr_record);


static struct hfi1_bulksvc_verbs_cmpl* hfi1_bulksvc_verbs_cmd_cmpl_create(
				 struct hfi1_bulksvc_verbs_cmd *cmd,
				 u32 status);
static struct hfi1_bulksvc_verbs_cmpl* hfi1_bulksvc_verbs_access_cmpl_create(
				struct rvt_qp* qp,
				u32 lkey,
				u32 user_immdt_be,
				u16 flags);

// Executed in bulksvc thread, will enqueue a completion and schedule for bulksvc_rvt connector
static void enqueue_and_schedule_bts_rvt_cmpl(
	struct hfi1_bulksvc* const svc,
	struct hfi1_bulksvc_verbs_cmpl * const cmpl)
{
	if (WARN_ON(!cmpl || !svc)) {
		pr_err("%s:%d:%s() invalid cmpl or verbs_state\n",
		       __FILENAME__, __LINE__, __func__);
		return;
	}
	struct hfi1_bulksvc_verbs_cmpl_queue * const cmplq = &svc->verbs_state.bulksvc_cmplq;
	mutex_lock(&cmplq->lock);
	list_add_tail(&cmpl->node, &cmplq->list);
	mutex_unlock(&cmplq->lock);

	static bool const do_sync_cmpls = true;
	if (do_sync_cmpls) {
		hfi1_bts_handle_verbs_cmpls(&svc->verbs_state);
	}
	else {
		queue_work_node(svc->dd->node, system_wq, &svc->verbs_state.cmpl_work);
	}

}


///
/// Handle QP commands in the bulksvc thread
///

struct qp_rdma_cmpl_cookie {
	struct hfi1_bulksvc* svc;
	struct hfi1_bulksvc_verbs_cmd* cmd;
	struct bts_verbs_mr_record* mr_record;
	u32* remaining_wr_sges;
};

static void bulksvc_on_qp_cmd_rdma_complete(
	union hfi1_dms_completion_cookie * const cookie, int status)
{
	struct qp_rdma_cmpl_cookie * const rdma_cookie =
		(struct qp_rdma_cmpl_cookie *)cookie;
	struct hfi1_bulksvc * const svc = rdma_cookie->svc;
	struct hfi1_bulksvc_verbs_cmd * const cmd = rdma_cookie->cmd;
	struct hfi1_qp_priv *qpriv;
	unsigned long flags;

	if (rdma_cookie->remaining_wr_sges) {
		(*rdma_cookie->remaining_wr_sges)--;
		if (*rdma_cookie->remaining_wr_sges > 0) {
			// Still more SGE to process, do not complete yet
			goto release_cookie_resources;
		}
		kfree(rdma_cookie->remaining_wr_sges);
		rdma_cookie->remaining_wr_sges = NULL;
	}

	/*
	 * if more verbs operations already queued and ready to go
	 * don't wait for next bulksvc iteration, start handling now
	 */
	qpriv = cmd->rdma.txreq->qp->priv;
	spin_lock_irqsave(&cmd->rdma.txreq->qp->s_lock, flags);
	if (qpriv && --qpriv->bulksvc_qp_info->rdma_ops_sched > 0) {
		/* we have more ready to go */
		iowait_set_flag(&qpriv->s_iowait, IOWAIT_PENDING_BTS);
		/* add to verbs queue */
		if (__hfi1_do_bts_send(&qpriv->s_iowait.wait[IOWAIT_BTS_SE], true)) {
			iowait_clear_flag(&qpriv->s_iowait, IOWAIT_PENDING_BTS);
			spin_unlock_irqrestore(&cmd->rdma.txreq->qp->s_lock, flags);
			/* process verbs queue */
			hfi1_bulksvc_poll_verbs_cmds(svc);
		} else {
			spin_unlock_irqrestore(&cmd->rdma.txreq->qp->s_lock, flags);
		}
	} else
		spin_unlock_irqrestore(&cmd->rdma.txreq->qp->s_lock, flags);
	enqueue_and_schedule_bts_rvt_cmpl(svc, hfi1_bulksvc_verbs_cmd_cmpl_create(cmd, cmd->rdma.txreq->bts_rc));

release_cookie_resources:
	hfi1_bulksvc_verbs_cmd_put(rdma_cookie->cmd);
	bts_verbs_mr_record_put(rdma_cookie->mr_record);
}

static void bulksvc_on_qp_cmd_rdma_helper(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_verbs_cmd * const cmd)
{
	struct hfi1_bulksvc_verbs_state* const verbs_state = &svc->verbs_state;

	struct hfi1_bulksvc_qp_info * const qp_info = cmd->rdma.qp_info;
	struct verbs_txreq * const txreq = cmd->rdma.txreq;

	u16 const remote_lid = qp_info->qp_priv->owner->remote_ah_attr.opa.dlid;

	u32 * remaining_sges = NULL;
	int err_rc = 0;
	txreq->bts_rc = 0;

	if (WARN_ON(!qp_info->qp_priv->owner->ibqp.pd)) {
		pr_err("%s:%d:%s() invalid qp_priv->owner->ibqp.pd\n",
		       __FILENAME__, __LINE__, __func__);
		err_rc = -EINVAL;
		goto on_err;
	}

	if (WARN_ON(!txreq->wqe)) {
		pr_err("%s:%d:%s() invalid txreq->wqe\n",
		       __FILENAME__, __LINE__, __func__);
		err_rc = -EINVAL;
		goto on_err;
	}
	if (WARN_ON(!txreq->wqe->rdma_wr.wr.sg_list)) {
		pr_err("%s:%d:%s() invalid txreq->wqe->rdma_wr.wr.sg_list\n",
		       __FILENAME__, __LINE__, __func__);
		err_rc = -EINVAL;
		goto on_err;
	}

	u32 const remote_client_id = VERBS_PD_TO_CLIENT_ID(qp_info->qp_priv->owner->ibqp.pd->res.id);
	u32 const access_key = txreq->wqe->rdma_wr.rkey;
	union hfi1_dms_key const dms_key = { .access = access_key, .client = remote_client_id };

	u32 const num_sge = txreq->wqe->rdma_wr.wr.num_sge;
	if (WARN_ON(num_sge >= 256)) {
		// We only use 8 bits on the wire, impose a cap on num_sges
		pr_err("%s:%d:%s() num_sge %u is too large, max 255 supported\n",
		       __FILENAME__, __LINE__, __func__, num_sge);
		err_rc = -EINVAL;
		goto on_err;
	}
	if (num_sge > 1) {
		remaining_sges = kzalloc(sizeof(*remaining_sges), GFP_KERNEL);
		if (!remaining_sges) {
			pr_err("%s:%d:%s() failed to allocate remaining_sges\n",
			       __FILENAME__, __LINE__, __func__);
			err_rc = -ENOMEM;
			goto on_err;
		}
		*remaining_sges = 0;
	}

	u32 const rdma_opcode = txreq->wqe->wr.opcode;
	u64 remote_addr = txreq->wqe->rdma_wr.remote_addr;
	u32 const size = txreq->wqe->length;

	for (u32 sge_idx = 0; sge_idx < num_sge; ++sge_idx) {

		struct rvt_sge* const sge = &txreq->wqe->sg_list[sge_idx];
		u32 const sge_size = sge->sge_length;

		struct rvt_mregion* const mr = sge->mr;
		if (WARN_ON(!mr)) {
			pr_err("No mregion associated with rdma op\n");
			err_rc = -ENOENT;
			goto on_err;
		}

		struct bts_verbs_mr_record* mr_record = NULL;
		list_for_each_entry(mr_record, &verbs_state->mr_info_records, list_entry) {
			if (mr_record->type == BTS_VERBS_MR_RECORD_TYPE_PERSISTENT &&
			mr_record->rvt_mr == mr) {
				break;
			}
		}
	
		if (WARN_ON(!mr_record)) {
			pr_err("%s:%d:%s() bulksvc: Failed to find any MR records\n",
			__FILENAME__, __LINE__, __func__);
			err_rc = -ENOENT;
			goto on_err;
		}
		if (mr_record->rvt_mr != mr) {
			dd_dev_err(svc->dd, "%s:%d:%s() verbs RDMA OP trying to use unknown MR\n",
				   __FILENAME__, __LINE__, __func__);
			err_rc = -ENOENT;
			goto on_err;
		}

		/* the ib_sge has been freed so recalculate local user address given
		* the m, n and length values
		*/
		u32 user_base_offset = 0;
		/* quick math if all same size */
		if (mr->page_shift) {
			/* get page offset */
			user_base_offset = ((sge->m * RVT_SEGSZ) + sge->n) *
				(1 << mr->page_shift);
		} else {
			int m, n;
			for (int i = 0; i < sge->m * RVT_SEGSZ + sge->n; i ++) {
				m = i / RVT_SEGSZ;
				n = i % RVT_SEGSZ;
				user_base_offset += mr->map[m]->segs[n].length;
			}
		}

		/* now get offset into last page, this doesn't look right but
		* sge->length is actually remaining size in page, see rvt_lkey_ok
		*/
		user_base_offset += mr->map[sge->m]->segs[sge->n].length - sge->length;
		/* lastly the m and n values included mr->offset so take that out */
		user_base_offset -= mr->offset;
		if (WARN_ON(user_base_offset > mr->length)) {
			pr_err("%s:%d:%s(): Calculated local offset %u is larger than mr size %u\n",
			__FILENAME__, __LINE__, __func__, user_base_offset,
			sge_size);
			err_rc = -EINVAL;
			goto on_err;
		}
		if (sge_size > mr->length - user_base_offset) {
			pr_err("%s:%d:%s(): Can't write %u bytes to mr with len %u, offset %u\n",
			__FILENAME__, __LINE__, __func__, size, sge_size, user_base_offset);
			err_rc = -EINVAL;
			goto on_err;
		}


		struct hfi1_dms_tracker_completion completion = {
			.fn = bulksvc_on_qp_cmd_rdma_complete,
			.cookie = {},
		};

		struct qp_rdma_cmpl_cookie * cookie =
			(struct qp_rdma_cmpl_cookie *) &completion.cookie;
		cookie->svc = svc;
		hfi1_bulksvc_verbs_cmd_get(cmd);
		cookie->cmd = cmd;
		bts_verbs_mr_record_get(mr_record);
		cookie->mr_record = mr_record;
		cookie->remaining_wr_sges = remaining_sges;

		int rc = 0;
		u16 flags = 0; u64 imm_data = 0; // FIXME - blocksome - temporary
		if (rdma_opcode == IB_WR_BULKSVC_READ) {
			rc = hfi1_dms_read_data(&svc->dms, remote_lid, dms_key, remote_addr,
						sge_size, &mr_record->dms_mr,
						mr->user_base + user_base_offset,
						flags, imm_data,
						completion);

		} else if (rdma_opcode == IB_WR_BULKSVC_WRITE) {
			rc = hfi1_dms_write_data(&svc->dms, remote_lid, dms_key,
						remote_addr, sge_size, &mr_record->dms_mr,
						mr->user_base + user_base_offset,
						flags, imm_data,						
						completion);
		} else if (rdma_opcode == IB_WR_BULKSVC_WRITE_WITH_IMM) {
			flags |= HFI1_BULKSVC_VERBS_WRITE_FLAGS_IMMDT;
			imm_data = be32_to_cpu(txreq->wqe->wr.ex.imm_data);
			// Should only be 24 bits, we rely on that
			if (WARN_ON(txreq->qp->remote_qpn >= (1 << 24))) {
				pr_err("%s:%d:%s() remote_qpn %u is too large for imm_data, max 24 bits allowed\n",
				       __FILENAME__, __LINE__, __func__,
				       txreq->qp->remote_qpn);
				err_rc = -EINVAL;
				goto on_err;
			}
			imm_data |= (u64) (txreq->qp->remote_qpn & ((1 << 24) - 1)) << 32;
			// Verified above that num_sge < 256
			imm_data |= (u64) (num_sge & ((1 << 8) - 1)) << 56;
			if (txreq->wqe->wr.send_flags & IB_SEND_SOLICITED) {
				flags |= HFI1_BULKSVC_VERBS_WRITE_FLAGS_SOLICITED;
			}
			rc = hfi1_dms_write_data(&svc->dms, remote_lid, dms_key,
						remote_addr, sge_size, &mr_record->dms_mr,
						mr->user_base + user_base_offset,
						flags, imm_data,						
						completion);
		} else {
			pr_err("unknown opcode %u\n", rdma_opcode);
			err_rc = -EINVAL;
			goto on_err;
		}

		if (rc < 0) {
			pr_err("%s:%d:%s() Could not initiate RDMA read: %d\n",
			__FILENAME__, __LINE__, __func__, rc);
			bts_verbs_mr_record_put(mr_record);
			err_rc = rc;
			goto on_err;
		}

		if (remaining_sges) {
			(*remaining_sges)++;
		}

		remote_addr += sge_size;
	}

	goto done;

on_err:
	if (!remaining_sges || (remaining_sges && *remaining_sges == 0)) {
		// No outstanding sges
		kfree(remaining_sges);
		enqueue_and_schedule_bts_rvt_cmpl(svc, hfi1_bulksvc_verbs_cmd_cmpl_create(cmd, (u32)err_rc));
	} else {
		// sges in flight, enqueue error later
		txreq->bts_rc = err_rc;
	}

done:
	hfi1_bulksvc_verbs_cmd_put(cmd);

}

static void bulksvc_on_qp_cmd_read(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_verbs_cmd * const cmd)
{
	bulksvc_on_qp_cmd_rdma_helper(svc, cmd);
}

static void bulksvc_on_qp_cmd_write(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_verbs_cmd * const cmd)
{
	bulksvc_on_qp_cmd_rdma_helper(svc, cmd);
}

static void bulksvc_on_qp_cmd_write_with_imm(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_verbs_cmd * const cmd)
{
	bulksvc_on_qp_cmd_rdma_helper(svc, cmd);
}

static void bulksvc_on_qp_cmd(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_verbs_cmd * const cmd)
{
	struct hfi1_bulksvc_qp_info* qp_info = cmd->rdma.qp_info;
	struct verbs_txreq *txreq = cmd->rdma.txreq;
	if (WARN_ON(!qp_info || !txreq || !txreq->wqe)) {
		return;
	}

	switch (txreq->wqe->wr.opcode) {
		case IB_WR_BULKSVC_READ:
			bulksvc_on_qp_cmd_read(svc, cmd);
			break;
		case IB_WR_BULKSVC_WRITE:
			bulksvc_on_qp_cmd_write(svc, cmd);
			break;
		case IB_WR_BULKSVC_WRITE_WITH_IMM:
			bulksvc_on_qp_cmd_write_with_imm(svc, cmd);
			break;
		default:
			pr_err("%s:%d:%s() unknown qp cmd opcode %u\n",
			       __FILENAME__, __LINE__, __func__,
			       txreq->wqe->wr.opcode);
			break;
	}
}

///
/// Handle MR notifications in the bulksvc thread
///

struct verbs_mr_accessed_cookie {
	struct hfi1_bulksvc* svc;
	u32 lkey;
};

static void bulksvc_on_verbs_mr_accessed (
	union hfi1_dms_completion_cookie * const cookie, u16 flags, u64 imm_data, int status)
{
	(void) status;

	if (WARN_ON(!cookie)) {
		pr_err("%s:%d:%s() invalid cookie\n",
		       __FILENAME__, __LINE__, __func__);
		return;
	}

	struct verbs_mr_accessed_cookie * const accessed_cookie =
		(struct verbs_mr_accessed_cookie *)cookie;
		
	if (WARN_ON(!accessed_cookie->svc)) {
		pr_err("%s:%d:%s() invalid svc\n",
			__FILENAME__, __LINE__, __func__);
		return;
	}

	struct hfi1_bulksvc_verbs_state * const verbs_state = &accessed_cookie->svc->verbs_state;

	if (flags & HFI1_BULKSVC_VERBS_WRITE_FLAGS_IMMDT) {
		u32 const qpn = (u32)(imm_data >> 32) & ((1 << 24) - 1);
		u8 const num_dms_txfers_for_wqe = (u8)((imm_data >> 56) & ((1 << 8) - 1));
		u32 const immdt = cpu_to_be32((u32)imm_data);

		struct hfi1_bulksvc_qp_info* qp_info = NULL;
		mutex_lock(&verbs_state->qp_infos_lock);
		list_for_each_entry(qp_info, &verbs_state->qp_infos, node) {
			if (qp_info->qp_priv->owner->ibqp.qp_num == qpn) {
				break;
			}
		}
		mutex_unlock(&verbs_state->qp_infos_lock);
		if (!qp_info) {
			pr_err("Cannot route immediate data to unknown QP num %u\n", qpn);
			goto done;
		}
		if (WARN_ON(!qp_info->qp_priv)) {
			pr_err("no qp_priv\n");
			goto done;
		}
		if (WARN_ON(!qp_info->qp_priv->owner)) {
			pr_err("no qp_priv->owner\n");
			goto done;
		}
		if (qp_info->qp_priv->owner->ibqp.qp_num != qpn) {
			pr_err("qp_info not found for qpn %u\n", qpn);
			goto done;
		}

		if (num_dms_txfers_for_wqe) {
			qp_info->num_rx_transfers_seen_for_current_transaction += 1;
			if (qp_info->num_rx_transfers_seen_for_current_transaction < num_dms_txfers_for_wqe) {
				goto done;
			}
			// Otherwise, time to notify completion
			qp_info->num_rx_transfers_seen_for_current_transaction = 0;
		}
		struct rvt_qp* qp = qp_info->qp_priv->owner;
		enqueue_and_schedule_bts_rvt_cmpl(accessed_cookie->svc, hfi1_bulksvc_verbs_access_cmpl_create(qp, accessed_cookie->lkey, immdt, flags));
	}

done:
	return;
}

static void bulksvc_on_verbs_cmd_mr_reg(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_verbs_cmd * const cmd)
{
	if (WARN_ON(cmd->op != HFI1_BULKSVC_VERBS_CMD_OP_MR_REG)) {
		pr_err("%s:%d:%s() invalid cmd op %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->op);
		return;
	}

	struct hfi1_bulksvc_verbs_mr_reg_cmd *mr_reg_cmd = &cmd->mr_reg;

	struct rvt_mregion * const rvt_mregion = mr_reg_cmd->mr;

	struct bts_verbs_mr_record * const mr_record = bts_verbs_mr_record_create_from_rvtmr(
		svc->dd, rvt_mregion);
	if (!mr_record) {
		pr_err("%s:%d:%s() bulksvc: Failed to create MR record\n",
		       __FILENAME__, __LINE__, __func__);
		return;
	}

	list_add_tail(&mr_record->list_entry, &svc->verbs_state.mr_info_records);

	struct hfi1_dms_access_completion completion = {
		.fn = bulksvc_on_verbs_mr_accessed,
		.cookie = {},
	};
	struct verbs_mr_accessed_cookie * cookie =
		(struct verbs_mr_accessed_cookie *) &completion.cookie;
	cookie->svc = svc;
	cookie->lkey = rvt_mregion->lkey;

	union hfi1_dms_key const dms_key = {
		.client = mr_record->client_id,
		.access = mr_record->rkey,
	};
	int rc = hfi1_dms_register_access(&svc->dms, &mr_record->dms_mr, mr_record->dms_mr.user.addr, mr_reg_cmd->mr->length, dms_key,
				  completion, HFI1_DMS_ACCESS_TYPE_PERSISTENT, NULL);

	if (rc < 0) {
		pr_err("%s:%d:%s() bulksvc: Failed to register DMS data\n",
		       __FILENAME__, __LINE__, __func__);
	}
	enqueue_and_schedule_bts_rvt_cmpl(svc, hfi1_bulksvc_verbs_cmd_cmpl_create(cmd, rc));
	hfi1_bulksvc_verbs_cmd_put(cmd);
}

static void bulksvc_on_verbs_cmd_mr_dereg(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_verbs_cmd * const cmd)
{
	struct rvt_mregion * const rvt_mr = cmd->mr_dereg.mr;
	if (WARN_ON(!rvt_mr)) {
		pr_err("%s:%d:%s() invalid MR in dereg cmd\n",
		       __FILENAME__, __LINE__, __func__);
		return;
	}
	u32 const dms_client_id = VERBS_PD_TO_CLIENT_ID(pd_id);
	u32 const rkey = rvt_mr->lkey;

	struct bts_verbs_mr_record *pos, *n;
	bool found = false;
	list_for_each_entry_safe(pos, n, &svc->verbs_state.mr_info_records, list_entry) {
		if (pos->client_id == dms_client_id && pos->rkey == rkey) {
			found = true;
			break;
		}
	}

	if (!found) {
		pr_err("%s:%d:%s() MR to deregister not found\n",
		__FILENAME__, __LINE__, __func__);

		enqueue_and_schedule_bts_rvt_cmpl(svc, hfi1_bulksvc_verbs_cmd_cmpl_create(cmd, -ENOENT));
		hfi1_bulksvc_verbs_cmd_put(cmd);
		return;
	}

	struct bts_verbs_mr_record * const mr_record = pos;
	union hfi1_dms_key const dms_key = {
		.client = dms_client_id,
		.access = mr_record->rkey,
	};
	int rc = hfi1_dms_unregister_access(&svc->dms, dms_key);
	if (rc != 0) {
		pr_err("%s:%d:%s() Failed to deregister MR from DMS: %d\n",
		       __FILENAME__, __LINE__, __func__, rc);

		enqueue_and_schedule_bts_rvt_cmpl(svc, hfi1_bulksvc_verbs_cmd_cmpl_create(cmd, rc));
		hfi1_bulksvc_verbs_cmd_put(cmd);
		return;
	}

	enqueue_and_schedule_bts_rvt_cmpl(svc, hfi1_bulksvc_verbs_cmd_cmpl_create(cmd, 0));
	hfi1_bulksvc_verbs_cmd_put(cmd);
	list_del(&mr_record->list_entry);
	bts_verbs_mr_record_put(mr_record);
}

int hfi1_bulksvc_poll_verbs_cmds(struct hfi1_bulksvc * const svc)
{
	struct hfi1_bulksvc_verbs_cmd *tmp;
	struct list_head cmds;
	unsigned long flags;
	int processed = 0;

	INIT_LIST_HEAD(&cmds);
	spin_lock_irqsave(&svc->verbs_state.cmd_queue.lock, flags);
	list_cut_before(&cmds, &svc->verbs_state.cmd_queue.list, &svc->verbs_state.cmd_queue.list);
	INIT_LIST_HEAD(&svc->verbs_state.cmd_queue.list);
	spin_unlock_irqrestore(&svc->verbs_state.cmd_queue.lock, flags);

	struct hfi1_bulksvc_verbs_cmd *cmd;
	list_for_each_entry_safe(cmd, tmp, &cmds, node) {
		list_del(&cmd->node);
		processed += 1;
		switch (cmd->op) {
			case HFI1_BULKSVC_VERBS_CMD_OP_RDMA:
				bulksvc_on_qp_cmd(svc, cmd);
				break;
			case HFI1_BULKSVC_VERBS_CMD_OP_MR_REG:
				bulksvc_on_verbs_cmd_mr_reg(svc, cmd);
				break;
			case HFI1_BULKSVC_VERBS_CMD_OP_MR_DEREG:
				bulksvc_on_verbs_cmd_mr_dereg(svc, cmd);
				break;
		}
	}
	return processed;
}

///
/// Resource initialization and cleanup
///

struct hfi1_bulksvc_qp_info* hfi1_bulksvc_qp_info_create(struct hfi1_bulksvc_verbs_state* verbs_state, struct hfi1_qp_priv *qp_priv)
{
	if (WARN_ON(!qp_priv)) {
		return NULL;
	}
	struct hfi1_bulksvc_qp_info* res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate qp info\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}

	kref_init(&res->refcount);
	INIT_LIST_HEAD(&res->node);

	res->qp_priv = qp_priv;
	res->verbs_state = verbs_state;

	res->num_rx_transfers_seen_for_current_transaction = 0;

	res->rdma_ops_sched = 0;

	return res;
}

void hfi1_bulksvc_qp_info_get(struct hfi1_bulksvc_qp_info *qp_info)
{
	kref_get(&qp_info->refcount);
}

static void bulksvc_qp_info_destroy(struct kref* info_refcount)
{
	struct hfi1_bulksvc_qp_info* info = container_of(info_refcount, struct hfi1_bulksvc_qp_info, refcount);

	mutex_lock(&info->verbs_state->qp_infos_lock);
	list_del(&info->node);
	mutex_unlock(&info->verbs_state->qp_infos_lock);

	kfree(info);
}

void hfi1_bulksvc_qp_info_put(struct hfi1_bulksvc_qp_info *qp_info)
{
	kref_put(&qp_info->refcount, bulksvc_qp_info_destroy);
}

struct hfi1_bulksvc_verbs_cmd* hfi1_bulksvc_verbs_cmd_rdma_create(
				 struct hfi1_bulksvc_qp_info *qp_info,
				 struct verbs_txreq *txreq)
{
	struct hfi1_bulksvc_verbs_cmd *cmd = kzalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate verbs cmd\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}
	cmd->op = HFI1_BULKSVC_VERBS_CMD_OP_RDMA;
	INIT_LIST_HEAD(&cmd->node);
	kref_init(&cmd->refcount);

	hfi1_get_txreq(txreq);
	cmd->rdma.txreq = txreq;
	hfi1_bulksvc_qp_info_get(qp_info);
	cmd->rdma.qp_info = qp_info;
	return cmd;
}

struct hfi1_bulksvc_verbs_cmd * hfi1_bulksvc_verbs_cmd_mr_reg_create(
				 struct rvt_mregion *mr)
{
	struct hfi1_bulksvc_verbs_cmd *cmd = kzalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate verbs cmd\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}
	cmd->op = HFI1_BULKSVC_VERBS_CMD_OP_MR_REG;
	INIT_LIST_HEAD(&cmd->node);
	kref_init(&cmd->refcount);
	
	rvt_get_mr(mr);
	cmd->mr_reg.mr = mr;

	return cmd;
}

struct hfi1_bulksvc_verbs_cmd * hfi1_bulksvc_verbs_cmd_mr_dereg_create(
				 struct rvt_mregion *mr)
{
	struct hfi1_bulksvc_verbs_cmd *cmd = kzalloc(sizeof(*cmd), GFP_ATOMIC);
	if (!cmd) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate verbs cmd\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}
	cmd->op = HFI1_BULKSVC_VERBS_CMD_OP_MR_DEREG;
	INIT_LIST_HEAD(&cmd->node);
	kref_init(&cmd->refcount);
	rvt_get_mr(mr);
	cmd->mr_dereg.mr = mr;
	return cmd;
}

void hfi1_bulksvc_verbs_cmd_get(struct hfi1_bulksvc_verbs_cmd *cmd)
{
	kref_get(&cmd->refcount);
}

static void hfi1_bulksvc_verbs_cmd_destroy(struct kref *refcount)
{
	struct hfi1_bulksvc_verbs_cmd *cmd =
		container_of(refcount, struct hfi1_bulksvc_verbs_cmd, refcount);

	switch (cmd->op) {
		case HFI1_BULKSVC_VERBS_CMD_OP_RDMA:
			hfi1_bulksvc_qp_info_put(cmd->rdma.qp_info);
			hfi1_put_txreq(cmd->rdma.txreq);
			break;
		case HFI1_BULKSVC_VERBS_CMD_OP_MR_REG:
			rvt_put_mr(cmd->mr_reg.mr);
			break;
		case HFI1_BULKSVC_VERBS_CMD_OP_MR_DEREG:
			rvt_put_mr(cmd->mr_dereg.mr);
			break;
		default:
			pr_err("%s:%d:%s() bulksvc: Unknown cmd op %u\n",
			       __FILENAME__, __LINE__, __func__, cmd->op);
			break;
	}
	kfree(cmd);
}

void hfi1_bulksvc_verbs_cmd_put(struct hfi1_bulksvc_verbs_cmd *cmd)
{
	kref_put(&cmd->refcount, hfi1_bulksvc_verbs_cmd_destroy);
}

struct hfi1_bulksvc_verbs_cmpl* hfi1_bulksvc_verbs_cmd_cmpl_create(
				 struct hfi1_bulksvc_verbs_cmd *cmd,
				 u32 status)
{
	struct hfi1_bulksvc_verbs_cmpl *cmpl = kzalloc(sizeof(*cmpl), GFP_KERNEL);
	if (!cmpl) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate verbs completion\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}
	cmpl->type = HFI1_BULKSVC_VERBS_CMPL_TYPE_CMD;
	cmpl->cmd.bts_cmd = cmd;
	hfi1_bulksvc_verbs_cmd_get(cmpl->cmd.bts_cmd);
	cmpl->cmd.status = status;
	INIT_LIST_HEAD(&cmpl->node);
	kref_init(&cmpl->refcount);
	return cmpl;
}

struct hfi1_bulksvc_verbs_cmpl* hfi1_bulksvc_verbs_access_cmpl_create(
				struct rvt_qp* qp,
				u32 lkey,
				u32 user_immdt_be,
				u16 flags)
{
	struct hfi1_bulksvc_verbs_cmpl *cmpl = kzalloc(sizeof(*cmpl), GFP_KERNEL);
	if (!cmpl) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate verbs completion\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}
	cmpl->type = HFI1_BULKSVC_VERBS_CMPL_TYPE_ACCESS;
	rvt_get_qp(qp);
	cmpl->access.qp = qp;
	cmpl->access.lkey = lkey;
	cmpl->access.user_immdt_be = user_immdt_be;
	cmpl->access.flags = flags;
	INIT_LIST_HEAD(&cmpl->node);
	kref_init(&cmpl->refcount);
	return cmpl;
}

static void hfi1_bulksvc_verbs_cmpl_destroy(struct kref *refcount)
{
	struct hfi1_bulksvc_verbs_cmpl *cmpl =
		container_of(refcount, struct hfi1_bulksvc_verbs_cmpl, refcount);
	switch (cmpl->type) {
		case HFI1_BULKSVC_VERBS_CMPL_TYPE_CMD:
			hfi1_bulksvc_verbs_cmd_put(cmpl->cmd.bts_cmd);
			break;
		case HFI1_BULKSVC_VERBS_CMPL_TYPE_ACCESS:
			rvt_put_qp(cmpl->access.qp);
			break;
	}
	kfree(cmpl);
}

void hfi1_bulksvc_verbs_cmpl_put(struct hfi1_bulksvc_verbs_cmpl *cmpl)
{
	kref_put(&cmpl->refcount, hfi1_bulksvc_verbs_cmpl_destroy);
}

int hfi1_bulksvc_verbs_state_init(struct hfi1_bulksvc_verbs_state *state, struct hfi1_dms* dms)
{
	state->dms = dms;

	mutex_init(&state->qp_infos_lock);
	INIT_LIST_HEAD(&state->qp_infos);

	INIT_LIST_HEAD(&state->mr_info_records);

	spin_lock_init(&state->cmd_queue.lock);
	INIT_LIST_HEAD(&state->cmd_queue.list);

	mutex_init(&state->bulksvc_cmplq.lock);
	INIT_LIST_HEAD(&state->bulksvc_cmplq.list);
	INIT_WORK(&state->cmpl_work, _hfi1_bts_handle_verbs_cmpls);

	return 0;
}

int hfi1_bulksvc_verbs_dms_reg_client_id(struct hfi1_dms* dms) 
{
	if (hfi1_dms_create_client_key(dms, VERBS_CLIENT_ID_START)) {
		pr_err("Failed to create DMS client key for verbs %u\n",
			   VERBS_CLIENT_ID_START);
		return -1;
	}

	return 0;
}

void hfi1_bulksvc_verbs_release_client_id(struct hfi1_dms* dms)
{
	hfi1_dms_release_client_key(dms, VERBS_CLIENT_ID_START);
}

static int bts_verbs_pinned_check(struct hfi1_dms_mr * const dms_mr, unsigned int start_page_index, unsigned int npages_to_request)
{
	struct bts_verbs_mr_record * const mr_record = container_of(dms_mr, struct bts_verbs_mr_record, dms_mr);
	(void)mr_record; // Unused for now, but can be used for debugging
	// TODO real check?
	return 0;
}

static struct bts_verbs_mr_record *bts_verbs_mr_record_create_from_rvtmr(
	struct hfi1_devdata *dd,
	struct rvt_mregion * const rvt_mr)
{
	if (WARN_ON(!rvt_mr)) {
		pr_err("%s:%d:%s() bulksvc: Invalid rvt_mr\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}

	struct bts_verbs_mr_record * const mr_record = kzalloc(sizeof(*mr_record), GFP_KERNEL);
	if (!mr_record) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate mr record\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
		// TODO
	}

	INIT_LIST_HEAD(&mr_record->list_entry);

	// dms key
	u32 const dms_client_id = VERBS_PD_TO_CLIENT_ID(pd_id);
	u32 const rkey = rvt_mr->lkey;
	mr_record->client_id = dms_client_id;
	mr_record->rkey = rkey;

	// rvt_mr
	rvt_get_mr(rvt_mr);
	mr_record->type = BTS_VERBS_MR_RECORD_TYPE_PERSISTENT;
	mr_record->rvt_mr = rvt_mr;

	for (u64 i = 0; i < rvt_mr->mapsz; ++i) {
		struct rvt_segarray *map = rvt_mr->map[i];
		if (!map) {
			pr_err("%s:%d:%s() bulksvc: Invalid map at index %llu\n",
				   __FILENAME__, __LINE__, __func__, i);
			kfree(mr_record);
			return NULL;
		}
	}

	// dms_mr
	struct hfi1_dms_mr * const dms_mr = &mr_record->dms_mr;
	dms_mr->extended_vaddr.addr = rvt_mr->user_base & ~(PAGE_SIZE - 1);
	u64 const extension_down = rvt_mr->user_base - dms_mr->extended_vaddr.addr;
	u64 const len_extended_down = rvt_mr->length + extension_down;
	u64 const len_extended_down_up = (len_extended_down + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	dms_mr->extended_vaddr.len = len_extended_down_up;

	dms_mr->user.addr = rvt_mr->user_base;
	dms_mr->user.len = rvt_mr->length;

	// TODO should we use rvt_mr->page_shift?
	dms_mr->npages_total = dms_mr->extended_vaddr.len >> PAGE_SHIFT;
	// Pinned by rvt
	dms_mr->npages_pinned = dms_mr->npages_total;

	dms_mr->pages = kvcalloc(dms_mr->npages_total, sizeof(struct page*), GFP_KERNEL);
	if (!dms_mr->pages) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate mr pages array\n",
		       __FILENAME__, __LINE__, __func__);
		kfree(mr_record);
		return NULL;
		// TODO
	}
	u32 i, m, s;
	for (i = 0; i < dms_mr->npages_total; i++) {
		m = i / RVT_SEGSZ;
		s = i % RVT_SEGSZ;
		/* sanity check */
		if (WARN_ON((m * RVT_SEGSZ) + s >= rvt_mr->max_segs)) {
			kvfree(mr_record->dms_mr.pages);
			kfree(mr_record);
			return NULL;
		}
		struct page *page = virt_to_page(rvt_mr->map[m]->segs[s].vaddr);
		if (WARN_ON(!page)) {
			pr_err("%s:%d:%s() bulksvc: Failed to get page for addr %p\n",
			       __FILENAME__, __LINE__, __func__,
			       rvt_mr->map[m]->segs[s].vaddr);
			kvfree(mr_record->dms_mr.pages);
			kfree(mr_record);
			return NULL;
		}
		if (rvt_mr->map[m]->segs[s].length != PAGE_SIZE) {
			pr_err("%s:%d:%s() bulksvc: Unexpected segment length %zu at map %d seg %u\n",
				__FILENAME__, __LINE__, __func__,
				rvt_mr->map[m]->segs[s].length, m, s);
			kvfree(mr_record->dms_mr.pages);
			kfree(mr_record);
			return NULL;
		}
		dms_mr->pages[i] = page;
	}

	dms_mr->dma_list = kvcalloc(dms_mr->npages_total, sizeof(dma_addr_t), GFP_KERNEL);
	if (!dms_mr->dma_list) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate dma list\n",
		       __FILENAME__, __LINE__, __func__);
		kfree(mr_record->dms_mr.pages);
		kfree(mr_record);
		return NULL;
	}

	for (i = 0; i < dms_mr->npages_pinned; i++) {
		dms_mr->dma_list[i] = dma_map_page(&dd->pcidev->dev,
		       dms_mr->pages[i], 0, PAGE_SIZE, // map whole page
		       //we don't know the use so do bidrect
		       DMA_BIDIRECTIONAL);
		if (unlikely(dma_mapping_error(&dd->pcidev->dev, dms_mr->dma_list[i]))) {
			pr_err("%s:%d:%s() bulksvc: Failed to map page %d for addr %lx\n",
			       __FILENAME__, __LINE__, __func__, i,
			       dms_mr->extended_vaddr.addr + (i << PAGE_SHIFT));
			kvfree(mr_record->dms_mr.dma_list);
			kvfree(mr_record->dms_mr.pages);
			kfree(mr_record);
			return NULL;
		}
	}

	dms_mr->region_offset = dms_mr->user.addr & (PAGE_SIZE - 1);
	dms_mr->mode = rvt_mr->access_flags & IB_UVERBS_ACCESS_ZERO_BASED ? HFI1_DMS_MR_MODE_OFFSET : HFI1_DMS_MR_MODE_VADDR;

	dms_mr->pinned_check_fn = bts_verbs_pinned_check;

	kref_init(&mr_record->refcount);

	return mr_record;
}

static void bts_verbs_mr_record_get(struct bts_verbs_mr_record * const mr_record)
{
	kref_get(&mr_record->refcount);
}

static void bts_verbs_mr_record_destroy(struct kref* refcount)\
{
	struct bts_verbs_mr_record * const mr_record =
		container_of(refcount, struct bts_verbs_mr_record, refcount);

	if (mr_record->type == BTS_VERBS_MR_RECORD_TYPE_PERSISTENT && mr_record->rvt_mr) {
		rvt_put_mr(mr_record->rvt_mr);
		mr_record->rvt_mr = NULL;
	}
	else if (mr_record->type == BTS_VERBS_MR_RECORD_TYPE_ONETIME && mr_record->qp_info) {
		hfi1_bulksvc_qp_info_put(mr_record->qp_info);
		mr_record->qp_info = NULL;
	}

	kvfree(mr_record->dms_mr.pages);
	kvfree(mr_record->dms_mr.dma_list);
	kfree(mr_record);
}

static void bts_verbs_mr_record_put(struct bts_verbs_mr_record * const mr_record)
{
	kref_put(&mr_record->refcount, bts_verbs_mr_record_destroy);
}

static struct rvt_qp *qp_from_number(struct hfi1_bulksvc *svc, u64 app_context)
{
	struct rvt_qp *qp = NULL;
	struct hfi1_bulksvc_qp_info* qp_info = NULL;
	mutex_lock(&svc->verbs_state.qp_infos_lock);
	list_for_each_entry(qp_info, &svc->verbs_state.qp_infos, node) {
		if (qp_info->qp_priv->owner->ibqp.qp_num == app_context) {
			qp = qp_info->qp_priv->owner;
			break;
		}
	}
	mutex_unlock(&svc->verbs_state.qp_infos_lock);

	return qp;
}

static void bts_send_cq(struct rvt_qp *qp, u64 wr_id, u32 byte_len,
			enum ib_wc_opcode wr_opcode, enum ib_wc_status status)
{
	unsigned long lflags;
	struct rvt_dev_info *rdi = ib_to_rvt(qp->ibqp.device);
	spin_lock_irqsave(&qp->s_lock, lflags);
	struct ib_wc w = {
		.wr_id = wr_id,
		.status = status,
		.opcode = rdi->wc_opcode[wr_opcode],
		.qp = &qp->ibqp,
		.byte_len = byte_len
	};
	rvt_send_cq(qp, &w, true,
		    RVT_QP_LOCK_STATE_S);
	spin_unlock_irqrestore(&qp->s_lock, lflags);
}

/*
 * TODO - this function must check if the wqe can be passed to DMS
 * and put on the wire now. Things to keep in mind:
 * 1. is the wqe bts-able - see hfi1_setup_bulksvc_wqe
 * 2. is anything else going through rdmavt? must respect
 *    verbs ordering
 */
static bool can_bts_hotpath(void) {
	/* TODO hotpath not implemented */
	return false;
}

void bulksvc_on_cmd_uverbs_post_send(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_user_info * const user_info,
	struct hfi1_bulksvc_cmd_uverbs_post_send const * const cmd)
{
	const struct ib_send_wr *bad_wr = NULL;
	u64 qpn = cmd->app_context;
	struct ib_uverbs_sge *sge;
	struct rvt_qp *qp;
	int ret;
	u16 i;

	qp = qp_from_number(svc, qpn);
	if (!qp) {
		dd_dev_err(svc->dd, "QP #%llu not found\n", cmd->app_context);
		return;
	}
	if (qp->ibqp.qp_type != IB_QPT_RC) {
		dd_dev_err(svc->dd, "Cannot ioctl bypass non RC qp's\n");
		return;
	}


	u8 *ptr = (u8 *)cmd->wrs;
	for (i = 0; i < cmd->num_wrs; i ++) {
		struct ib_rdma_wr rdma_wr;
		struct ib_atomic_wr atomic_wr;
		struct ib_uverbs_send_wr *user_wr;

		user_wr = (struct ib_uverbs_send_wr *)ptr;
		sge = (struct ib_uverbs_sge *)(ptr + sizeof(*user_wr));

		struct ib_send_wr *wr;
		struct ib_send_wr swr = {
			.next = NULL,
			.wr_id = user_wr->wr_id,
			.sg_list = (struct ib_sge *)sge,
			.num_sge = user_wr->num_sge,
			.opcode = user_wr->opcode,
			.send_flags = user_wr->send_flags,
			.ex.imm_data = user_wr->ex.imm_data
		};
		if (user_wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM ||
		    user_wr->opcode == IB_WR_RDMA_WRITE ||
		    user_wr->opcode == IB_WR_RDMA_READ) {
			rdma_wr.wr = swr;
			rdma_wr.remote_addr =  user_wr->wr.rdma.remote_addr;
			rdma_wr.rkey = user_wr->wr.rdma.rkey;

			wr = &rdma_wr.wr;
		} else if (user_wr->opcode == IB_WR_ATOMIC_CMP_AND_SWP ||
			   user_wr->opcode == IB_WR_ATOMIC_FETCH_AND_ADD) {
			atomic_wr.wr = swr,
			atomic_wr.remote_addr = user_wr->wr.atomic.remote_addr;
			atomic_wr.compare_add = user_wr->wr.atomic.compare_add;
			atomic_wr.swap = user_wr->wr.atomic.swap;
			atomic_wr.rkey = user_wr->wr.atomic.rkey;

			wr = &atomic_wr.wr;
		} else {
			wr = &swr;
		}

		if (can_bts_hotpath()) {
			/* we need to post errors to cq */
			dd_dev_err(svc->dd, "BTS VERBS HOTPATH NOT IMPLEMENTED\n");
			goto post_errs;
		} else {
			ret = rvt_post_send(&qp->ibqp, wr, &bad_wr);
			if (ret) {
				/* we need to post errors to cq */
				dd_dev_err(svc->dd, "bts: rdmavt post send rc %d\n", ret);
				goto post_errs;
			}
		}

		ptr += sizeof(*user_wr) + (user_wr->num_sge * sizeof(*sge));
	}

	return;
post_errs:
	for (; i < cmd->num_wrs; i ++) {
		struct ib_uverbs_send_wr *user_wr;
		user_wr = (struct ib_uverbs_send_wr *)ptr;
		u32 byte_len = 0;
		/* sg_list follows the wr header */
		sge = (struct ib_uverbs_sge *)(ptr + sizeof(*user_wr));
		for (int s = 0; s < user_wr->num_sge; s++) {
			byte_len += sge->length;
			sge++;
		}

		bts_send_cq(qp, user_wr->wr_id, byte_len, user_wr->opcode, IB_WC_GENERAL_ERR);
		ptr += sizeof(*user_wr) + (user_wr->num_sge * sizeof(*sge));
	}
}

