/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2025 Cornelis Networks.
 */
#include <linux/workqueue.h>
#include "qp.h"
#include "bulksvc.h"
#include "bulksvc_rvt.h"
#include "bulksvc_verbs.h"

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

static bool __hfi1_do_bts_send(struct iowait_work *w, bool in_thread);

/*** TEMP THINGS UNTIL API IS DEFINED ***/
int verbs_bulksvc_reg_mr(struct hfi1_bulksvc *svc, struct rvt_mregion *mr)
{
	unsigned long flags;

	if (WARN_ON(!svc || !mr || !mr->pd)) {
		pr_err("%s:%d:%s() bulksvc: Invalid svc or mr\n",
		       __FILE__, __LINE__, __func__);
		return -EINVAL;
	}

	rvt_get_mr(mr);

	struct hfi1_bulksvc_verbs_cmd * const cmd =
		hfi1_bulksvc_verbs_cmd_mr_reg_create(mr);
	
	if (WARN_ON(!cmd)) {
		pr_err("%s:%d:%s() bulksvc: Failed to create MR reg cmd\n",
		       __FILE__, __LINE__, __func__);
		return -ENOMEM;
	}

	spin_lock_irqsave(&svc->verbs_state.cmd_queue.lock, flags);
	list_add_tail(&cmd->node, &svc->verbs_state.cmd_queue.list);
	spin_unlock_irqrestore(&svc->verbs_state.cmd_queue.lock, flags);

	hfi1_bulksvc_schedule(svc);
	return 0;
}

void verbs_bulksvc_dereg_mr(struct hfi1_bulksvc *svc, struct rvt_mregion *mr)
{
	struct hfi1_bulksvc_verbs_cmd * const cmd =
		hfi1_bulksvc_verbs_cmd_mr_dereg_create(mr);
	unsigned long flags;

	if (WARN_ON(!cmd)) {
		pr_err("%s:%d:%s() bulksvc: Failed to create MR dereg cmd\n",
		       __FILE__, __LINE__, __func__);
		return;
	}
	
	spin_lock_irqsave(&svc->verbs_state.cmd_queue.lock, flags);
	list_add_tail(&cmd->node, &svc->verbs_state.cmd_queue.list);
	spin_unlock_irqrestore(&svc->verbs_state.cmd_queue.lock, flags);

	rvt_put_mr(mr);
	hfi1_bulksvc_schedule(svc);

	return;
}

static int bts_on_verbs_rdma_op(struct hfi1_bulksvc_verbs_cmd *cmd)
{
	if (!cmd) {
		printk(KERN_ERR "vBTS called with no cmd\n");
		return -EINVAL;
	}
	if (WARN_ON(cmd->op != HFI1_BULKSVC_VERBS_CMD_OP_RDMA)) {
		printk(KERN_ERR "vBTS called with non-RDMA cmd op %u\n", cmd->op);
		return -EINVAL;
	}
	struct verbs_txreq *tx = cmd->rdma.txreq;
	if (!tx || !tx->qp || !tx->qp->priv) {
		printk(KERN_ERR "vBTS called with no tx or qp priv\n");
		return -EINVAL;
	}
	enum ib_qp_type const qptype = tx->qp->ibqp.qp_type;
	if (qptype != IB_QPT_RC) {
		printk(KERN_ERR "vBTS called with non-RC qp type %d\n", qptype);
		return -EINVAL;
	}
	if (!tx->wqe) {
		printk(KERN_ERR "vBTS called with no wqe\n");
		return -EINVAL;
	}
	// Checked above that qptype is RC
	enum ib_wr_opcode const opcode = tx->wqe->wr.opcode;
	if (!ib_wr_opcode_is_hfi1_bulksvc(opcode)) {
		printk(KERN_ERR "vBTS called with non-BULKSVC opcode %d\n",
		       opcode);
		// TODO
		return -EINVAL;
	}

	struct hfi1_bulksvc_mpsc_verbs_cmd_queue *const cmd_queue =
		&cmd->rdma.qp_info->verbs_state->cmd_queue;
	/* don't need irqsave because calling function should have alredy
	 * done that
	 */
	spin_lock(&cmd_queue->lock);
	list_add_tail(&cmd->node,
		      &cmd_queue->list);
	spin_unlock(&cmd_queue->lock);


	struct hfi1_bulksvc *svc = container_of(cmd->rdma.qp_info->verbs_state,
						struct hfi1_bulksvc,
						verbs_state);
	hfi1_bulksvc_schedule(svc);

	return 0;
}

/*** ACTUAL THINGS ***/
static bool bulksvc_negotiation_check(void)
{
	return true; /* assume both sides support for now */
}

/* STEP 1: Recognize this wqe is eligble for BTS */
/* return true if this wqe opcode has been changed to use bulksvc */
/* this function is comparable to setup_tid_rdma_wqe */
bool hfi1_setup_bulksvc_wqe(struct rvt_qp *qp, struct rvt_swqe *wqe)
{
	struct hfi1_qp_priv *qpriv;
	struct hfi1_pportdata *ppd;
	struct hfi1_devdata *dd;
	enum ib_wr_opcode new_opcode;
	u32 new_lpsn;

	/* if opfn not enabled, no way to negotiate */
	/* TODO ADD OPFN SUPPORT */
	// if (!wqe->priv)
	// 	return false;

	if (wqe->length < BULKSVC_VERBS_MIN_SEGMENT_SIZE)
		return false;
	switch (wqe->wr.opcode) {
	case IB_WR_RDMA_READ:
		new_opcode = IB_WR_BULKSVC_READ;
		new_lpsn = wqe->psn - 1;
		break;
	case IB_WR_RDMA_WRITE:
		new_opcode = IB_WR_BULKSVC_WRITE;
		new_lpsn = wqe->psn - 1;
		break;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		new_opcode = IB_WR_BULKSVC_WRITE_WITH_IMM;
		new_lpsn = wqe->psn - 1;
		break;
	default:
		return false;
	}

	qpriv = (struct hfi1_qp_priv *)qp->priv;
	/* IB packets only */
	if (qpriv->hdr_type != HFI1_PKT_TYPE_9B)
		return false;

	ppd = qpriv->rcd->ppd;
	/* no loopbacks */
	if ((rdma_ah_get_dlid(&qp->remote_ah_attr) & ~((1 << ppd->lmc) - 1)) ==
				ppd->lid)
		return false;

	/* bulksvc supported on both sides check */
	if (!bulksvc_negotiation_check())
		return false;
	/* is bulksvc ready to go */
	dd = ppd->dd;
	if (!dd->bulksvc)
		return false;

	wqe->wr.opcode = new_opcode;
	wqe->lpsn = new_lpsn;
	qp->s_ssn--; /* peer won't give us an MSN update so don't count this ssn */

	return true;
}

/* STEP 2: Silently remove this entry from the standard verbs processing
 * store any data we may need to give to BTS
 * called from normal IB verbs processing
 */
void verbs_bulksvc_enqueue(struct hfi1_qp_priv *qpriv, struct verbs_txreq *tx,
			   struct rvt_swqe *wqe)
{
	struct rvt_qp *qp = qpriv->owner;

	lockdep_assert_held(&qp->s_lock);
	/* txreq is more or less a shell around our wqe, grab extra kref
	 * since we will be dropping it in make_rc_req
	 */
	/* this kref should be dropped when handed to BTS in _hfi1_do_bts_send */
	hfi1_get_txreq(tx);
	tx->wqe = wqe; // wqe is what we really will need later
	list_add_tail(&tx->txreq.list,
		      &qpriv->s_iowait.wait[IOWAIT_BTS_SE].tx_head);

	iowait_set_flag(&qpriv->s_iowait, IOWAIT_PENDING_BTS);
	/* try to send now */
	if (__hfi1_do_bts_send(&qpriv->s_iowait.wait[IOWAIT_BTS_SE], true))
		iowait_clear_flag(&qpriv->s_iowait, IOWAIT_PENDING_BTS);
	/* else immediate send failed, just leave PENDING flag */

	// /* Ideally we set the flag above and iowait see's it and
	//  * calls our function in hfi1_qp_schedule.
	//  * My understanding is apparently wrong, if we return here
	//  * nothing happens.
	//  * So do what we expected to happen in another thread here.
	//  * and figure this crap out later. Maybe we skip all this
	//  * iowait stuff and hand to bts here
	//  */
	// int ret;
	// qp->s_flags &= ~RVT_S_BUSY;
	// if (iowait_flag_set(&qpriv->s_iowait, IOWAIT_PENDING_BTS)) {
	// 	ret = hfi1_schedule_bts_send(qp);
	// 	if (ret)
	// 		iowait_clear_flag(&qpriv->s_iowait, IOWAIT_PENDING_BTS);
	// }
}

static bool _hfi1_schedule_bts_send(struct rvt_qp *qp)
{
	lockdep_assert_held(&qp->s_lock);
	struct hfi1_qp_priv *priv = qp->priv;
	struct hfi1_ibport *ibp =
		to_iport(qp->ibqp.device, qp->port_num);
	struct hfi1_pportdata *ppd = ppd_from_ibp(ibp);
	struct hfi1_devdata *dd = ppd->dd;

	if ((dd->flags & HFI1_SHUTDOWN))
		return true;

	return iowait_bts_schedule(&priv->s_iowait, dd->hfi1_wq,
				   priv->s_sde ?
				   priv->s_sde->cpu :
				   cpumask_first(cpumask_of_node(dd->node)));
}


/* same as hfi1_send_okay minus check for RVT_S_WAIT_ACK, bc that's us */
static inline int bts_send_ok(struct rvt_qp *qp)
{
	struct hfi1_qp_priv *priv = qp->priv;

	return !(qp->s_flags & (RVT_S_BUSY | HFI1_S_ANY_WAIT_IO)) &&
		(verbs_txreq_queued(iowait_get_ib_work(&priv->s_iowait)) ||
		(qp->s_flags & RVT_S_RESP_PENDING) ||
		 !(qp->s_flags & ~RVT_S_WAIT_ACK & RVT_S_ANY_WAIT_SEND));
}

/* called by iowait functions */
bool hfi1_schedule_bts_send(struct rvt_qp *qp)
{
	lockdep_assert_held(&qp->s_lock);
	if (hfi1_send_ok(qp)) {
		/*
		 * The following call returns true if the wq is not on the
		 * queue and false if the wq is already on the queue before
		 * this call. Either way, the qp will be on the queue when the
		 * call returns.
		 */
		_hfi1_schedule_bts_send(qp);
		return true;
	}
	if (qp->s_flags & HFI1_S_ANY_WAIT_IO)
		iowait_set_flag(&((struct hfi1_qp_priv *)qp->priv)->s_iowait,
				IOWAIT_PENDING_BTS);

	return false;
}

/* STEP 4: Hand to BTS */
/* returns true if list item handled false if not */
static bool __hfi1_do_bts_send(struct iowait_work *w, bool in_thread)
{
	struct sdma_txreq *txreq = iowait_get_txhead(w);
	struct hfi1_qp_priv *qpriv;
	struct verbs_txreq *tx;
	unsigned long flags;
	struct rvt_qp *qp;

	if (!txreq) {
		printk(KERN_ERR "vBTS scheduled us but empty list\n");
		return true;
	}

	tx = container_of(txreq, struct verbs_txreq, txreq);
	qp = tx->qp;
	if (!qp) {
		printk(KERN_ERR "vBTS scheduled request with no qp\n");
		hfi1_put_txreq(tx);
		return true;
	}
	qpriv = qp->priv;

	if (WARN_ON(!qpriv)) {
		printk(KERN_ERR "vBTS scheduled request with no qp priv\n");
		hfi1_put_txreq(tx);
		return true;
	}

	// /* no more sending until we get this acked by hfi1_bts_send_complete */
	if (!in_thread) {
		spin_lock_irqsave(&qp->s_lock, flags);
		tx->qp->s_flags |= RVT_S_WAIT_ACK;
		spin_unlock_irqrestore(&qp->s_lock, flags);
	} else {
		tx->qp->s_flags |= RVT_S_WAIT_ACK;
	}
	
	struct hfi1_bulksvc_verbs_cmd *cmd = hfi1_bulksvc_verbs_cmd_rdma_create(qpriv->bulksvc_qp_info, tx);
	if (!cmd) {
		printk(KERN_ERR "vBTS failed to allocate cmd\n");
		return true;
	}
	if(!bts_on_verbs_rdma_op(cmd)) {
		rvt_get_qp(qp); /* put by hfi1_qp_wakeup */

		hfi1_put_txreq(tx);
		return true; /* success case */
	}

	hfi1_bulksvc_verbs_cmd_put(cmd);
	/* error state reset our work so we can try again later */
	if (!in_thread)
		spin_lock_irqsave(&qp->s_lock, flags);
	tx->qp->s_flags &= ~RVT_S_WAIT_ACK;
	list_add_tail(&tx->txreq.list, &w->tx_head);
	if (!in_thread)
		spin_unlock_irqrestore(&qp->s_lock, flags);
	iowait_set_flag(w->iow, IOWAIT_PENDING_BTS);
	return false;
}

/* called from iowait schedule */
void _hfi1_do_bts_send(struct work_struct *work)
{
	struct iowait_work *w = container_of(work, struct iowait_work, iowork);

	__hfi1_do_bts_send(w, false);
}

static void bts_rdma_complete(struct hfi1_bulksvc_verbs_cmpl *cmpl)
{
	struct hfi1_bulksvc_verbs_cmd *cmd = cmpl->cmd.bts_cmd;
	struct hfi1_bulksvc_qp_info *qp_info = cmd->rdma.qp_info;
	struct verbs_txreq *tx = cmd->rdma.txreq;
	struct hfi1_qp_priv *priv = qp_info->qp_priv;
	struct rvt_qp *qp = priv->owner;
	struct hfi1_ibport *ibp =
		to_iport(qp->ibqp.device, qp->port_num);
	struct hfi1_pportdata *ppd = ppd_from_ibp(ibp);
	struct hfi1_devdata *dd = ppd->dd;

	if ((dd->flags & HFI1_SHUTDOWN))
		return;

	/* tuck rc code in for reference later */
	tx->bts_rc = cmpl->cmd.status;

	/* clear wait flag, allow other things to send now */
	unsigned long flags;

	spin_lock_irqsave(&qp->s_lock, flags);
	rvt_send_complete(tx->qp, tx->wqe, tx->bts_rc, RVT_QP_LOCK_STATE_S);

	/* allow other things to be sent now */
	qp->s_flags &= ~RVT_S_WAIT_ACK;
	hfi1_schedule_send(qp);
	spin_unlock_irqrestore(&qp->s_lock, flags);
	hfi1_qp_wakeup(qp, RVT_S_WAIT_TX);
}

static void bts_mr_reg_complete(struct hfi1_bulksvc_verbs_cmpl *cmpl)
{
}

static void bts_mr_dereg_complete(struct hfi1_bulksvc_verbs_cmpl *cmpl, struct hfi1_bulksvc_verbs_state* verbs_state)
{
	if (cmpl->cmd.status == -EBUSY) {
		pr_warn("verbs dereg_mr returned EBUSY from dms\n");
		// TODO for now, do not retry
		bool const do_retry = false;
		if (do_retry) {
			pr_warn("re-attempting to deregister verbs MR from dms\n");
			struct hfi1_bulksvc_verbs_cmd * cmd = cmpl->cmd.bts_cmd;
			hfi1_bulksvc_verbs_cmd_get(cmd);
			
			unsigned long flags;
			spin_lock_irqsave(&verbs_state->cmd_queue.lock, flags);
			list_add_tail(&cmd->node, &verbs_state->cmd_queue.list);
			spin_unlock_irqrestore(&verbs_state->cmd_queue.lock, flags);
			struct hfi1_bulksvc *svc = container_of(verbs_state,
								struct hfi1_bulksvc,
								verbs_state);
			hfi1_bulksvc_schedule(svc);
		}

	}
}

static void bts_access_complete(struct hfi1_bulksvc_verbs_cmpl *cmpl)
{
	struct hfi1_ibdev *verbs_dev;
	struct rvt_qp *qp;
	struct rvt_dev_info *rdi;
	struct hfi1_devdata *dd;
	struct ib_qp *ibqp;
	struct ib_wc wc;
	int ret;

	if (WARN_ON(!cmpl) || WARN_ON(cmpl->type != HFI1_BULKSVC_VERBS_CMPL_TYPE_ACCESS)) {
		pr_err("bts_access_complete called with invalid cmpl\n");
		return;
	}

	qp = cmpl->access.qp;

	ibqp = &qp->ibqp;
	ret = rvt_get_rwqe(qp, true);
	if (ret <= 0) {
		rdi = ib_to_rvt(ibqp->device);
		verbs_dev = container_of(rdi, struct hfi1_ibdev, rdi);
		dd = container_of(verbs_dev, struct hfi1_devdata, verbs_dev);
		if (ret < 0)
			dd_dev_err(dd, "bulksvc: Error getting rwqe\n");
		else
			dd_dev_dbg(dd, "bulksvc: No rwqe's available\n");

		return;
	}
	if (!__test_and_clear_bit(RVT_R_WRID_VALID, &qp->r_aflags))
		return;

	wc.wr_id = qp->r_wr_id;
	wc.status = IB_WC_SUCCESS;

	if (cmpl->access.flags & HFI1_BULKSVC_VERBS_WRITE_FLAGS_IMMDT) {
		wc.opcode = IB_WC_RECV_RDMA_WITH_IMM;
		wc.wc_flags = IB_WC_WITH_IMM;
		wc.ex.imm_data = cmpl->access.user_immdt_be;
	} else {;
		wc.opcode = IB_WC_RECV;
	}

	wc.qp = &qp->ibqp;
	wc.src_qp = cmpl->access.qp->remote_qpn;
	wc.slid = rdma_ah_get_dlid(&qp->remote_ah_attr) & U16_MAX;
	wc.vendor_err = 0;
	wc.pkey_index = 0;
	wc.dlid_path_bits = 0;
	wc.port_num = 0;
	rvt_recv_cq(qp, &wc, !!(cmpl->access.flags & HFI1_BULKSVC_VERBS_WRITE_FLAGS_SOLICITED), RVT_QP_LOCK_STATE_NONE);
}

void hfi1_bts_handle_verbs_cmpls(struct hfi1_bulksvc_verbs_state* state)
{
	struct list_head cmpls;
	INIT_LIST_HEAD(&cmpls);

	mutex_lock(&state->bulksvc_cmplq.lock);
	list_cut_before(&cmpls, &state->bulksvc_cmplq.list, &state->bulksvc_cmplq.list);
	mutex_unlock(&state->bulksvc_cmplq.lock);

	struct hfi1_bulksvc_verbs_cmpl *cmpl, *tmp;
	list_for_each_entry_safe(cmpl, tmp, &cmpls, node) {
		switch (cmpl->type) {
			case HFI1_BULKSVC_VERBS_CMPL_TYPE_CMD:
				switch (cmpl->cmd.bts_cmd->op) {
				case HFI1_BULKSVC_VERBS_CMD_OP_RDMA:
					bts_rdma_complete(cmpl);
					hfi1_bulksvc_verbs_cmpl_put(cmpl);
					break;
				case HFI1_BULKSVC_VERBS_CMD_OP_MR_REG:
					bts_mr_reg_complete(cmpl);
					hfi1_bulksvc_verbs_cmpl_put(cmpl);
					break;
				case HFI1_BULKSVC_VERBS_CMD_OP_MR_DEREG:
					bts_mr_dereg_complete(cmpl, state);
					hfi1_bulksvc_verbs_cmpl_put(cmpl);
					break;
				}
				break;
			case HFI1_BULKSVC_VERBS_CMPL_TYPE_ACCESS:
				bts_access_complete(cmpl);
				hfi1_bulksvc_verbs_cmpl_put(cmpl);
				break;
		}
	}
}

void _hfi1_bts_handle_verbs_cmpls(struct work_struct *work)
{
	struct hfi1_bulksvc_verbs_state *state =
		container_of(work, struct hfi1_bulksvc_verbs_state, cmpl_work);
	hfi1_bts_handle_verbs_cmpls(state);
}
