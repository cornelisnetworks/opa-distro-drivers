
#ifndef DEF_HFI1_BULKSVC_RVT_H
#define DEF_HFI1_BULKSVC_RVT_H

#include <rdma/rdmavt_qp.h>
#include "bulksvc.h"

/* use bulksvc if size exceeds this */
#define BULKSVC_VERBS_MIN_SEGMENT_SIZE BIT(11) /* 2K Bytes */

/* called in post_send routine
 * check if wqe can be used for bts, if so change op code */ 
bool hfi1_setup_bulksvc_wqe(struct rvt_qp *qp, struct rvt_swqe *wqe);
// Is it possible to get cq reference in this fn?  How do we know what cq to use?

/* called in general IB iowait routine when building rc reqs */
/* adds useful info to tx_list for the bts wait routine to pick up */
void verbs_bulksvc_enqueue(struct hfi1_qp_priv *qpriv, struct verbs_txreq *tx,
			   struct rvt_swqe *wqe);
/* called from qp_schedule when BTS_PENDING bit is set */
bool hfi1_schedule_bts_send(struct rvt_qp *qp);

/* called by iowait func for BTS */
void _hfi1_do_bts_send(struct work_struct *work);

/* notification from verbs stack of user mr reg/dereg */
int verbs_bulksvc_reg_mr(struct hfi1_bulksvc *svc, struct rvt_mregion *mr);
void verbs_bulksvc_dereg_mr(struct hfi1_bulksvc *svc, struct rvt_mregion *mr);

/* called by work_struct func */
void _hfi1_bts_handle_verbs_cmpls(struct work_struct *work);
void hfi1_bts_handle_verbs_cmpls(struct hfi1_bulksvc_verbs_state* state);

#endif /* DEF_HFI1_BULKSVC_RVT_H */
