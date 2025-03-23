// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2023 Cornelis Networks.
 */

/*
 * Implementation details of CPORT communications.
 */

#include <linux/semaphore.h>
#include <linux/io.h>

#include "hfi.h"
#include "chip_jkr.h"
#include "cport.h"

static void cport_send_req_fn(struct work_struct *work);
static void cport_send_rsp_fn(struct work_struct *work);

#undef CPORT_XA_DEBUG	/* every tid assigned from xarray */
#undef CPORT_RCV_DEBUG	/* every message (header) received, and outbox empty */
#undef CPORT_SND_DEBUG	/* every message (header) sent */
#undef CPORT_INT_DEBUG	/* every interrupt processed, and status in timeouts */
/*
 * This limit needs to balance memory consuption against
 * the need to ensure tids don't repeat during periods of
 * CPORT stall and message timeout.
 *
 * Also note that the limit parameter passed to xa_alloc*()
 * gets modified, so we cannot use a static structure here.
 */
#define cport_tid_limit	XA_LIMIT(0, 255)

/*
 * The "header" (first qword) of a message to/from CPORT.
 */
union cport_header {
	struct {
		u64 len:15;
		u64 _resv1:1;
		u64 is_req:1;
		u64 no_rsp:1;
		u64 seq_no:6;
		u64 sts:8;
		u64 tid:16;
		u64 sideband:8;
		u64 op_code:8;
	};
	u64 qw;
};

#define CPORT_SEQNO_MASK 0x3f

#define CPORT_HDR_DEF	0x0000007ec0000000ul
#define CPORT_HDR_LEN	48	/* bit position of length in CPORT_HDR_DEF */

#define CPORT_IN_SCRATCH	(JKR_ASIC_CFG_SCRATCH + 0)
#define CPORT_OUT_SCRATCH	(JKR_ASIC_CFG_SCRATCH + sizeof(u64))

/*
 * Assignment of bits in JKR_MCTXT_CPORT_INT_STATUS and
 * JKR_MCTXT_PF0_INT_STATUS.
 */
#define JKR_MCTXT_INT_OUTBOX_EMPTY	0b00000001
#define JKR_MCTXT_INT_INBOX_FULL	0b00000010

/*
 * The remainder is private to the host driver.
 * CPORT firmware has no need of this interface.
 */

/*
 * How the MCTXT CSRs are interpreted.
 */
union mctxt_mem {
	union cport_header hdr;
	u64 qw[JKR_C_MCTXT_MEM_SIZE_IN_QWORDS];
};

/*
 * The maximum length of a CPORT message payload (cport_header.len).
 * The MCTXT is 2K each direction, and payload length excludes header.
 */
#define CH_LEN_MAX	(sizeof(union mctxt_mem) - sizeof(union cport_header))

/*
 * The common structure used to implement CPORT messages in hfi1.
 */
struct cport_work {
	struct work_struct work;
	struct kref kref;
	int flags;
	long timeout;
	struct semaphore *sem; /* only valid in send, if request w/response */
	struct hfi1_devdata *dd; /* only valid in recv context */
	union mctxt_mem req;
	union mctxt_mem rsp;	/* only used for request w/response */
};

#define CW_FLAG_SEND		0x01	/* struct originated in send */
#define CW_FLAG_RECV		0x02	/* struct originated in receive */
#define CW_FLAG_RQ_ALLOC	0x04	/* request payload was kalloc'ed */
#define CW_FLAG_RS_ALLOC	0x08	/* response payload was kalloc'ed */

/*
 * Acquire a reference to the message structure
 */
static inline void cwget(struct cport_work *cw)
{
	kref_get(&cw->kref);
}

/*
 * Locate and remove the 'id' message in the xarray and atomically
 * acquire a reference to the message structure.
 */
static inline struct cport_work *cwget_xa(struct hfi1_devdata *dd, u32 id)
{
	struct cport_work *cw;

	xa_lock(&dd->cport->tid_xa);
	cw = __xa_erase(&dd->cport->tid_xa, id);
	if (cw)
		cwget(cw);
	xa_unlock(&dd->cport->tid_xa);
	return cw;
}

static void cwrelease(struct kref *kref)
{
	struct cport_work *cw = container_of(kref, struct cport_work, kref);

	/* TODO: any more tear-down? */
	kfree(cw);
}

static void cwput(struct cport_work *cw)
{
	kref_put(&cw->kref, cwrelease);
}

static struct cport_work *cwalloc(int flag)
{
	struct cport_work *cw = kzalloc(sizeof(*cw), GFP_KERNEL);

	if (!cw)
		return NULL;
	cw->flags = flag;
	kref_init(&cw->kref);
	return cw;
}

/* set "external" (non-alloc) response payload */
static void pld_rsp_set(struct cport_work *cw, void *pld, int len)
{
	if (len > CH_LEN_MAX)
		len = CH_LEN_MAX;
	memcpy(&cw->rsp.qw[1], pld, len);
	cw->rsp.hdr.len = len + sizeof(cw->rsp.hdr);
}

/*
 * Send request, non-blocking, with timeout for OUTBOX_EMPTY wait.
 * Caller must watch 'wait' semaphore for completion, and
 * then call cport_send_comp() or cport_send_cancel() to finalize everything.
 * Returns handle for cport_send_comp()/_cancel(), or ERR_PTR().
 *
 * See cport_send_req() for example usage.
 */
void *cport_send_req_nb(struct hfi1_devdata *dd, u8 op, u8 sideband, void *payload,
			int len, struct semaphore *wait, long timeout)
{
	int ret;
	struct cport_work *msg;
	u32 idx;

	if (!dd->cport || len > CH_LEN_MAX)
		return ERR_PTR(-EINVAL);

	msg = cwalloc(CW_FLAG_SEND);
	if (!msg)
		return ERR_PTR(-ENOMEM);
	msg->dd = dd;
	msg->timeout = timeout;
	memcpy(&msg->req.qw[1], payload, len);
	ret = xa_alloc_cyclic(&dd->cport->tid_xa, &idx, msg, cport_tid_limit,
			      &dd->cport->tid_next, GFP_KERNEL);
	if (ret < 0) {
		cwput(msg);
		return ERR_PTR(ret);
	}
#ifdef CPORT_XA_DEBUG
	dd_dev_info(dd, "CPORT tid is %04x\n", idx);
#endif
	msg->req.hdr.op_code = op;
	msg->req.hdr.sideband = sideband;
	msg->req.hdr.is_req = 1;
	msg->req.hdr.no_rsp = 0;
	msg->req.hdr.tid = idx;
	msg->req.hdr.len = len + sizeof(msg->req.hdr);
	msg->sem = wait;
	cwget(msg);	/* extra ref so not freed after send */
	INIT_WORK(&msg->work, cport_send_req_fn);
	queue_work(dd->hfi1_wq, &msg->work);
	return msg;
}

/*
 * Extract results from response and drop (last) reference to structure.
 * Returns status from response header.
 * Must never be called twice for the same message (message has been freed).
 * Must never be called on a message that has not received response (up'ed wait).
 */
int cport_send_comp(struct hfi1_devdata *dd, void *handle,
		    void **rsp_pld, int *rsp_len)
{
	struct cport_work *msg = handle;
	void *ptr;
	int ret;
	int len;

	*rsp_len = len = msg->rsp.hdr.len - sizeof(msg->rsp.hdr);
	if (rsp_pld) {
		ptr = kzalloc(len, GFP_KERNEL);
		if (!ptr)
			return -ENOMEM;
		memcpy(ptr, &msg->rsp.qw[1], len);
		*rsp_pld = ptr;
	}
	ret = msg->rsp.hdr.sts;
	cwput(msg);
	return ret;
}

/*
 * Cleanup aborted wait for response.
 * Only called for requests w/responses.
 * Must never be called twice for the same message (message has been freed).
 */
void cport_send_cancel(struct hfi1_devdata *dd, void *handle)
{
	struct cport_work *msg = handle;

	cancel_work(&msg->work);	/* cport_send() drops ref on all paths */
	xa_erase(&dd->cport->tid_xa, msg->req.hdr.tid);
	cwput(msg);
}

/*
 * Send request and wait for response, with timeout.
 * Caller must be able to sleep.
 * Returns status from response header, and response payload data, on success.
 * Response payload was from k[z]alloc() and caller must kfree().
 * On error, returns -errno (response status is always 0-15).
 */
int cport_send_req(struct hfi1_devdata *dd, u8 op, u8 sideband, void *payload, int len,
		   void **rsp_pld, int *rsp_len, long timeout)
{
	int ret;
	struct cport_work *msg;
	DEFINE_SEMAPHORE(comp);
	/* XXX Do we need to do a down() here? It defaults to 1 I think*/
	down(&comp);

	might_sleep();

	msg = cport_send_req_nb(dd, op, sideband, payload, len, &comp, timeout);
	if (IS_ERR(msg))
		return PTR_ERR(msg);
	if (timeout > 0 && timeout != MAX_SCHEDULE_TIMEOUT)
		ret = down_timeout(&comp, timeout);
	else
		ret = down_killable(&comp);
	if (ret) {
#ifdef CPORT_INT_DEBUG
		u64 ints;

		ints = read_csr(dd, JKR_MCTXT_PF0_INT_STATUS);
		dd_dev_err(dd, "CPORT request wait interrupted %016llx (%d) [%02llx]\n",
			   msg->req.hdr.qw, ret, ints);
#else
		dd_dev_err(dd, "CPORT request wait interrupted %016llx (%d)\n",
			   msg->req.hdr.qw, ret);
#endif
		cport_send_cancel(dd, msg);
		return ret;
	}
	return cport_send_comp(dd, msg, rsp_pld, rsp_len);
}

int cport_send_notif(struct hfi1_devdata *dd, u8 op, u8 sideband, void *payload, int len)
{
	struct cport_work *msg;

	if (!dd->cport || len > CH_LEN_MAX)
		return -EINVAL;

	msg = cwalloc(CW_FLAG_SEND);
	if (!msg)
		return -ENOMEM;
	msg->dd = dd;
	memcpy(&msg->req.qw[1], payload, len);
	msg->req.hdr.len = len + sizeof(msg->req.hdr);
	msg->req.hdr.op_code = op;
	msg->req.hdr.sideband = sideband;
	msg->req.hdr.is_req = 1;
	msg->req.hdr.no_rsp = 1;
	INIT_WORK(&msg->work, cport_send_req_fn);
	queue_work(dd->hfi1_wq, &msg->work);
	return 0;
}

/*
 ********************************************************************
 * Internal routines.
 */

/*
 * Send a response to CPORT's request.
 *
 * Re-uses message structure from request. Queues to send workqueue.
 */
static int cport_send_rsp(struct cport_work *msg, int sts)
{
	struct hfi1_devdata *dd = msg->dd;

	/* rsp.hdr.len and rsp.qw[1..] already setup, also rsp.op_code/rsp.tid */
	msg->rsp.hdr.is_req = 0;
	msg->rsp.hdr.sts = sts;
	INIT_WORK(&msg->work, cport_send_rsp_fn);
	queue_work(dd->hfi1_wq, &msg->work);
	return 0;
}

static void cport_send(struct cport_work *msg, bool req)
{
	int len;
	u64 *ptr;
	u32 i;
	int ret;
	struct hfi1_devdata *dd = msg->dd;
	union mctxt_mem *mc = req ? &msg->req : &msg->rsp;

	/* sleep until OutboxEmpty... */
	if (msg->timeout > 0 && msg->timeout != MAX_SCHEDULE_TIMEOUT)
		ret = down_timeout(&dd->cport->outbox, msg->timeout);
	else
		ret = down_killable(&dd->cport->outbox);
	if (ret) {
		dd_dev_err(dd, "CPORT Send OUTBOX_EMPTY killed %016llx (%d)\n",
			   msg->req.hdr.qw, ret);
		cwput(msg);
		return;	/* no way to report error to caller */
	}
	mc->hdr.seq_no = atomic_fetch_inc(&dd->cport->seqno);
#ifdef CPORT_SND_DEBUG
	dd_dev_info(dd, "MCTXT sent %016llx\n", mc->hdr.qw);
#endif
	len = mc->hdr.len; /* msg len == pkt len, >= sizeof(u64) */
	ptr = &mc->qw[0];
	/* NOTE: "CPORT IN" is our output */
	i = JKR_MCTXT_CPORT_IN;
	write_csr(dd, CPORT_IN_SCRATCH, CPORT_HDR_DEF | ((u64)len << CPORT_HDR_LEN));
	/* since buffer is full MCTXT, last bytes can be sent as qword. */
	while (len > 0) {
		write_csr(dd, i, *ptr++);
		i += sizeof(u64);
		len -= sizeof(u64);
	}
	write_csr(dd, JKR_MCTXT_CPORT_INT_STATUS, JKR_MCTXT_INT_INBOX_FULL);
	cwput(msg); /* may or may not free memory */
}

/*
 * Low-level send to CPORT via MCTXT.
 *
 * Interfaces with MCTXT.
 */
static void cport_send_req_fn(struct work_struct *work)
{
	struct cport_work *msg = container_of(work, struct cport_work, work);

	cport_send(msg, true);
}

static void cport_send_rsp_fn(struct work_struct *work)
{
	struct cport_work *msg = container_of(work, struct cport_work, work);

	cport_send(msg, false);
}

static int echo_req(struct hfi1_devdata *dd, u8 op, u8 sideband,
		    void *pld, int pll, void *handle)
{
	struct cport_work *msg = handle;

	dd_dev_info(msg->dd, "cport ping %02x (%d)\n", sideband, pll);
	/* Leave payload in-tact (echo). */
	pld_rsp_set(msg, pld, pll);
	return MSG_RSP_STATUS_OK;
}

static int inval_req(struct hfi1_devdata *dd, u8 op, u8 sideband,
		     void *pld, int pll, void *handle)
{
	return MSG_RSP_STATUS_OPCODE_UNSUPPORTED;
}

/*
 * Process a request from CPORT.
 *
 * May be dispatched to external function from handlers[].
 */
static void cport_req_fn(struct work_struct *work)
{
	struct cport_work *msg = container_of(work, struct cport_work, work);
	cport_handler func;
	int ret = MSG_RSP_STATUS_OK;
	void *pld;
	int pll;

	pll = msg->req.hdr.len - sizeof(msg->req.hdr);
	pld = &msg->req.qw[1];
	msg->rsp.hdr.qw = msg->req.hdr.qw;
	/* default to no payload in response (if any) */
	msg->rsp.hdr.len = sizeof(msg->req.hdr);
	func = msg->dd->cport->handlers[msg->req.hdr.op_code];
	if (func)
		ret = func(msg->dd, msg->req.hdr.op_code, msg->req.hdr.sideband,
			   pld, pll, msg);
	else
		ret = inval_req(msg->dd, msg->req.hdr.op_code, msg->req.hdr.sideband,
				pld, pll, msg);
	if (msg->req.hdr.no_rsp) {
		cwput(msg);
		if (ret)
			dd_dev_err(msg->dd, "Op %d %02x failed (%d)\n",
				   msg->req.hdr.op_code, msg->req.hdr.sideband, ret);
	} else {
		/* msg->rsp.qw[*] and msg->rsp.hdr.len have been updated */
		ret = cport_send_rsp(msg, ret);
		if (ret)
			dd_dev_err(msg->dd, "Response send failed (%d)\n", ret);
	}
}

/*
 * Handler for MCTXT Inbox Full interrupt.
 *
 * Only one can be queued/run until JKR_MCTXT_INT_OUTBOX_EMPTY is cleared.
 * Run in a workqueue (not interrupt context).
 */
static void cport_mctxt_fn(struct work_struct *work)
{
	struct hfi1_cport *cport = container_of(work, struct hfi1_cport, mctxt_work);
	struct hfi1_devdata *dd = cport->dd;
	int ret = 0;
	int len;
	u64 *ptr;
	u32 i;
	struct cport_work *msg;
	union cport_header hdr;

	/*
	 * CPORT output MCTXT is our input.
	 */
	i = JKR_MCTXT_CPORT_OUT;
	/*
	 * This header ignored:
	 * mhdr = read_csr(dd, CPORT_OUT_SCRATCH);
	 * assert(mhdr.PKT_LEN_BYTES == hdr.len);
	 */
	hdr.qw = read_csr(dd, i);
#ifdef CPORT_RCV_DEBUG
	dd_dev_info(dd, "cport_mctxt_fn() %016llx\n", hdr.qw);
#endif
	i += sizeof(u64);
	/* No need for atomics here, we are single threaded */
	if (hdr.seq_no != cport->rseqno) {
		dd_dev_info(dd, "Recv out of sequence: %d -> %d\n", cport->rseqno, hdr.seq_no);
		cport->rseqno = hdr.seq_no;
	}
	cport->rseqno = (cport->rseqno + 1) & CPORT_SEQNO_MASK;
	if (hdr.is_req) {
		/* Request from CPORT, has no existing message context */
		msg = cwalloc(CW_FLAG_RECV);
		if (!msg) {
			ret = -ENOMEM;
			goto fail; /* drop message, with error */
		}
		ptr = &msg->req.qw[0];
	} else {
		/*
		 * Responses already have a 'msg', extra ref was already taken.
		 * Take an additional ref against possible race with timeout
		 * (cport_send_cancel()) between here and the up().
		 */
		msg = cwget_xa(dd, hdr.tid);
		if (!msg) {
			ret = -ESRCH;
			goto fail; /* drop message, with error */
		}
		ptr = &msg->rsp.qw[0];
		/* assert msg->req.hdr ~= hdr */
	}
	*ptr++ = hdr.qw;
	/* now copy payload into chosen buffer */
	len = hdr.len - sizeof(hdr);
	while (len > 0) {
		*ptr++ = read_csr(dd, i);
		i += sizeof(u64);
		len -= sizeof(u64);
	}
	/*
	 * We are finished with the dd->cport->mctxt_work struct,
	 * and the MCTXT, so it can all be re-used now.
	 */
	write_csr(dd, JKR_MCTXT_CPORT_INT_STATUS, JKR_MCTXT_INT_OUTBOX_EMPTY);
#ifdef CPORT_RCV_DEBUG
	dd_dev_info(dd, "cport_mctxt_fn() set CPORT OUTBOX_EMPTY\n");
#endif

	/* responses don't require any more work here - just wakeup requester */
	if (!hdr.is_req) {
		up(msg->sem);
		cwput(msg);
		return;
	}
	/* TODO: can we just process the CPORT request in this thread? */
	msg->dd = dd;
	/* dispatch 'msg' request */
	INIT_WORK(&msg->work, cport_req_fn);
	/* don't care about locality */
	queue_work(dd->hfi1_wq, &msg->work);
	return;
fail:
	write_csr(dd, JKR_MCTXT_CPORT_INT_STATUS, JKR_MCTXT_INT_OUTBOX_EMPTY);
	dd_dev_err(dd, "Dropping incoming CPORT message %016llx (%d)\n", hdr.qw, ret);
}

/*
 * Handler for PF0 MCTXT interrupts.
 *
 * Called when one of the enabled MCTXT_PF0 conditions occurs.
 * 'source' is always 0. Called in interrupt context.
 *
 * Since this interrupt is exclusive to MCTXT, there is no doubt
 * about which transport to use (always is MCTXT).
 */
void is_cport_int(struct hfi1_devdata *dd, unsigned int source)
{
	u64 ints;

	if (!dd->cport)
		return;

#ifdef CONFIG_HFI_CPORT_POLLING
	ints = read_csr(dd, JKR_MCTXT_PF0_INT_STATUS);
#else
	ints = read_csr(dd, JKR_MCTXT_PF0_INT_STATUS_ENABLED);
#endif
	if (!ints) {
		dd_dev_warn(dd, "MCTXT interrupt, but no status bits set\n");
		return;
	}
	write_csr(dd, JKR_MCTXT_PF0_INT_ACK, ints);
#ifdef CPORT_INT_DEBUG
	dd_dev_info(dd, "is_cport_int() %02llx\n", ints);
#endif
	if (ints & JKR_MCTXT_INT_INBOX_FULL)
		queue_work(dd->hfi1_wq, &dd->cport->mctxt_work);
	if (ints & JKR_MCTXT_INT_OUTBOX_EMPTY)
		up(&dd->cport->outbox);
}

void is_cport_name(char *buf, size_t bsize, unsigned int source)
{
	snprintf(buf, bsize, "cport");
}

/***************************************************
 * API for handling notifications from CPORT
 */

void *cport_resp_alloc(void *handle, int len)
{
	struct cport_work *msg = handle;

	if (!msg || len <= 0 || len > CH_LEN_MAX)
		return NULL;
	msg->rsp.hdr.len = len + sizeof(msg->rsp.hdr);
	return &msg->rsp.qw[1];
}

int cport_resp_set(void *handle, void *payload, int len)
{
	struct cport_work *msg = handle;

	if (!msg || !payload || len <= 0 || len > CH_LEN_MAX)
		return -EINVAL;
	msg->rsp.hdr.len = len + sizeof(msg->rsp.hdr);
	memcpy(&msg->rsp.qw[1], payload, len);
	return 0;
}

int cport_register_cb(struct hfi1_devdata *dd, u8 op_start, u8 op_end, cport_handler func)
{
	int x;

	if (op_start > op_end || op_start < 0 || op_end >= 256)
		return -ERANGE;
	if (!dd->cport)
		return -EINVAL;

	/* 'func' may be NULL, to unregister */
	for (x = op_start; x <= op_end; ++x) {
		/* TODO: what if already registered? */
		dd->cport->handlers[x] = func;
	}
	return 0;
}

static int cport_ping(void *data)
{
	struct hfi1_devdata *dd = data;
	char buf[16];
	int len;
	unsigned int num;
	void *rspbuf;
	int rsplen;
	int rc;

	while (!kthread_should_stop() && (num = atomic_read(&dd->cport->nping)) > 0) {
		len = snprintf(buf, sizeof(buf), "ping %u", num);
		rspbuf = NULL;
		rc = cport_send_req(dd, CH_OP_PING, 0, buf, len,
				    &rspbuf, &rsplen, MAX_SCHEDULE_TIMEOUT);
		if (rc < 0) {
			dd_dev_info(dd, "CPORT \"%s\" error %d\n", buf, rc);
			break;
		}
		dd_dev_info(dd, "CPORT \"%s\" -> %d \"%.*s\"\n",
			    buf, rc, rsplen, (char *)rspbuf);
		kfree(rspbuf);
		atomic_dec(&dd->cport->nping);
	}
	dd->cport->ping_th = NULL;
	atomic_set(&dd->cport->nping, 0);
	return 0;
}

int cport_ping_start(struct hfi1_devdata *dd, unsigned int count)
{
	int rc;

	/* TODO: avoid race(s) with exiting kthread */
	if (!count) {
		if (dd->cport->ping_th)
			kthread_stop(dd->cport->ping_th);
			/* kthread will zero count when exiting */
		else
			atomic_set(&dd->cport->nping, 0);
		return 0;
	}
	atomic_set(&dd->cport->nping, count);
	if (dd->cport->ping_th)
		return 0;

	dd->cport->ping_th = kthread_create_on_node(cport_ping, dd, dd->node, "cport_ping");
	if (IS_ERR(dd->cport->ping_th)) {
		rc = PTR_ERR(dd->cport->ping_th);
		dd->cport->ping_th = NULL;
		dd_dev_err(dd, "Failed to create CPORT ping thread %d\n", rc);
		return rc;
	}
	wake_up_process(dd->cport->ping_th);
	return 0;
}

#ifdef CONFIG_HFI_CPORT_POLLING
static int cport_poll(void *data)
{
	struct hfi1_devdata *dd = data;
	u64 v;

	while (!kthread_should_stop()) {
		v = read_csr(dd, JKR_MCTXT_PF0_INT_STATUS);
		if (v & 0xff)
			is_cport_int(dd, 0);
		fsleep(30);
	}
	return 0;
}
#endif

/*
 * Initialization/setup of MCTXT CPORT communications channel.
 */
int cport_init(struct hfi1_devdata *dd)
{
	struct hfi1_cport *cport;

	if (dd->params->chip_type == CHIP_WFR)
		return 0;

	cport = kzalloc(sizeof(*cport), GFP_KERNEL);
	if (!cport)
		goto err1;

	INIT_WORK(&cport->mctxt_work, cport_mctxt_fn);
	xa_init_flags(&cport->tid_xa, XA_FLAGS_ALLOC);
	xa_init_flags(&cport->trap_xa, XA_FLAGS_ALLOC);

	/*
	 * Setting initial state can be problematic.
	 * We require that CPORT set JKR_MCTXT_INT_OUTBOX_EMPTY in
	 * JKR_MCTXT_PF0_INT_STATUS or we will never start sending.
	 * We also require that CPORT never set JKR_MCTXT_INT_OUTBOX_EMPTY
	 * gratuitously, or we get a semaphore count > 1 and will
	 * start overrunning MCTXT. Essentially, CPORT must set this
	 * exactly once when entering the "ready to receive" state
	 * (initially and after processing each message).
	 */
	sema_init(&cport->outbox, 0);

	cport->dd = dd;
	dd->cport = cport;

	cport_register_cb(dd, CH_OP_PING, CH_OP_PING, echo_req);

#ifdef CONFIG_HFI_CPORT_POLLING
	cport->poll_th = kthread_create_on_node(cport_poll, dd, dd->node, "cport_poll");
	if (!cport->poll_th)
		dd_dev_err(dd, "Failed to create CPORT polling thread\n");
	else
		wake_up_process(dd->cport->poll_th);
#else
	/* Enable intr source for MCTXT from CPORT (to PF0) */
	write_csr(dd, JKR_MCTXT_PF0_INT_ENABLE,
		  JKR_MCTXT_INT_INBOX_FULL | JKR_MCTXT_INT_OUTBOX_EMPTY);
	set_intr_bits(dd, JKR_MCTXT_CPORT_TO_PCIE_INT, JKR_MCTXT_CPORT_TO_PCIE_INT, true);
#endif

	/*
	 * Must reset/resync sequence numbers as CPORT is strictly enforcing
	 * sequence number order.
	 */
	cport_send_notif(dd, CH_OP_PING, 0, NULL, 0);
	return 0;

err1:
	return -ENOMEM;
}

/*
 * Deinitialization of MCTXT CPORT communications channel.
 */
int cport_exit(struct hfi1_devdata *dd)
{
	if (!dd->cport)
		return 0;

	/* Disable intr source for MCTXT from CPORT (to PF0) */
	set_intr_bits(dd, JKR_MCTXT_CPORT_TO_PCIE_INT, JKR_MCTXT_CPORT_TO_PCIE_INT, false);
	write_csr(dd, JKR_MCTXT_PF0_INT_ENABLE, 0);
	/* leave JKR_MCTXT_INT_OUTBOX_EMPTY set so that future users are ready-to-go */
	write_csr(dd, JKR_MCTXT_PF0_INT_STATUS, JKR_MCTXT_INT_OUTBOX_EMPTY);
#ifdef CONFIG_HFI_CPORT_POLLING
	if (dd->cport->poll_th)
		kthread_stop(dd->cport->poll_th);
#endif
	if (dd->cport->ping_th)
		kthread_stop(dd->cport->ping_th);

	cancel_work(&dd->cport->mctxt_work);

	xa_destroy(&dd->cport->tid_xa);
	xa_destroy(&dd->cport->trap_xa);
	kfree(dd->cport);
	dd->cport = NULL;

	return 0;
}
