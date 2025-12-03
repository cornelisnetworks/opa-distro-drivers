// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 */

#include "hfi.h"
#include "user_sdma.h"
#include "uverbs.h"
#include "file_ops.h"
#include "bulksvc.h"

#define UVERBS_MODULE_NAME hfi1_uv
#include <rdma/uverbs_named_ioctl.h>

static const u64 zero8; /* 8 bytes of 0 */

/*
 * RDMA mmap token: <type> << <page offset>
 *
 * Expect type to be less than 256 (8 bits).  rdmavt reserves the bottom 256
 * tokens for the driver.  A type of zero is always considered invalid.
 * Types >= 256 are used for rdmavt's dynamic token generation.
 */

/* convert RDMA mmap token to type: the first 8 bits above a page */
static inline u8 rdma_mmap_get_type(unsigned long token)
{
	return token >> PAGE_SHIFT;
}

/* calculate the token from a pointer offset */
static inline unsigned long rdma_mmap_token_p(u8 type, void *offset)
{
	return rdma_mmap_token_i(type, (unsigned long)offset);
}

int hfi1_alloc_ucontext(struct ib_ucontext *ucontext, struct ib_udata *udata)
{
	struct hfi1_devdata *dd = dd_from_ibdev(ucontext->device);
	struct rvt_ucontext *rcontext = container_of(ucontext, struct rvt_ucontext, ibucontext);
	struct hfi1_filedata *fd;

	fd = hfi1_alloc_filedata(dd);
	if (!fd)
		return -ENOMEM;

	rcontext->priv = fd;

	return 0;
}

void hfi1_dealloc_ucontext(struct ib_ucontext *ucontext)
{
	struct rvt_ucontext *rcontext = container_of(ucontext, struct rvt_ucontext, ibucontext);
	struct hfi1_filedata *fd;

	fd = rcontext->priv;
	if (fd) {
		hfi1_dealloc_filedata(fd);
		rcontext->priv = NULL;
	}
}

static inline struct hfi1_filedata *fd_from_attrs(struct uverbs_attr_bundle *attrs)
{
	struct ib_ucontext *ucontext = ib_uverbs_get_ucontext(attrs);
	struct rvt_ucontext *rcontext = container_of(ucontext, struct rvt_ucontext, ibucontext);

	return rcontext->priv;
}

static int UVERBS_HANDLER(HFI1_METHOD_ASSIGN_CTXT)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_assign_ctxt_cmd cmd;
	unsigned int swmajor;
	int ret;

	ret = uverbs_copy_from(&cmd, attrs, HFI1_ATTR_ASSIGN_CTXT_CMD);
	if (ret)
		return ret;

	swmajor = cmd.userversion >> HFI1_SWMAJOR_SHIFT;
	if (swmajor != HFI1_RDMA_USER_SWMAJOR)
		return -ENODEV;

	if (cmd.reserved1 != 0 || cmd.reserved2 != 0)
		return -EINVAL;

	return hfi1_do_assign_ctxt(fd, &cmd);
};

static int UVERBS_HANDLER(HFI1_METHOD_CTXT_INFO)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_ctxt_info_rsp rsp = {};

	if (!uctxt)
		return -EINVAL;

	rsp.runtime_flags = (((uctxt->flags >> HFI1_CAP_MISC_SHIFT) &
				HFI1_CAP_MISC_MASK) << HFI1_CAP_USER_SHIFT) |
#ifdef NVIDIA_GPU_DIRECT
			    HFI1_CAP_GPUDIRECT_OT |
#endif
			    HFI1_CAP_UGET_MASK(uctxt->flags, MASK) |
			    HFI1_CAP_KGET_MASK(uctxt->flags, K2U);
	/* adjust flag if this fd is not able to cache */
	if (!fd->use_mn)
		rsp.runtime_flags |= HFI1_CAP_TID_UNMAP; /* no caching */

	rsp.num_active = hfi1_count_active_units();
	rsp.unit = uctxt->dd->unit;
	rsp.ctxt = uctxt->ctxt;
	rsp.subctxt = fd->subctxt;
	rsp.rcvtids = roundup(uctxt->egrbufs.alloced,
			      uctxt->dd->rcv_entries.group_size) +
		      uctxt->expected_count;
	rsp.credits = uctxt->sc->credits;
	rsp.numa_node = uctxt->numa_id;
	rsp.rec_cpu = fd->rec_cpu_num;
	rsp.send_ctxt = uctxt->sc->hw_context;

	rsp.egrtids = uctxt->egrbufs.alloced;
	rsp.rcvhdrq_cnt = get_hdrq_cnt(uctxt);
	rsp.rcvhdrq_entsize = get_hdrqentsize(uctxt) << 2;
	rsp.sdma_ring_size = fd->cq->nentries;
	rsp.rcvegr_size = uctxt->egrbufs.rcvtid_size;

	return uverbs_copy_to(attrs, HFI1_ATTR_CTXT_INFO_RSP, &rsp,
			      sizeof(rsp));
};

static int UVERBS_HANDLER(HFI1_METHOD_USER_INFO)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_user_info_rsp rsp = {};
	struct hfi1_devdata *dd;
	unsigned long offset;

	if (!uctxt)
		return -EINVAL;
	dd = uctxt->dd;

	rsp.hw_version = dd->revision;
	rsp.sw_version = HFI1_USER_SWVERSION;
	rsp.bthqp = RVT_KDETH_QP_PREFIX;
	rsp.jkey = uctxt->jkey;
	/*
	 * If more than 64 contexts are enabled, the allocated credit return
	 * will span two or three contiguous pages. Only the page containing
	 * the context's credit return address is mapped.  Calculate the offset
	 * in the proper page.
	 */
	offset = ((u64)uctxt->sc->hw_free -
		  (u64)dd->cr_base[uctxt->numa_id].va) % PAGE_SIZE;
	rsp.sc_credits_addr = rdma_mmap_token_i(PIO_CRED, offset);
	rsp.pio_bufbase = rdma_mmap_token_p(PIO_BUFS, uctxt->sc->base_addr);
	rsp.pio_bufbase_sop = rdma_mmap_token_p(PIO_BUFS_SOP,
						uctxt->sc->base_addr);
	rsp.rcvhdr_bufbase = rdma_mmap_token_p(RCV_HDRQ, uctxt->rcvhdrq);
	rsp.rcvegr_bufbase = rdma_mmap_token_i(RCV_EGRBUF,
					       uctxt->egrbufs.rcvtids[0].dma);
	rsp.sdma_comp_bufbase = rdma_mmap_token_i(SDMA_COMP, 0);
	/*
	 * user regs are at
	 * (RXE_PER_CONTEXT_USER + (ctxt * RXE_PER_CONTEXT_SIZE))
	 */
	rsp.user_regbase = rdma_mmap_token_i(UREGS, 0);
	offset = offset_in_page((uctxt_offset(uctxt) + fd->subctxt) *
				sizeof(*dd->events));
	rsp.events_bufbase = rdma_mmap_token_i(EVENTS, offset);
	rsp.status_bufbase = rdma_mmap_token_p(STATUS, dd->status);
	if (HFI1_CAP_IS_USET(DMA_RTAIL))
		rsp.rcvhdrtail_base = rdma_mmap_token_i(RTAIL, 0);
	if (uctxt->subctxt_cnt) {
		rsp.subctxt_uregbase = rdma_mmap_token_i(SUBCTXT_UREGS, 0);
		rsp.subctxt_rcvhdrbuf = rdma_mmap_token_i(SUBCTXT_RCV_HDRQ, 0);
		rsp.subctxt_rcvegrbuf = rdma_mmap_token_i(SUBCTXT_EGRBUF, 0);
	}

	if (dd->params->chip_type != CHIP_WFR)
		rsp.rheq_bufbase = rdma_mmap_token_p(RCV_RHEQ, uctxt->rcvhdrq);

	return uverbs_copy_to(attrs, HFI1_ATTR_USER_INFO_RSP, &rsp,
			      sizeof(rsp));
};

static int UVERBS_HANDLER(HFI1_METHOD_TID_UPDATE)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_tid_info_v3 tinfo = {};
	struct hfi1_tid_update_cmd cmd;
	struct hfi1_tid_update_rsp rsp = {};
	int ret;

	if (!fd->uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI1_ATTR_TID_UPDATE_CMD);
	if (ret)
		return ret;

	/* reserved .flags bits must be 0 */
	if (cmd.flags & HFI1_TID_UPDATE_V3_FLAGS_RESERVED_MASK)
		return -EINVAL;
	/* reserved for now */
	if (cmd.context)
		return -EINVAL;

	/* copy to internal structure */
	tinfo.vaddr = cmd.vaddr;
	tinfo.tidlist = cmd.tidlist;
	tinfo.length = cmd.length;
	tinfo.tidcnt = cmd.tidcnt;
	tinfo.flags = cmd.flags;
	tinfo.context = cmd.context;

	ret = hfi1_user_exp_rcv_setup(fd, &tinfo, false, true);
	if (ret)
		return ret;

	rsp.length = tinfo.length;
	rsp.tidcnt = tinfo.tidcnt;
	ret = uverbs_copy_to(attrs, HFI1_ATTR_TID_UPDATE_RSP, &rsp,
			     sizeof(rsp));
	if (!ret)
		hfi1_user_exp_rcv_clear(fd, (struct hfi1_tid_info *)&tinfo);

	return ret;
};

static int UVERBS_HANDLER(HFI1_METHOD_TID_FREE)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_tid_info tinfo = {};
	struct hfi1_tid_free_cmd cmd;
	struct hfi1_tid_free_rsp rsp = {};
	int ret;

	if (!fd->uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI1_ATTR_TID_FREE_CMD);
	if (ret)
		return ret;

	if (cmd.reserved != 0)
		return -EINVAL;

	tinfo.tidlist = cmd.tidlist;
	tinfo.tidcnt = cmd.tidcnt;

	ret = hfi1_user_exp_rcv_clear(fd, &tinfo);
	if (!ret)
		return ret;

	rsp.tidcnt = tinfo.tidcnt;

	return uverbs_copy_to(attrs, HFI1_ATTR_TID_FREE_RSP, &rsp,
			      sizeof(rsp));
};

static int UVERBS_HANDLER(HFI1_METHOD_CREDIT_UPD)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_ctxtdata *uctxt = fd->uctxt;

	if (!uctxt)
		return -EINVAL;
	sc_return_credits(uctxt->sc);

	return 0;
};

static int UVERBS_HANDLER(HFI1_METHOD_RECV_CTRL)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_recv_ctrl_cmd cmd;
	int ret;

	if (!uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI1_ATTR_RECV_CTRL_CMD);
	if (ret)
		return ret;

	/* verify small reserved array of u8s is zero */
	if (memcmp(cmd.reserved, &zero8, sizeof(cmd.reserved)) != 0)
		return -EINVAL;

	return manage_rcvq(uctxt, fd->subctxt, cmd.start_stop);
};

static int UVERBS_HANDLER(HFI1_METHOD_POLL_TYPE)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_poll_type_cmd cmd;
	int ret;

	if (!uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI1_ATTR_POLL_TYPE_CMD);
	if (ret)
		return ret;

	if (cmd.reserved != 0)
		return -EINVAL;

	uctxt->poll_type = (typeof(uctxt->poll_type))cmd.poll_type;

	return 0;
};

static int UVERBS_HANDLER(HFI1_METHOD_ACK_EVENT)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_ack_event_cmd cmd;
	int ret;

	if (!uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI1_ATTR_ACK_EVENT_CMD);
	if (ret)
		return ret;

	return user_event_ack(uctxt, fd->subctxt, cmd.event);
};

static int UVERBS_HANDLER(HFI1_METHOD_SET_PKEY)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_set_pkey_cmd cmd;
	int ret;

	if (!uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI1_ATTR_SET_PKEY_CMD);
	if (ret)
		return ret;

	/* verify small reserved array of u8s is zero */
	if (memcmp(cmd.reserved, &zero8, sizeof(cmd.reserved)) != 0)
		return -EINVAL;

	return set_ctxt_pkey(uctxt, cmd.pkey);
};

static int UVERBS_HANDLER(HFI1_METHOD_CTXT_RESET)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_ctxtdata *uctxt = fd->uctxt;

	if (!uctxt)
		return -EINVAL;

	return ctxt_reset(uctxt);
};

static int UVERBS_HANDLER(HFI1_METHOD_TID_INVAL_READ)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_tid_info tinfo = {};
	struct hfi1_tid_inval_read_cmd cmd;
	struct hfi1_tid_inval_read_rsp rsp = {};
	int ret;

	if (!fd->uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI1_ATTR_TID_INVAL_READ_CMD);
	if (ret)
		return ret;

	if (cmd.reserved != 0)
		return -EINVAL;

	tinfo.tidlist = cmd.tidlist;
	tinfo.tidcnt = cmd.tidcnt;

	ret = hfi1_user_exp_rcv_invalid(fd, &tinfo, true);
	if (!ret)
		return ret;

	rsp.tidcnt = tinfo.tidcnt;

	return uverbs_copy_to(attrs, HFI1_ATTR_TID_INVAL_READ_RSP, &rsp,
			      sizeof(rsp));
};

static int UVERBS_HANDLER(HFI1_METHOD_GET_VERS)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_get_vers_rsp rsp = {};

	rsp.version = HFI1_RDMA_USER_SWVERSION;
	return uverbs_copy_to(attrs, HFI1_ATTR_GET_VERS_RSP, &rsp, sizeof(rsp));
};

static int UVERBS_HANDLER(HFI1_METHOD_PIN_STATS)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_pin_stats_cmd cmd;
	struct hfi1_pin_stats_rsp rsp = {};
	struct hfi1_pin_stats stats = {};
	int ret;

	if (!fd->uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI1_ATTR_PIN_STATS_CMD);
	if (ret)
		return ret;

	stats.memtype = cmd.memtype;
	stats.index = cmd.index;
	ret = hfi1_get_pinning_stats(fd, &stats);
	if (ret)
		return ret;

	rsp.id = stats.id;
	rsp.cache_entries = stats.cache_entries;
	rsp.total_refcounts = stats.total_refcounts;
	rsp.total_bytes = stats.total_bytes;
	rsp.hits = stats.hits;
	rsp.misses = stats.misses;
	rsp.internal_evictions = stats.internal_evictions;
	rsp.external_evictions = stats.external_evictions;

	return uverbs_copy_to(attrs, HFI1_ATTR_PIN_STATS_RSP, &rsp,
			      sizeof(rsp));
};

static int UVERBS_HANDLER(HFI1_METHOD_BULKSVC_GET_CMPLQ)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_bulksvc_queue_info *rsp;
	int ret;

	if (!fd->bulksvc_user_info || !fd->dd->bulksvc)
		return -EINVAL;

	struct hfi1_bulksvc_user_info* const bulksvc_user_info = fd->bulksvc_user_info;

	ret = create_bulksvc_queue(fd->dd, bulksvc_user_info, true, true, &rsp);
	if (ret)
		return ret;

	return uverbs_copy_to(attrs, HFI1_ATTR_BULKSVC_GET_CMPLQ_RSP, rsp,
			      sizeof(*rsp));
}

static int UVERBS_HANDLER(HFI1_METHOD_BULKSVC_GET_CMDQ)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_bulksvc_queue_info *rsp;
	int ret;

	if (!fd->bulksvc_user_info || !fd->dd->bulksvc)
		return -EINVAL;

	struct hfi1_bulksvc_user_info* const bulksvc_user_info = fd->bulksvc_user_info;

	ret = create_bulksvc_queue(fd->dd, bulksvc_user_info, false, true, &rsp);
	if (ret)
		return ret;

	return uverbs_copy_to(attrs, HFI1_ATTR_BULKSVC_GET_CMDQ_RSP, rsp,
			      sizeof(*rsp));
}

static int UVERBS_HANDLER(HFI1_METHOD_BULKSVC_CLIENT_INIT)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_bulksvc_client_init rsp;
	int ret;

	if (!fd->dd || !fd->dd->bulksvc)
		return -EINVAL;

	ret = init_bulksvc_client(fd, &rsp);
	if (ret)
		return ret;

	ret = uverbs_copy_to(attrs, HFI1_ATTR_BULKSVC_CLIENT_INIT_RSP,
			     &rsp, sizeof(rsp));
	if (ret)
		hfi1_bulksvc_user_info_put(fd->bulksvc_user_info);

	return ret;
}

static int UVERBS_HANDLER(HFI1_METHOD_BULKSVC_DOORBELL)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);

	if (!fd->dd || !fd->dd->bulksvc || !fd->bulksvc_user_info)
		return -EINVAL;

	hfi1_bulksvc_schedule(fd->dd->bulksvc);

	return 0;
}

static int UVERBS_HANDLER(HFI1_METHOD_BULKSVC_SYNCCMD)(struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	int ret;

	if (!fd->bulksvc_user_info || !fd->dd->bulksvc) {
		return -EINVAL;
	}

	struct hfi1_bulksvc_cmd_hdr hdr;
	ret = uverbs_copy_from_or_zero(&hdr, attrs, HFI1_ATTR_BULKSVC_SYNCCMD);
	if (ret != 0) {
		pr_err("failed to copy bulksvc cmd hdr from user, rc %d\n", ret);
		return ret;
	}

	struct hfi1_bulksvc_cmd *cmd = kzalloc(hdr.num_blocks * CACHELINE_SIZE, GFP_KERNEL);
	if (!cmd) {
		pr_err("failed to allocate bulksvc synccmd\n");
		return -ENOMEM;
	}

	ret = _uverbs_copy_from_or_zero(cmd, attrs, HFI1_ATTR_BULKSVC_SYNCCMD,
				hdr.num_blocks * CACHELINE_SIZE);
	if (ret != 0) {
		pr_err("failed to copy bulksvc cmd from user, rc %d, \n", ret);
		kfree(cmd);
		return ret;
	}

	ret =  do_bulksvc_synccmd(fd, cmd);

	kfree(cmd);
	return ret;
}



DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_ASSIGN_CTXT,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_ASSIGN_CTXT_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_assign_ctxt_cmd),
			   UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_CTXT_INFO,
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_CTXT_INFO_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_ctxt_info_rsp),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_USER_INFO,
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_USER_INFO_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_user_info_rsp),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_TID_UPDATE,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_TID_UPDATE_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_tid_update_cmd),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_TID_UPDATE_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_tid_update_rsp),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_TID_FREE,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_TID_FREE_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_tid_free_cmd),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_TID_FREE_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_tid_free_rsp),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_CREDIT_UPD,
	/* no arguments */
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_RECV_CTRL,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_RECV_CTRL_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_recv_ctrl_cmd),
			   UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_POLL_TYPE,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_POLL_TYPE_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_poll_type_cmd),
			   UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_ACK_EVENT,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_ACK_EVENT_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_ack_event_cmd),
			   UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_SET_PKEY,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_SET_PKEY_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_set_pkey_cmd),
			   UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_CTXT_RESET,
	/* no arguments */
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_TID_INVAL_READ,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_TID_INVAL_READ_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_tid_inval_read_cmd),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_TID_INVAL_READ_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_tid_inval_read_rsp),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_GET_VERS,
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_GET_VERS_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_get_vers_rsp),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_PIN_STATS,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_PIN_STATS_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_pin_stats_cmd),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_PIN_STATS_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_pin_stats_rsp),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_BULKSVC_GET_CMPLQ,
	/* no cmd */
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_BULKSVC_GET_CMPLQ_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_bulksvc_queue_info),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_BULKSVC_GET_CMDQ,
	/* no cmd */
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_BULKSVC_GET_CMDQ_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_bulksvc_queue_info),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_BULKSVC_CLIENT_INIT,
	/* no cmd */
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_BULKSVC_CLIENT_INIT_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_bulksvc_client_init),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_BULKSVC_DOORBELL,
	/* no cmd */
	/* no rsp */
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_BULKSVC_SYNCCMD,
	/* no rsp */
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_BULKSVC_SYNCCMD,
			    UVERBS_ATTR_MIN_SIZE(sizeof(struct hfi1_bulksvc_cmd_hdr)),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_GLOBAL_METHODS(HFI1_OBJECT_DV0,
	&UVERBS_METHOD(HFI1_METHOD_ASSIGN_CTXT),
	&UVERBS_METHOD(HFI1_METHOD_CTXT_INFO),
	&UVERBS_METHOD(HFI1_METHOD_USER_INFO),
	&UVERBS_METHOD(HFI1_METHOD_TID_UPDATE),
	&UVERBS_METHOD(HFI1_METHOD_TID_FREE),
	&UVERBS_METHOD(HFI1_METHOD_CREDIT_UPD),
	&UVERBS_METHOD(HFI1_METHOD_RECV_CTRL),
	&UVERBS_METHOD(HFI1_METHOD_POLL_TYPE));

DECLARE_UVERBS_GLOBAL_METHODS(HFI1_OBJECT_DV1,
	&UVERBS_METHOD(HFI1_METHOD_ACK_EVENT),
	&UVERBS_METHOD(HFI1_METHOD_SET_PKEY),
	&UVERBS_METHOD(HFI1_METHOD_CTXT_RESET),
	&UVERBS_METHOD(HFI1_METHOD_TID_INVAL_READ),
	&UVERBS_METHOD(HFI1_METHOD_GET_VERS),
	&UVERBS_METHOD(HFI1_METHOD_PIN_STATS));

DECLARE_UVERBS_GLOBAL_METHODS(HFI1_OBJECT_DV2,
	&UVERBS_METHOD(HFI1_METHOD_BULKSVC_GET_CMPLQ),
	&UVERBS_METHOD(HFI1_METHOD_BULKSVC_GET_CMDQ),
	&UVERBS_METHOD(HFI1_METHOD_BULKSVC_CLIENT_INIT),
	&UVERBS_METHOD(HFI1_METHOD_BULKSVC_DOORBELL),
	&UVERBS_METHOD(HFI1_METHOD_BULKSVC_SYNCCMD));

const struct uapi_definition hfi1_ib_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HFI1_OBJECT_DV0),
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HFI1_OBJECT_DV1),
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HFI1_OBJECT_DV2),
	{}
};

int hfi1_rdma_mmap(struct ib_ucontext *ucontext, struct vm_area_struct *vma)
{
	struct rvt_ucontext *rcontext = container_of(ucontext, struct rvt_ucontext, ibucontext);
	struct hfi1_filedata *fd = rcontext->priv;
	unsigned long token;
	u8 type;

	if (!fd)
		return -EINVAL;

	token = vma->vm_pgoff << PAGE_SHIFT;
	type = rdma_mmap_get_type(token);

	if (type >= BULKSVC_QUEUE_TYPES_FIRST && type <= BULKSVC_QUEUE_TYPES_LAST) {
		if (!fd->bulksvc_user_info) {
			return -EINVAL;
		}
		return do_bulksvc_mmap(fd->bulksvc_user_info, type, vma);
	} else if (type == BULKSVC_FAST_DOORBELL) {
		return do_bulksvc_doorbell_mmap(fd, vma);
	}

	return hfi1_do_mmap(fd, type, vma);
}

ssize_t hfi1_uverbs_write_iter(struct ib_ucontext *ucontext,
			       struct iov_iter *from)
{
	struct rvt_ucontext *rcontext = container_of(ucontext, struct rvt_ucontext, ibucontext);
	struct hfi1_filedata *fd = rcontext->priv;

	return hfi1_do_write_iter(fd, from);
}
