// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2025 Cornelis Networks.
 */
#include "dms.h"
#include "asm-generic/bug.h"
#include "asm/io.h"
#include "asm/page_types.h"
#include "chip.h"
#include "hfi.h"
#include "linux/dma-mapping.h"
#include "linux/gfp_types.h"
#include "linux/mm.h"
#include "sdma.h"
#include "device.h"
#include "bulksvc.h"
#include "sdma_defs.h"
#include "sdma_txreq.h"
#include "chip_registers_jkr.h"
#include <linux/kernel.h>
#include <linux/minmax.h>
#include <linux/string.h>

#include "trace_dms.h"

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define HFI1_DMS_COUNTERS_ENABLE 0
#define HFI1_DMS_TRACE_ENABLE 0
#define HFI1_DMS_BUG_ENABLE 1
#define HFI1_DMS_WORK_ITEM_MAX_RETRY_TIME_NS (5000000000) // 5s

#if HFI1_DMS_COUNTERS_ENABLE
#define dms_rdtsc() rdtsc()
#else
#define dms_rdtsc() (0ull)
#endif

#if HFI1_DMS_TRACE_ENABLE
#define dms_trace(trace_name, ...) \
	trace_##trace_name( __VA_ARGS__)
#else
#define dms_trace(trace_name, ...) \
	do { } while (0)
#endif

#if HFI1_DMS_BUG_ENABLE
#define DMS_BUG_ON(...) BUG_ON(__VA_ARGS__)
#define DMS_WARN_ON(...) WARN_ON(__VA_ARGS__)
#else
#define DMS_BUG_ON(...) 
#define DMS_WARN_ON(...) (false)
#endif

#define HFI1_DMS_PORT (1) // For now lets just use port 1 because on JKR it's the default
#define HFI1_DMS_PKEY (0x8001) // we probably need to do something more dynamic here
#define HFI1_DMS_CSPECAGE (0) // unsure if this should be specifiable
#define HFI1_DMS_BTH_OPCODE (192) // USER_0
#define HFI1_DMS_MAX_PAYLOAD_SIZE (8192)
// max initial trackers, no reason we can't realloc
#define HFI1_DMS_MAX_RX_TRACKERS (1024) // Just some value for now
#define HFI1_DMS_MAX_TX_TRACKERS_FAST ((u64) U16_MAX)

#define HFI1_DMS_TID_SET_PAGES_MAX (HFI1_DMS_TID_SET_SIZE * 2)
#define HFI1_DMS_DESC_CHUNK_SIZE (32)
#define HFI1_DMS_PAYLOAD_CHUNK_SIZE (256)

#define HFI1_DMS_LRH16BC_LEN_QW_MASK (0x7ffull)
#define HFI1_DMS_LRH16BC_LEN_QW_SHIFT (48)

enum hfi1_dms_msg_type {
	HFI1_DMS_MSG_TYPE_READ_REQUEST = 0,
	HFI1_DMS_MSG_TYPE_READ_REQUEST_FIXUP = 1,
	HFI1_DMS_MSG_TYPE_DATA = 2,
	HFI1_DMS_MSG_TYPE_DATA_FIXUP = 3,
	HFI1_DMS_MSG_TYPE_READ_REQUEST_ACK = 4,
	HFI1_DMS_MSG_TYPE_READ_REQUEST_EXPECTED = 5,
	HFI1_DMS_MSG_TYPE_READ_REQUEST_SMALL = 6,
	HFI1_DMS_MSG_TYPE_DATA_SMALL = 7,

	HFI1_DMS_MSG_TYPE_LENGTH = 8,
};

struct hfi1_dms_read_request_payload {
	u32 tid_info; // first 32 bits of non-optional KDETH on first data packet returned
	u64 offset; // offset into access buffer to read
	union {
		u64 dms_key; // key provided by user application
		u16 tx_rift_index; // index provided by initiator hfisvc
	};
} __attribute__((packed, aligned(4)));

struct hfi1_dms_read_request_nack {
	u32 tid_info; // we use TID for the lookup anyway
} __attribute__((packed, aligned(4)));

struct hfi1_dms_proto_info_read_request_small {
	u32 bth[3];
	u32 kdeth[2];
	u16 size;
	u16 rx_rift_index;
	u64 dms_key;
	u64 offset;
} __attribute__((packed, aligned(8)));

struct hfi1_dms_proto_info_read_request_fixup {
	u32 bth[3];
	u32 kdeth[2];
	u32 size;
	u64 dms_key;
	u64 offset;
} __attribute__((packed, aligned(8)));

struct hfi1_dms_proto_info_read_request_ack {
	u32 bth[3];
	u32 kdeth[2];
	u16 tx_rift_index;
	u16 unused;
	u64 size;
} __attribute__((packed, aligned(8)));

struct hfi1_dms_proto_info_data_small {
	u32 bth[3];
	u32 kdeth[2];
	u16 unused;
	u16 rx_rift_index;
	u64 data[2];
} __attribute__((packed, aligned(8)));

/**
 * this is used when the message type is DATA_FIXUP
 * and contains the head and tail of sbuf so the rbuf can be
 * QW aligned properly for the rest of the read requests
 */
struct hfi1_dms_proto_info_data_fixup {
	u32 bth[3];
	u32 kdeth[2];
	u16 tx_rift_index;
	u16 rx_rift_index;
	u64 head; // first 8 bytes of sbuf
	u64 tail; // last 8 bytes of sbuf
} __attribute__((packed, aligned(8)));

struct hfi1_dms_proto_info_data {
	u32 bth[3];
	u32 kdeth[2];
	u16 tx_rift_index;
	u16 unused;
} __attribute__((packed, aligned(8)));

/**
 * specifically this is the header we expect to land
 * in the HDRQ
 * NOTE: the `user_kdeth` might not fully land (read: won't)
 * and in reality there will only be 5 DWs there.
 * The RHF will be in those last 2 DWs though
 */
union hfi1_dms_16b_header {
	u64 qws[8];
	struct {
		u64 lrh[2];
		u32 bth[3];
		u32 kdeth[2];
		u32 user_kdeth[7];
	};
};

union hfi1_dms_proto_cmd_read_request_small {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_read_request_small info; // 5 qws
		u64 tail_flit;
	};
};

union hfi1_dms_proto_pkt_read_request_small {
	u64 qws[8];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_read_request_small info; // 5 qws
		u64 tail_flit;
	};
};

union hfi1_dms_proto_cmd_data_small {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_data_small info;	// 5 qws
		u64 tail_flit;
	};
};

union hfi1_dms_proto_pkt_data_small {
	u64 qws[8];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_data_small info; // 5 qws
		u64 tail_flit;
	};
};

union hfi1_dms_proto_cmd_read_request_fixup {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_read_request_fixup info; // 5 qws
		u64 tail_flit;
	};
};

union hfi1_dms_proto_pkt_read_request_fixup {
	u64 qws[8];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_read_request_fixup info; // 5 qws
		u64 tail_flit;
	};
};

union hfi1_dms_proto_cmd_data_fixup {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_data_fixup info;	// 5 qws
		u64 tail_flit;
	};
};

union hfi1_dms_proto_pkt_data_fixup {
	u64 qws[8];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_data_fixup info; // 5 qws
		u64 tail_flit;
	};
};

union hfi1_dms_proto_cmd_data {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_data info;	// 3 qws
		u64 tail_flit;
		u64 padding[2];
	};
};

union hfi1_dms_proto_pkt_data {
	u64 qws[6];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_data info; // 3 qws
		u64 tail_flit;
	};
};



union hfi1_dms_proto_cmd_read_request_ack {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_read_request_ack info; // 4 qws
		u64 tail_flit;
		u64 padding[1];
	};
};

union hfi1_dms_proto_pkt_read_request_ack {
	u64 qws[7];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_read_request_ack info; // 4 qws
		u64 tail_flit;
	};
};

// redundant now but keeping it here just in case
static void hfi1_sdma_disable_gen_check(struct hfi1_dms *dms, struct sdma_engine *sde)
{
	u64 reg;

	pr_debug("%s:%d:%s() ENTER: dms=%p, sde=%p\n", __FILENAME__, __LINE__, __func__, dms, sde);
	sde->check_generation = SDMA_CHECK_GEN_DISABLE; // disabled
	reg = read_sdma_csr(dms->dd, sde->this_idx, sde->dd->params->send_dma_len_gen_reg);
	reg &= ~(((u64) (BIT(3) - 1)) << SEND_DMA_LEN_GEN_GENERATION_SHIFT);
	write_sdma_csr(dms->dd, sde->this_idx, sde->dd->params->send_dma_len_gen_reg, reg);
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

static inline u32 hfi1_dms_lrh16B_slid_get(u32 *lrh)
{
	u32 ret;

	pr_debug("%s:%d:%s() ENTER: lrh=%p\n", __FILENAME__, __LINE__, __func__, lrh);
	ret = (u32)((lrh[0] & OPA_16B_LID_MASK) |
			 (((lrh[2] & OPA_16B_SLID_MASK) >>
			 OPA_16B_SLID_HIGH_SHIFT) << OPA_16B_SLID_SHIFT));
	pr_debug("%s:%d:%s() EXIT: ret=%u\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

static inline u32 hfi1_dms_lrh16B_pkt_len_get(u64 *lrh)
{
	u32 ret;

	pr_debug("%s:%d:%s() ENTER: lrh=%p\n", __FILENAME__, __LINE__, __func__, lrh);
	ret = (u32)((lrh[0] & OPA_16B_LEN_MASK) >> OPA_16B_LEN_SHIFT);
	pr_debug("%s:%d:%s() EXIT: ret=%u\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

static inline u32 hfi1_dms_16b_data_payload_qws_get(union hfi1_dms_16b_header *hdr)
{
	u32 pktlen_qws;
	u32 ret;

	pr_debug("%s:%d:%s() ENTER: hdr=%p\n", __FILENAME__, __LINE__, __func__, hdr);
	// For DMS data messages the amount of payload is
	// pktlen_qws - HEADER_SIZE_QWs (8) - 1 (tail flit)
	pktlen_qws = hfi1_dms_lrh16B_pkt_len_get(hdr->lrh);
	ret = pktlen_qws - 8 - 1; // 8 QWs for header, 1 QW for tail flit
	pr_debug("%s:%d:%s() EXIT: ret=%u\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

static inline u32 hfi1_dms_tid_info_make(u16 tid, u16 offset_dw)
{
	u32 const kver = 0x1u << 30; // Kernel version bit
	u32 const tid_ctrl = 0x3u << 26; // Upper and Lower
	u32 const TID_MASK = 0x3ffu;
	u32 const TID_SHIFT = 16;
	u32 const OFFSET_DW_MASK = 0xffffu;
	u32 ret;

	pr_debug("%s:%d:%s() ENTER: tid=%u, offset_dw=%u\n", __FILENAME__, __LINE__, __func__, tid, offset_dw);
	ret = kver | tid_ctrl | (((u32) tid & TID_MASK) << TID_SHIFT) | (offset_dw & OFFSET_DW_MASK);
	pr_debug("%s:%d:%s() EXIT: ret=0x%x\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

static inline u32 hfi1_dms_tid_info_update_tid(u32 tid_info, u16 tid)
{
	u32 const TID_MASK = 0x3ffu;
	u32 const TID_SHIFT = 16;

	pr_debug("%s:%d:%s() ENTER: tid_info=0x%x, tid=%u\n", __FILENAME__, __LINE__, __func__, tid_info, tid);
	// Clear the old TID
	tid_info &= ~(TID_MASK << TID_SHIFT);
	// Set the new TID
	tid_info |= ((u32) tid & TID_MASK) << TID_SHIFT;

	pr_debug("%s:%d:%s() EXIT: ret=0x%x\n", __FILENAME__, __LINE__, __func__, tid_info);
	return tid_info;
}

void hfi1_dms_impl_pbc_dlid_set(u64 *pbc, u32 dlid);
void hfi1_dms_impl_lrh16bc_dlid_set(u64 *lrh16bc, u32 dlid);
void hfi1_dms_impl_lrh16bc_len_qws_set(u64 *lrh16bc, u32 len_qws);


// General Utilities
// NOTE: size has to be <= sizeof(u64) for now. Maybe later this can be a full utility
void hfi1_dms_impl_slow_write_to_user(struct hfi1_mem_region *mr, u64 offset, const void *data, u64 size);
// NOTE: size has to be <= sizeof(u64) for now. Maybe later this can be a full utility
u64 hfi1_dms_impl_slow_read_from_user(struct hfi1_mem_region *mr, u64 offset, u64 size);

// Context and CSR utility functions
void hfi1_dms_impl_rcv_context_disable9B(struct hfi1_dms *dms, u8 pidx, struct hfi1_ctxtdata *rcd);

// Data structure functions
int hfi1_dms_impl_work_item_block_alloc(struct hfi1_dms *dms);
void hfi1_dms_impl_work_item_block_free(struct hfi1_dms *dms);
struct hfi1_dms_work_item *hfi1_dms_impl_work_item_new(struct hfi1_dms *dms);
void hfi1_dms_impl_work_item_free(struct hfi1_dms *dms, struct hfi1_dms_work_item *item);
int hfi1_dms_impl_rx_tracker_block_alloc(struct hfi1_dms *dms);
void hfi1_dms_impl_rx_tracker_block_free(struct hfi1_dms *dms);
int hfi1_dms_impl_tx_tracker_block_alloc(struct hfi1_dms *dms);
void hfi1_dms_impl_tx_tracker_block_free(struct hfi1_dms *dms);
int hfi1_dms_impl_ahg_header_block_alloc(struct hfi1_dms *dms);
void hfi1_dms_impl_ahg_header_block_free(struct hfi1_dms *dms);

int hfi1_dms_access_block_new(struct hfi1_dms *dms);
struct hfi1_dms_access * hfi1_dms_access_freelist_pop(struct hfi1_dms *dms);

struct hfi1_dms_dlist_element * hfi1_dms_impl_tracker_new(struct hfi1_dms_tracker_mgr *trackers, size_t elemsz);
struct hfi1_dms_rx_tracker *hfi1_dms_impl_rx_tracker_new(struct hfi1_dms *dms,
							   u64 size,
							   u64 starting_sbuf_offset, u64 dms_key,
							   u32 src_lid, struct hfi1_mem_region *rbuf, u64 rbuf_offset, struct hfi1_dms_tracker_completion const *completion);
void hfi1_dms_impl_rx_tracker_free(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker * tracker);

int hfi1_dms_impl_tx_tracker_initialize(struct hfi1_dms_tx_tracker * tx_tracker,
							   struct hfi1_dms_access *access, u64 size, u16 tx_rift_index);

void hfi1_dms_impl_tx_tracker_free(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker * tracker);

struct hfi1_dms_ahg_header *hfi1_dms_impl_ahg_header_get(struct hfi1_dms *dms);

struct hfi1_dms_dlist_element * hfi1_dms_impl_dlist_pop(struct hfi1_dms_dlist * dlist);
void hfi1_dms_impl_dlist_push(struct hfi1_dms_dlist * dlist, struct hfi1_dms_dlist_element * element);
void hfi1_dms_impl_dlist_append(struct hfi1_dms_dlist * dlist, struct hfi1_dms_dlist_element * element);
void hfi1_dms_impl_dlist_remove(struct hfi1_dms_dlist * dlist, struct hfi1_dms_dlist_element * element);

struct hfi1_dms_rx_tracker * hfi1_dms_impl_rx_tracker_next_active(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker * tracker);

s32 hfi1_dms_impl_tid_set_peek(struct hfi1_dms *dms);
s32 hfi1_dms_impl_tid_set_get(struct hfi1_dms *dms);
void hfi1_dms_impl_tid_set_put(struct hfi1_dms *dms, s32 tid_set);

void hfi1_dms_impl_lrh16bc_dlid_set(u64 *lrh16bc, u32 dlid);

// protocol message creation functions
void hfi1_dms_impl_fill_proto_templates(struct hfi1_dms *dms);
int hfi1_dms_impl_16bc_state_set(struct hfi1_dms *dms);

u32 hfi1_dms_impl_read_request_size_qw_get(union hfi1_dms_16b_header *hdr);

// protocol functions
int hfi1_dms_impl_make_fixup_read_request(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *tracker);
int hfi1_dms_impl_make_read_request(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *tracker, s32 tid_set);
int hfi1_dms_impl_make_read_requests(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *tracker);

// protocol packet handling functions
static int hfi1_dms_impl_queue_work_item(struct hfi1_dms *dms, void * data, size_t len, hfi1_dms_work_fn work_fn);
void hfi1_dms_impl_handle_packet(struct hfi1_packet *packet);
void hfi1_dms_impl_noop_packet(struct hfi1_packet *packet);

int hfi1_dms_impl_handle_read_request_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
int hfi1_dms_impl_handle_read_request_fixup_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
int hfi1_dms_impl_handle_read_request_ack(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
int hfi1_dms_impl_handle_read_request_expected_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
int hfi1_dms_impl_handle_read_request_small_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);

void hfi1_dms_handle_data(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
void hfi1_dms_handle_data_fixup(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr, u8 *data);
void hfi1_dms_impl_handle_data_small_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);

int hfi1_dms_impl_sdma_send(struct hfi1_dms *dms, struct hfi1_dms_mr * mr, u64 page_offset, u32 nbytes, u32 dlid, u8 rx_id, u32 tid_info, u16 tx_rift_index);

// PIO functions - note: these should only be used in bulksvc/dms or similar.
// the assumption here is only one thread is controlling the PIO buffers at any given time

// since DMS exclusively uses 16B packets all sizes are QW anyway
// also this is function assumes we're either doing 1 or 2 PIO blocks
int hfi1_dms_impl_pio_send(struct hfi1_dms *dms, u64 pbc, void *data, u64 size_qw);

int hfi1_dms_impl_pio_send_or_enqueue_work(struct hfi1_dms *dms, union hfi1_dms_proto_cmd * cmd);

u64 hfi1_dms_impl_pbc_length_dws_get(u64 pbc);

void _rift_init(struct hfi1_dms_rift * rift);


const rhf_rcv_function_ptr hfi1_dms_rhf_rcv_functions[] = {
	[RHF_RCV_TYPE_EAGER] = hfi1_dms_impl_handle_packet,
	[RHF_RCV_TYPE_EXPECTED] = hfi1_dms_impl_handle_packet,
	[RHF_RCV_TYPE_ERROR] = hfi1_dms_impl_handle_packet,
	[RHF_RCV_TYPE_BYPASS] = hfi1_dms_impl_handle_packet,

	[RHF_RCV_TYPE_IB] = hfi1_dms_impl_noop_packet,
	[RHF_RCV_TYPE_INVALID5] = hfi1_dms_impl_noop_packet,
	[RHF_RCV_TYPE_INVALID6] = hfi1_dms_impl_noop_packet,
	[RHF_RCV_TYPE_INVALID7] = hfi1_dms_impl_noop_packet,
};

int hfi1_dms_init(struct hfi1_dms *dms, struct hfi1_devdata *dd, struct hfi1_ctxtdata **rcds, int num_rcds, struct sdma_engine **sdma_engines, int num_engines)
{
	struct hfi1_dms_access *access = NULL;
	int ret = 0;
	u64 rcv_tid_ctrl;
	u64 rcv_tid_pair_cnt;
	s32 max_tid_set_idx;
	int i;

	pr_debug("%s:%d:%s() ENTER: dms=%p, dd=%p, rcds=%p, num_rcds=%d, sdma_engines=%p, num_engines=%d\n",
		   __FILENAME__, __LINE__, __func__, dms, dd, rcds, num_rcds, sdma_engines, num_engines);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(dd == NULL);
	DMS_BUG_ON(rcds == NULL);
	DMS_BUG_ON(num_rcds <= 0);
	DMS_BUG_ON(sdma_engines == NULL);
	DMS_BUG_ON(num_engines <= 0);

	*dms = (struct hfi1_dms){0}; // Initialize the dms structure to zero
	dms->dd = dd;
	dms->rctxt = rcds[0]; // Use the first context as the main one for now - later split into protocol and data ctxts
	dms->sctxt = dms->rctxt->sc;
	dms->sdma_engines = sdma_engines;
	dms->num_engines = num_engines;
	max_tid_set_idx = (dms->rctxt->expected_count / 2) / HFI1_DMS_TID_SET_SIZE;
	// s32 max_tid_set_idx = 400 / HFI1_DMS_TID_SET_SIZE; // For now we use a fixed value, later we can make it dynamic based on expected_count

	rcv_tid_ctrl = read_rctxt_csr(dd, dms->rctxt->ctxt, dd->params->rcv_tid_ctrl_reg);
	rcv_tid_pair_cnt = read_iprc_csr(dd, dms->rctxt->ppd->hw_pidx, dms->rctxt->ctxt, JKR_RCV_IPORT_CTRL + 0x04000);
	dd_dev_info(dd, "DMS: rctxt %d sctx %d rcv_tid_ctrl 0x%016llx rcv_tid_pair_cnt 0x%016llx\n", dms->rctxt->ctxt, dms->sctxt->hw_context, (unsigned long long)rcv_tid_ctrl, (u64) rcv_tid_pair_cnt);
	// write_rctxt_csr(dd, ctxt, dd->params->rcv_tid_ctrl_reg, reg);

	for (i = 0; i < num_engines; ++i) {
		hfi1_sdma_disable_gen_check(dms, dms->sdma_engines[i]);
	}

	hfi1_dms_impl_rcv_context_disable9B(dms, HFI1_DMS_PORT, dms->rctxt);

	dms->rctxt->rhf_rcv_function_map = hfi1_dms_rhf_rcv_functions;
	
	for (i = 0; i < max_tid_set_idx; ++i) {
		dms->free_tid_sets_stack[i] = i;
	}
	dms->free_tid_sets_stack_top = max_tid_set_idx;

	dms->protocol_cmd_templates = (union hfi1_dms_proto_cmd *) kcalloc(HFI1_DMS_MSG_TYPE_LENGTH, sizeof(union hfi1_dms_proto_cmd), GFP_KERNEL);
	if (!dms->protocol_cmd_templates) {
		ret = -ENOMEM;
		goto bail;
	}
	hfi1_dms_impl_fill_proto_templates(dms);

	// initialize a set of rx trackers
	if (hfi1_dms_impl_rx_tracker_block_alloc(dms)) {
		ret = -ENOMEM;
		goto bail;
	}

	// initialize a set of tx trackers
	if (hfi1_dms_impl_tx_tracker_block_alloc(dms)) {
		ret = -ENOMEM;
		goto bail;
	}

	dms->sde_rsrcs = kcalloc(num_engines, sizeof(struct hfi1_dms_sde_rsrc), GFP_KERNEL);
	if (!dms->sde_rsrcs) {
		ret = -ENOMEM;
		goto bail;
	}

	if (hfi1_dms_impl_16bc_state_set(dms)) {
		ret = -EINVAL;
		goto bail;
	}

	if (hfi1_dms_impl_ahg_header_block_alloc(dms)) {
		ret = -ENOMEM;
		goto bail;
	}

	if (hfi1_dms_impl_work_item_block_alloc(dms)) {
		ret = -ENOMEM;
		goto bail;
	}

	dms->zero_page.kvaddr = dma_alloc_coherent(&dd->pcidev->dev, PAGE_SIZE, &dms->zero_page.phys_addr, GFP_DMA);
	if (!dms->zero_page.kvaddr) {
		ret = -ENOMEM;
		goto bail;
	}
	dms->zero_page.len = PAGE_SIZE;

	dms->desc_stack = kcalloc(HFI1_DMS_DESC_CHUNK_SIZE * 6, sizeof(struct sdma_desc), GFP_KERNEL);
	if (!dms->desc_stack) {
		ret = -ENOMEM;
		goto bail;
	}
	dms->num_descs = HFI1_DMS_DESC_CHUNK_SIZE * 6;

	dms->ahg_header_stack = kcalloc(HFI1_DMS_TID_SET_PAGES_MAX, sizeof(struct hfi1_dms_ahg_header*), GFP_KERNEL);
	if (!dms->ahg_header_stack) {
		ret = -ENOMEM;
		goto bail;
	}
	dms->num_ahgs = HFI1_DMS_TID_SET_PAGES_MAX;
	
	dms->client_rbtree = RB_ROOT;

	if (hfi1_dms_access_block_new(dms)) {
		ret = -ENOMEM;
		goto bail;
	}

	_rift_init(&dms->rx_rift);
	_rift_init(&dms->tx_rift);

	dd_dev_warn(dd, "DMS initialized with %d SDMA engines.\n", num_engines);

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0;

bail:
	while ((access = hfi1_dms_access_freelist_pop(dms))) {
		kfree(access);
	}

	hfi1_dms_impl_ahg_header_block_free(dms);

	if (dms->ahg_header_stack) {
		kfree(dms->ahg_header_stack);
		dms->ahg_header_stack = NULL;
		dms->num_ahgs = 0;
	}

	if (dms->desc_stack) {
		kfree(dms->desc_stack);
		dms->desc_stack = NULL;
		dms->num_descs = 0;
	}

	if (dms->zero_page.kvaddr) {
		dma_free_coherent(&dd->pcidev->dev, PAGE_SIZE, dms->zero_page.kvaddr, dms->zero_page.phys_addr);
		dms->zero_page.kvaddr = NULL;
	}


	if (dms->sde_rsrcs) {
		kfree(dms->sde_rsrcs);
		dms->sde_rsrcs = NULL;
	}

	hfi1_dms_impl_rx_tracker_block_free(dms);
	hfi1_dms_impl_tx_tracker_block_free(dms);

	if (dms->protocol_cmd_templates) {
		kfree(dms->protocol_cmd_templates);
		dms->protocol_cmd_templates = NULL;
	}

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

void hfi1_dms_uninit(struct hfi1_dms *dms)
{
	int i;

	pr_debug("%s:%d:%s() ENTER: dms=%p\n", __FILENAME__, __LINE__, __func__, dms);
	DMS_BUG_ON(dms == NULL);

	for (i = 0; i < dms->num_engines; ++i) {
		struct hfi1_dms_sde_rsrc *rsrc = &dms->sde_rsrcs[i];
		while (rsrc->active_ahg_headers.head != NULL) {
			hfi1_dms_impl_dlist_pop(&rsrc->active_ahg_headers);
			// don't bother pushing on free list we're about to free all the blocks
		}
	}

	hfi1_dms_impl_work_item_block_free(dms);
	hfi1_dms_impl_ahg_header_block_free(dms);

	if (dms->zero_page.kvaddr) {
		dma_free_coherent(&dms->dd->pcidev->dev, PAGE_SIZE, dms->zero_page.kvaddr, dms->zero_page.phys_addr);
		dms->zero_page.kvaddr = NULL;
		dms->zero_page.phys_addr = 0;
		dms->zero_page.len = 0;
	}

	kfree(dms->ahg_header_stack);
	dms->ahg_header_stack = NULL;
	dms->num_ahgs = 0;
	kfree(dms->desc_stack);
	dms->desc_stack = NULL;
	kfree(dms->sde_rsrcs);
	dms->sde_rsrcs = NULL;
	hfi1_dms_impl_rx_tracker_block_free(dms);
	hfi1_dms_impl_tx_tracker_block_free(dms);

	struct hfi1_dms_access *access = NULL;
	while ((access = hfi1_dms_access_freelist_pop(dms))) {
		kfree(access);
	}

	kfree(dms->protocol_cmd_templates);
	dms->protocol_cmd_templates = NULL;
	dms->sdma_engines = NULL;
	dms->num_engines = 0;
	if (dms->dd) {
		dd_dev_warn(dms->dd, "DMS uninitialized successfully.\n");
	}
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

struct hfi1_dms_client_state * hfi1_dms_client_rbtree_search(struct hfi1_dms *dms, u32 client_key)
{
	struct rb_root *root = &dms->client_rbtree;
	struct rb_node *node = root->rb_node;
	struct hfi1_dms_client_state *client;

	pr_debug("%s:%d:%s() ENTER: dms=%p, client_key=%u\n", __FILENAME__, __LINE__, __func__, dms, client_key);
	while (node) {
		client = container_of(node, struct hfi1_dms_client_state, node);

		if (client_key < client->key)
			node = node->rb_left;
		else if (client_key > client->key)
			node = node->rb_right;
		else {
			pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, client);
			return client;
		}
	}
	pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, NULL);
	return NULL;
}

int hfi1_dms_client_rbtree_insert(struct hfi1_dms *dms, u32 client_key, struct hfi1_dms_client_state * client)
{
	struct rb_root *root = &dms->client_rbtree;
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	pr_debug("%s:%d:%s() ENTER: dms=%p, client_key=%u, client=%p\n", __FILENAME__, __LINE__, __func__, dms, client_key, client);
	/* Figure out where to put new node */
	while (*new) {
		struct hfi1_dms_client_state *this = container_of(*new, struct hfi1_dms_client_state, node);

		parent = *new;
		if (client_key < this->key)
			new = &((*new)->rb_left);
		else if (client_key > this->key)
			new = &((*new)->rb_right);
		else {
			pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -ENOSPC);
			return -ENOSPC;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&client->node, parent, new);
	rb_insert_color(&client->node, &dms->client_rbtree);

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0;
 }

void hfi1_dms_client_rbtree_remove(struct hfi1_dms *dms, struct hfi1_dms_client_state *client)
{
	/* this and insert should have locking, or some garauntee on serialization */
	rb_erase(&client->node, &dms->client_rbtree);
}

int hfi1_dms_create_client_key(struct hfi1_dms *dms, u32 client_key)
{
	struct hfi1_dms_client_state *client;
	int rc;

	client = hfi1_dms_client_rbtree_search(dms, client_key);
	if (client) {
		dd_dev_err(dms->dd, "Client key %u already exists.\n", client_key);
		return -EEXIST;
	}

	client = (struct hfi1_dms_client_state *)kzalloc(sizeof(*client),
							GFP_KERNEL);
	if (!client) {
		dd_dev_err(dms->dd, "Memory allocation error.\n");
		return -ENOMEM;
	}

	client->key = client_key;
	client->access.rbt = RB_ROOT;
	rc = hfi1_dms_client_rbtree_insert(dms, client_key, client);
	if (rc < 0) {
		dd_dev_err(dms->dd, "Client rbtree insertion error.\n");
		kfree(client);
		return -EINVAL;
	}
	return 0;
}

struct hfi1_dms_access * hfi1_dms_access_rbtree_search(struct hfi1_dms_client_state *client, u64 access_key)
{
	struct rb_root *root = &client->access.rbt;
	struct rb_node *node = root->rb_node;
	struct hfi1_dms_access *access;

	pr_debug("%s:%d:%s() ENTER: client=%p, access_key=%llu\n", __FILENAME__, __LINE__, __func__, client, access_key);
	while (node) {
		access = container_of(node, struct hfi1_dms_access, node);

		if (access_key < access->access_key)
			node = node->rb_left;
		else if (access_key > access->access_key)
			node = node->rb_right;
		else {
			pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, access);
			return access;
		}
	}
	pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, NULL);
	return NULL;
}

int hfi1_dms_access_rbtree_insert(struct hfi1_dms_client_state *client, u64 access_key, struct hfi1_dms_access *access)
{
	struct rb_root *root = &client->access.rbt;
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	pr_debug("%s:%d:%s() ENTER: client=%p, access_key=%llu, access=%p\n", __FILENAME__, __LINE__, __func__, client, access_key, access);
	/* Figure out where to put new node */
	while (*new) {
		struct hfi1_dms_access *this = container_of(*new, struct hfi1_dms_access, node);

		parent = *new;
		if (access_key < this->access_key)
			new = &((*new)->rb_left);
		else if (access_key > this->access_key)
			new = &((*new)->rb_right);
		else {
			pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -ENOSPC);
			return -ENOSPC;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&access->node, parent, new);
	rb_insert_color(&access->node, &client->access.rbt);

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0;
}

 void hfi1_dms_access_freelist_push(struct hfi1_dms *dms, struct hfi1_dms_access *access)
{
	//pr_debug("%s:%d:%s() ENTER: dms=%p, access=%p\n", __FILENAME__, __LINE__, __func__, dms, access);
	// PRE - not active ...
	hfi1_dms_impl_dlist_push(&dms->access.freelist, &access->element);
	//pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

struct hfi1_dms_access *hfi1_dms_access_freelist_pop(struct hfi1_dms *dms)
{
	struct hfi1_dms_dlist_element * element;
	element = hfi1_dms_impl_dlist_pop(&dms->access.freelist);
	if (!element) {
		pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, NULL);
		return NULL;
	}
	return container_of(element, struct hfi1_dms_access, element);
}

int hfi1_dms_access_block_new(struct hfi1_dms *dms)
{
	int i;
	// allocate a bunch more
	for (i = 0; i < 1024; ++i) {
		struct hfi1_dms_access * access = (struct hfi1_dms_access *) kzalloc(sizeof(*access), GFP_KERNEL);
		if (!access) {
			dd_dev_err(dms->dd, "Memory allocation error.\n");
			return -ENOMEM;
		}
		hfi1_dms_access_freelist_push(dms, access);
	}
	return 0;
}

struct hfi1_dms_access * hfi1_dms_access_new(struct hfi1_dms *dms)
{
	struct hfi1_dms_access *access;

	pr_debug("%s:%d:%s() ENTER: dms=%p\n", __FILENAME__, __LINE__, __func__, dms);
	access = hfi1_dms_access_freelist_pop(dms);
	if (!access) {
		if (hfi1_dms_access_block_new(dms)) {
			dd_dev_err(dms->dd, "Failed to allocate new access block.\n");
			pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, NULL);
			return NULL;
		}

		access = hfi1_dms_access_freelist_pop(dms);
		if (!access) {
			dd_dev_err(dms->dd, "Free list error.\n");
			pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, NULL);
			return NULL;
		}
	}
	pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, access);
	return access;
}

int hfi1_dms_access_assign(struct hfi1_dms *dms, u64 dms_key, struct hfi1_dms_access *access)
{
	u64 client_key = dms_key >> 32;
	u64 access_key = dms_key & ((1ull << 32) - 1);
	struct hfi1_dms_client_state * client;
	int rc;

	pr_debug("%s:%d:%s() ENTER: dms=%p, dms_key=0x%llx, access=%p\n", __FILENAME__, __LINE__, __func__, dms, dms_key, access);
	client = hfi1_dms_client_rbtree_search(dms, client_key);
	// FIXME ... this should really be a BUG_ON because if client isn't defined then things are really messed up
	if (!client) {
		dd_dev_err(dms->dd, "Client key %llu not found.\n", client_key);
		return -EINVAL;
	}

	access->dms_key = dms_key;
	access->access_key = access_key;

	if (access_key < HFI1_DMS_MAX_ACCESS_FAST) {
		if (client->access.arr[access_key]) {
			dd_dev_err(dms->dd, "Client access already active for id %llu.\n", access_key);
			pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -1);
			return -1;
		}
		client->access.arr[access_key] = access;
	} else {
		rc = hfi1_dms_access_rbtree_insert(client, access_key, access);
		if (rc < 0) {
			dd_dev_err(dms->dd, "Client access rbtree insertion error.\n");
			pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -1);
			return -1;
		}
	}

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0;
}

void hfi1_dms_release_client_key(struct hfi1_dms *dms, u32 client_key)
{
	struct hfi1_dms_client_state *client;
	client = hfi1_dms_client_rbtree_search(dms, client_key);
	// FIXME this should be a BUG_ON or something because ifthe key isn't found then we are really messed up
	if (!client)
		return;
	hfi1_dms_client_rbtree_remove(dms, client);

	kfree(client);

	// consider decrementing last_client_key
}

int hfi1_dms_access_remove(struct hfi1_dms *dms, struct hfi1_dms_access * access)
{
	// FIXME - There must be a faster/better way to remove access from the rbtree since we already have pointers to it ....

	u64 dms_key = access->dms_key;
	u64 client_key = dms_key >> 32;
	u64 access_key = dms_key & ((1ull << 32) - 1);
	struct hfi1_dms_client_state * client;

	pr_debug("%s:%d:%s() ENTER: dms=%p, access=%p\n", __FILENAME__, __LINE__, __func__, dms, access);
	client = hfi1_dms_client_rbtree_search(dms, client_key);
	if (!client) {
		dd_dev_err(dms->dd, "Invalid client error. key = 0x%016llx (%llu)\n", client_key, client_key);
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -1);
		return -1;
	}

	if (access_key < HFI1_DMS_MAX_ACCESS_FAST) {
		if (!client->access.arr[access_key]) {
			dd_dev_err(dms->dd, "Access not active error. id = %llu\n", access_key);
			pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -1);
			return -1;
		}
		client->access.arr[access_key] = NULL;
	} else {
		rb_erase(&access->node, &client->access.rbt);
	}
	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0;
}

struct hfi1_dms_access * hfi1_dms_access_lookup(struct hfi1_dms *dms, u64 dms_key, struct hfi1_dms_client_state **client_out)
{
	WARN_ON(client_out == NULL);
	struct hfi1_dms_access * access = NULL;
	u64 client_key = dms_key >> 32;
	u64 access_key = dms_key & ((1ull << 32) - 1);
	struct hfi1_dms_client_state * client;

	pr_debug("%s:%d:%s() ENTER: dms=%p, dms_key=0x%llx\n", __FILENAME__, __LINE__, __func__, dms, dms_key);
	client = hfi1_dms_client_rbtree_search(dms, client_key);
	if (!client) {
		dd_dev_err(dms->dd, "Invalid client error. key = 0x%016llx (%llu)\n", client_key, client_key);
		pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, NULL);
		return NULL;
	}
	*client_out = client;

	if (access_key < HFI1_DMS_MAX_ACCESS_FAST) {
		access = client->access.arr[access_key];
	} else {
		access = hfi1_dms_access_rbtree_search(client, access_key);
	}

	if (!access) {
		dd_dev_dbg(dms->dd, "Access not found error. id = %llu\n", access_key);
		pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, NULL);
		return NULL;
	}
	pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, access);
	return access;
}


void hfi1_dms_tracker_completion_fn_noop(union hfi1_dms_completion_cookie *cookie)
{
	pr_debug("%s:%d:%s() ENTER: cookie=%p\n", __FILENAME__, __LINE__, __func__, cookie);
	(void) cookie;
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

void hfi1_dms_impl_access_initialize(struct hfi1_dms_access *access, enum hfi1_dms_access_type access_type, struct hfi1_dms_mr *mr, u64 offset, u32 size, u64 dms_key, struct hfi1_dms_tracker_completion const *completion)
{
	u64 access_key = dms_key & ((1ull << 32) - 1);

	access->node = (struct rb_node){ 0 };
	access->element = (struct hfi1_dms_dlist_element){ 0 };

	access->dms_key = dms_key;
	access->access_key = (u32)access_key;
	access->type = access_type;

	if (completion) {
		access->completion = *completion;
	} else {
		access->completion.fn = hfi1_dms_tracker_completion_fn_noop;
	}

	access->mr = mr;
	access->offset = offset;
	access->size = size;
	access->active_count = 0;
}

int hfi1_dms_register_access(struct hfi1_dms *dms, struct hfi1_dms_mr *mr, u64 offset, u32 size, u64 dms_key, struct hfi1_dms_tracker_completion const completion, enum hfi1_dms_access_type access_type)
{
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(mr == NULL);

	struct hfi1_dms_access *access;
	int rc;

	if (mr->mode == HFI1_DMS_MR_MODE_VADDR) {
		// offset is interpreted as a user virtual address
		if (offset < mr->user.addr) {
			dd_dev_err(dms->dd, "Access request virtual address starts before the valid address range of memory region.\n");
			return -EINVAL;
		}
		offset = offset - mr->user.addr;
	}

	if ((offset + size) > mr->user.len) {
		dd_dev_err(dms->dd, "Access request would extend beyond valid address range of memory region.\n");
		return -EINVAL;
	}

	access = hfi1_dms_access_new(dms);
	if (!access) {
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -ENOMEM);
		return -ENOMEM;
	} 
	rc = hfi1_dms_access_assign(dms, dms_key, access);
	if (rc < 0) {
		dd_dev_err(dms->dd, "Access not assigned.\n");
		hfi1_dms_access_freelist_push(dms, access);
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -ENOSPC);
		return -ENOSPC;
	}

	hfi1_dms_impl_access_initialize(access, access_type, mr, offset, size, dms_key, &completion);

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0;
}

int hfi1_dms_unregister_access(struct hfi1_dms *dms, u64 dms_key)
{
	struct hfi1_dms_access *access;
	struct hfi1_dms_client_state *client = NULL;

	pr_debug("%s:%d:%s() ENTER: dms=%p, dms_key=0x%016llx\n", __FILENAME__,
		   __LINE__, __func__, dms, dms_key);

	access = hfi1_dms_access_lookup(dms, dms_key, &client);
	if (!access || !client) {
		dd_dev_warn(dms->dd,
			    "Invalid dms_key %llu for unregistering access.\n",
			    dms_key);
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__,
			   __func__, -EINVAL);
		return -EINVAL;
	}

	if (access->active_count > 0) {
		dd_dev_warn(dms->dd,
			    "Attempt to unregister access with dms_key %llu while it is active.\n",
			    dms_key);
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__,
			   __func__, -EBUSY);
		return -EBUSY;
	}

	hfi1_dms_access_remove(dms, access);
	hfi1_dms_access_freelist_push(dms, access);

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__,
		   0);
	return 0;
}

int hfi1_dms_dma_access_once(struct hfi1_dms *dms, u32 client_key, struct hfi1_dms_mr *mr, u32 access_key,
			       u64 offset, u32 len,
			       struct hfi1_dms_tracker_completion const notification)
{
	u64 dms_key = ((u64)client_key << 32) | access_key;
	return hfi1_dms_register_access(dms, mr, offset, len, dms_key,
				      notification, HFI1_DMS_ACCESS_TYPE_EPHEMERAL);
}

int hfi1_dms_dma_access_enable(struct hfi1_dms *dms, u32 client_key, struct hfi1_dms_mr *mr, u32 access_key,
			       u64 offset, u32 len,
			       struct hfi1_dms_tracker_completion const notification)
{
	u64 dms_key = ((u64)client_key << 32) | access_key;
	return hfi1_dms_register_access(dms, mr, offset, len, dms_key,
				      notification, HFI1_DMS_ACCESS_TYPE_PERSISTENT);
}

int hfi1_dms_dma_access_disable(struct hfi1_dms *dms, u32 client_key, u32 access_key)
{
	u64 dms_key = ((u64)client_key << 32) | access_key;

	return hfi1_dms_unregister_access(dms, dms_key);
}

void _rift_init(struct hfi1_dms_rift * rift)
{
	static u16 const sz = (u16) HFI1_DMS_RIFT_SIZE;//(sizeof(rift->arr) / sizeof(rift->arr[0]));

	rift->stack_top = sz;
	for (u16 i = 0; i < sz; ++i) {
		rift->stack[i] = i;
		rift->arr[i] = NULL;
	}
}

int _rift_reserve(struct hfi1_dms_rift *rift, u16 *index)
{
	DMS_BUG_ON(!rift);
	DMS_BUG_ON(!index);

	if (rift->stack_top == 0) {
		return -ENOSPC;
	}
	*index = rift->stack[--rift->stack_top];
	return 0;
}

void _rift_assign(struct hfi1_dms_rift *rift, union hfi1_dms_tracker *tracker, u16 index)
{
	static u16 const sz = HFI1_DMS_RIFT_SIZE;//sizeof(dms->tx_rift) / sizeof(dms->tx_rift[0]);

	DMS_BUG_ON(!rift);
	DMS_BUG_ON(sz <= index);

	rift->arr[index] = tracker;
}

union hfi1_dms_tracker * _rift_lookup(struct hfi1_dms_rift *rift, u16 index)
{
	static u16 const sz = HFI1_DMS_RIFT_SIZE;//sizeof(dms->tx_rift) / sizeof(dms->tx_rift[0]);

	DMS_BUG_ON(!rift);
	DMS_BUG_ON(sz <= index);

	return rift->arr[index];
}

void _rift_release(struct hfi1_dms_rift *rift, u16 index)
{
	static u16 const sz = HFI1_DMS_RIFT_SIZE;//sizeof(dms->tx_rift) / sizeof(dms->tx_rift[0]);

	DMS_BUG_ON(!rift);
	DMS_BUG_ON(sz <= index);

	pr_debug("%s:%d:%s() index=%hu, sz=%hu, rift->stack_top = %hu\n", __FILENAME__, __LINE__, __func__, index, sz, rift->stack_top);
	DMS_BUG_ON(rift->stack_top == sz);

	rift->arr[index] = NULL;
	rift->stack[rift->stack_top++] = index;
}

int hfi1_dms_write_data(struct hfi1_dms *dms, u32 dest_lid, u64 dms_key, u64 remote_offset,
			u32 size, struct hfi1_dms_mr *mr, u64 mr_offset,
			struct hfi1_dms_tracker_completion const completion)
{
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(mr == NULL);
	DMS_BUG_ON(dest_lid == 0);

	return 0;
}

int hfi1_dms_unregister_data(struct hfi1_dms *dms, u64 dms_key)
{
	struct hfi1_dms_access * access;
	struct hfi1_dms_client_state *client = NULL;

	pr_debug("%s:%d:%s() ENTER: dms=%p, dms_key=0x%llx\n", __FILENAME__, __LINE__, __func__, dms, dms_key);
	// WARNING - bad things can happen if the access is currently being acted upon

	access = hfi1_dms_access_lookup(dms, dms_key, &client);
	if (!access || !client) {
		dd_dev_warn(dms->dd, "Invalid dms_key %llu for unregistering data.\n", dms_key);
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -EINVAL);
		return -EINVAL;
	}

	if (access->active_count > 0) {
		// error ... can't remove access while active
		// FIXME - blocksome
	} else {
		hfi1_dms_access_remove(dms, access);
		hfi1_dms_access_freelist_push(dms, access);
	}
	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0;
}

union hfi1_dms_proto_cmd_read_request_small hfi1_dms_proto_cmd_read_request_small_make(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker, u32 dlid, u16 rx_rift_index)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(rx_tracker->total_payload > 16);

	union hfi1_dms_proto_cmd_read_request_small * tmpl;
	union hfi1_dms_proto_cmd_read_request_small cmd;
	int i;

	pr_debug("%s:%d:%s() ENTER: dms=%p, rx_tracker=%p, dlid=%u, rx_rift_index=%hu\n",
		   __FILENAME__, __LINE__, __func__, dms, rx_tracker, dlid, rx_rift_index);
	DMS_BUG_ON(dms == NULL);

	tmpl = (union hfi1_dms_proto_cmd_read_request_small *)
		&dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_REQUEST_SMALL];

	int cmd_len_qws = sizeof(cmd) / sizeof(u64);
	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}

	cmd.info.dms_key = rx_tracker->dms_key;
	cmd.info.offset = rx_tracker->sbuf_start_offset;
	cmd.info.size = (u16) rx_tracker->total_payload;
	cmd.info.rx_rift_index = rx_rift_index;
	cmd.tail_flit = 0;
	// remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);

	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
	return cmd;
}

union hfi1_dms_proto_cmd_read_request_fixup hfi1_dms_proto_cmd_read_request_fixup_make(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker, u32 dlid, u16 rx_rift_index)
{
	union hfi1_dms_proto_cmd_read_request_fixup * tmpl;
	union hfi1_dms_proto_cmd_read_request_fixup cmd;
	int i;

	pr_debug("%s:%d:%s() ENTER: dms=%p, rx_tracker=%p, dlid=%u, rx_rift_index=%hu\n",
		   __FILENAME__, __LINE__, __func__, dms, rx_tracker, dlid, rx_rift_index);
	DMS_BUG_ON(dms == NULL);

	tmpl = (union hfi1_dms_proto_cmd_read_request_fixup *)
		&dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_REQUEST_FIXUP];


	int cmd_len_qws = sizeof(cmd) / sizeof(u64);
	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}

	DMS_BUG_ON((rx_tracker->total_payload & 0xffffffff00000000ull) != 0);	// TODO - handle fixups of read requests larger than 2^32 size

	cmd.info.dms_key = rx_tracker->dms_key;
	cmd.info.offset = rx_tracker->sbuf_start_offset;
	cmd.info.size = (u32) rx_tracker->total_payload;
	cmd.tail_flit = 0;
	// remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);
	cmd.info.bth[2] = (rx_rift_index << 16) | (cmd.info.bth[2] & 0xff);

	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
	return cmd;
}

union hfi1_dms_proto_cmd_data_small hfi1_dms_proto_cmd_data_small_make(struct hfi1_dms *dms, u32 dlid, u16 rx_rift_index, u64 data0, u64 data1)
{
	union hfi1_dms_proto_cmd_data_small * tmpl;
	union hfi1_dms_proto_cmd_data_small cmd;
	static u64 const cmd_len_qws = sizeof(cmd) / sizeof(u64);
	u64 i;

	pr_debug("%s:%d:%s() ENTER: dms=%p, dlid=%u, rx_rift_index=%hu, data0=0x%016llx, data1=0x%016llx\n",
		   __FILENAME__, __LINE__, __func__, dms, dlid, rx_rift_index, data0, data1);
	DMS_BUG_ON(dms == NULL);

	tmpl = (union hfi1_dms_proto_cmd_data_small *)
		&dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_SMALL];

	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}

	cmd.info.rx_rift_index = rx_rift_index;
	cmd.info.data[0] = data0;
	cmd.info.data[1] = data1;
	cmd.tail_flit = 0;
	// remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);

	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
	return cmd;	
}

union hfi1_dms_proto_cmd_data_fixup hfi1_dms_proto_cmd_data_fixup_make(struct hfi1_dms *dms, u32 dlid, u16 rx_rift_index, u64 head, u64 tail)
{
	union hfi1_dms_proto_cmd_data_fixup * tmpl;
	union hfi1_dms_proto_cmd_data_fixup cmd;
	static u64 const cmd_len_qws = sizeof(cmd) / sizeof(u64);
	u64 i;

	pr_debug("%s:%d:%s() ENTER: dms=%p, dlid=%u, rx_rift_index=%hu, head=0x%llx, tail=0x%llx\n",
		   __FILENAME__, __LINE__, __func__, dms, dlid, rx_rift_index, head, tail);
	DMS_BUG_ON(dms == NULL);

	tmpl = (union hfi1_dms_proto_cmd_data_fixup *)
		&dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_FIXUP];

	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}

	cmd.info.rx_rift_index = rx_rift_index;
	cmd.info.head = head;
	cmd.info.tail = tail;
	cmd.tail_flit = 0;
	// remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);

	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
	return cmd;
}

union hfi1_dms_proto_cmd_read_request_ack hfi1_dms_proto_cmd_read_request_ack_make(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker, u32 dlid, u32 tx_rift_index, u64 size)
{
	union hfi1_dms_proto_cmd_read_request_ack * tmpl;
	union hfi1_dms_proto_cmd_read_request_ack cmd;
	int i;

	pr_debug("%s:%d:%s() ENTER: dms=%p, rx_tracker=%p, dlid=%u, tx_rift_index=%u, size=%llu\n",
		   __FILENAME__, __LINE__, __func__, dms, rx_tracker, dlid, tx_rift_index, size);
	DMS_BUG_ON(dms == NULL);

	tmpl = (union hfi1_dms_proto_cmd_read_request_ack *)
		&dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_REQUEST_ACK];

	for (i = 0; i < 5; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}

	cmd.info.tx_rift_index = tx_rift_index;
	cmd.info.size = size;
	cmd.tail_flit = 0;
	// remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi1_dms_impl_pbc_dlid_set(&cmd.pbc, dlid);
	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);

	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
	return cmd;
}


int hfi1_dms_read_data(struct hfi1_dms *dms, u32 src_lid, u64 dms_key, u64 offset, u32 size, struct hfi1_dms_mr *mr, u64 mr_offset, struct hfi1_dms_tracker_completion const completion)
{
	int ret;
	u64 start, end;
	struct hfi1_dms_rx_tracker *rx_tracker;
	u16 rx_rift_index;
	union hfi1_dms_proto_cmd_read_request_small cmd;

	dms_trace(dms_read_data, dms, src_lid, dms_key, offset, size, mr, mr_offset);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(mr == NULL);
	DMS_BUG_ON(src_lid == 0);
	start = dms_rdtsc();
	dms->counters.sending_first_rr = ktime_get();

	u64 starting_rbuf_offset = 0;

	if (mr->mode == HFI1_DMS_MR_MODE_VADDR) {
		// offset is interpreted as a user virtual address
		if (mr_offset < mr->user.addr) {
			dd_dev_err(dms->dd, "Virtual address of receive buffer starts before the valid address range of memory region.\n");
			return -EINVAL;
		}
		mr_offset = mr_offset - mr->user.addr;
	}
	
	if ((mr_offset + size) > mr->user.len) {
		dd_dev_err(dms->dd, "Receive buffer would extend beyond valid address range of memory region.\n");
		return -EINVAL;
	}
	starting_rbuf_offset = mr->region_offset + mr_offset;

	rx_tracker = hfi1_dms_impl_rx_tracker_new(dms, size, offset, dms_key, src_lid, mr->hfi1_mr, starting_rbuf_offset, &completion);
	if (rx_tracker == NULL) {
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -ENOMEM);
		return -ENOMEM;
	}

	dd_dev_dbg(dms->dd, "Adding rx_tracker for dms_key %llu, src_lid %u, offset %llu, size %u mr_addr 0x%llx rbuf.rbaddr 0x%lx mr_offset %llu\n", dms_key, src_lid, offset, size, rx_tracker->rbuf->rb.addr + rx_tracker->rbuf_offset, rx_tracker->rbuf->rb.addr, rx_tracker->rbuf_offset);

	if (rx_tracker->total_payload <= 16) {
		ret = _rift_reserve(&dms->rx_rift, &rx_rift_index);
		DMS_BUG_ON(ret < 0); // FIXME - blocksome - add to a "pending" queue attached to this rift
		//if (ret < 0) {
		//	dd_dev_dbg(dms->dd, "Rx RDMA In-Flight Table is full.\n");
		//	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
		//	return ret;
		//}

		_rift_assign(&dms->rx_rift, (union hfi1_dms_tracker *)rx_tracker, rx_rift_index);

		cmd = hfi1_dms_proto_cmd_read_request_small_make(dms, rx_tracker, rx_tracker->src_lid, rx_rift_index);

		ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
		if (ret < 0) {
			dd_dev_err(dms->dd, "Failed to send or enqueue read request fixup\n");
			return ret;
		}
		rx_tracker->payload_requested += size;
	} else {

		// If a fixup is needed just do it, if a fixup is not needed this doesn't do anything
		if (hfi1_dms_impl_make_fixup_read_request(dms, rx_tracker)) {
			dd_dev_err(dms->dd, "Failed to make or enqueue fixup read request for rx_tracker with dms_key %llu.\n", dms_key);
			hfi1_dms_impl_rx_tracker_free(dms, rx_tracker);
			pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -ENOMEM);
			return -ENOMEM;
		}


		s32 tid_set = hfi1_dms_impl_tid_set_peek(dms);
		if (tid_set >= 0) {
			int rc = hfi1_dms_impl_make_read_request(dms, rx_tracker, tid_set);
			if (rc == 0) {
				hfi1_dms_impl_tid_set_get(dms);
			}
		}
	}

	if (rx_tracker->payload_requested == rx_tracker->total_payload) {
		dd_dev_dbg(dms->dd, "Tracker for key %llu has requested all data. Waiting to receive.\n", dms_key);
	}

	end = dms_rdtsc();
	dms->counters.rget += end - start;

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0;
}

void hfi1_dms_rx_tracker_handle_completion(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker, u32 dlid, u32 tx_rift_index)
{
	union hfi1_dms_proto_cmd_read_request_ack cmd;

	rx_tracker->completion.fn(&rx_tracker->completion.cookie);

	// inject read_request_ack
	cmd = hfi1_dms_proto_cmd_read_request_ack_make(dms, rx_tracker, dlid, tx_rift_index, rx_tracker->total_payload);

	pr_debug("%s:%d:%s() HERE\n", __FILENAME__, __LINE__, __func__);
	hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);

	dd_dev_dbg(dms->dd, "Freeing rx_tracker with dms_key %llu.\n", rx_tracker->dms_key);
	hfi1_dms_impl_rx_tracker_free(dms, rx_tracker);
}

int hfi1_dms_impl_rift_index_get(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	union hfi1_dms_proto_pkt_data * data = (union hfi1_dms_proto_pkt_data *)hdr;
	return data->info.tx_rift_index;
}

void hfi1_dms_handle_data(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	u64 start;
	u16 tid;
	u16 tid_set;
	u32 pktlen_qws;
	u32 payload_qws;
	u32 payload_bytes;
	struct hfi1_dms_read_request_state *read_request;
	u64 rr_start;
	struct hfi1_dms_rx_tracker *rx_tracker;
	struct hfi1_dms_rx_tracker *next;
	u32 dlid;
	union hfi1_dms_proto_pkt_data * data;
	u64 rr_end;
	u64 end;

	dms_trace(dms_handle_data, dms, hdr);

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(hdr == NULL);

	start = dms_rdtsc();
	if (dms->counters.rcv_first_data == 0) {
		dms->counters.rcv_first_data = ktime_get();
	}

	tid = (hdr->kdeth[0] >> 16) & (BIT(10) - 1);
	tid_set = (tid / HFI1_DMS_TID_SET_SIZE);
	pktlen_qws = hfi1_dms_lrh16B_pkt_len_get(&hdr->lrh[0]);
	payload_qws = hfi1_dms_16b_data_payload_qws_get(hdr);
	payload_bytes = payload_qws << 3;

	read_request = &dms->read_requests[tid_set];
	DMS_BUG_ON(read_request == NULL);
	DMS_BUG_ON(read_request->rx_tracker == NULL);
	DMS_WARN_ON(read_request->remaining_qws < payload_qws);

	rx_tracker = read_request->rx_tracker;
	rx_tracker->tx_rift_index = hfi1_dms_impl_rift_index_get(dms, hdr);
	hfi1_dms_impl_make_read_requests(dms, rx_tracker);

	read_request->remaining_qws -= payload_qws;
	if (read_request->remaining_qws == 0) {
		rr_start = dms_rdtsc();
		rx_tracker->payload_remaining -= (read_request->total_requested_qws << 3);
		
		next = rx_tracker;
		DMS_BUG_ON(rx_tracker->payload_requested > rx_tracker->total_payload);
		if (rx_tracker->payload_requested == rx_tracker->total_payload) {
			next = hfi1_dms_impl_rx_tracker_next_active(dms, rx_tracker);
		}
		
		if (rx_tracker->payload_remaining == 0) {
			dlid = hfi1_dms_lrh16B_slid_get((u32 *) &hdr->lrh[0]);
			data = (union hfi1_dms_proto_pkt_data *)hdr;
			hfi1_dms_rx_tracker_handle_completion(dms, rx_tracker, dlid, data->info.tx_rift_index);
		}

		if (next != NULL) {
			int ret = hfi1_dms_impl_make_read_request(dms, next, tid_set);
			if (ret < 0) {
				dd_dev_dbg(dms->dd, "Could not make read request for next active tracker. - %d\n", ret);
				hfi1_dms_impl_tid_set_put(dms, tid_set);
			}
		} else {
			hfi1_dms_impl_tid_set_put(dms, tid_set);
		}
		rr_end = dms_rdtsc();
		dms->counters.read_request_done += rr_end - rr_start;
	}
	end = dms_rdtsc();
	dms->counters.handle_data += end - start;
}

void hfi1_dms_handle_data_fixup(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr, u8 *data)
{
	union hfi1_dms_proto_pkt_data_fixup * fixup;
	struct hfi1_dms_rx_tracker *rx_tracker;
	u64 rbuf_addr;
	u8 head_misalignment;
	u8 tail_misalignment;
	u64 head;
	u64 tail;
	u32 dlid;

	dms_trace(dms_handle_data_fixup, dms, hdr, data);

	pr_debug("%s:%d:%s() ENTER: dms=%p, hdr=%p\n", __FILENAME__, __LINE__, __func__, dms, hdr);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(hdr == NULL);

	// UNSAFE - the tail field in this is actually in the data pointer
	// this will bleed over into the next hdrq entry otherwise (and also the RHF of this entry)
	fixup = (union hfi1_dms_proto_pkt_data_fixup *)hdr;
	head = fixup->info.head;
	// memcpy(&tail, data, sizeof(u64));
	tail = fixup->info.tail;

	dd_dev_dbg(dms->dd, "Received a header:\n");
	dd_dev_dbg(dms->dd, "Raw: %016llx %016llx %08x %08x %08x %08x %08x %08x\n",
		   hdr->qws[0], hdr->qws[1], hdr->bth[0], hdr->bth[1], hdr->bth[2],
		   hdr->kdeth[0], hdr->kdeth[1], hdr->user_kdeth[0]);
	dd_dev_dbg(dms->dd, "Received fixup data for tx_rift_index %hu, rx_rift_index %hu, head 0x%016llx, tail 0x%016llx\n",
		   fixup->info.tx_rift_index, fixup->info.rx_rift_index, head, tail);

	rx_tracker = (struct hfi1_dms_rx_tracker *) _rift_lookup(&dms->rx_rift, fixup->info.rx_rift_index);
	DMS_BUG_ON(rx_tracker == NULL);
	_rift_release(&dms->rx_rift, fixup->info.rx_rift_index);	// FIXME - blocksome - check the rift pending queue and reuse this rift index for the next guy

	if (rx_tracker->total_payload <= sizeof(u64)) {
		hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset, &head, rx_tracker->total_payload);
		rx_tracker->payload_remaining -= rx_tracker->total_payload;
		DMS_BUG_ON(rx_tracker->payload_remaining > 0);
	} else {
		hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset, &head, sizeof(head));
		hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset + rx_tracker->total_payload - sizeof(u64), &tail, sizeof(tail));

		rbuf_addr = rx_tracker->rbuf->rb.addr + rx_tracker->rbuf_start_offset;
		head_misalignment = (8 - (rbuf_addr & 0x7)) & 0x7;
		tail_misalignment = (rbuf_addr + rx_tracker->total_payload) & 0x7;
		rx_tracker->payload_remaining -= (head_misalignment + tail_misalignment);
	}

	if (rx_tracker->payload_remaining == 0) {
		dlid = hfi1_dms_lrh16B_slid_get((u32 *) &hdr->lrh[0]);
		hfi1_dms_rx_tracker_handle_completion(dms, rx_tracker, dlid, fixup->info.tx_rift_index);
	}
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

void hfi1_dms_impl_handle_data_small_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	union hfi1_dms_proto_pkt_data_small * small;
	struct hfi1_dms_rx_tracker *rx_tracker;

	dms_trace(dms_handle_data_fixup, dms, hdr, data);

	pr_debug("%s:%d:%s() ENTER: dms=%p, hdr=%p\n", __FILENAME__, __LINE__, __func__, dms, hdr);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(hdr == NULL);

	small = (union hfi1_dms_proto_pkt_data_small *)hdr;

	dd_dev_dbg(dms->dd, "Received a header:\n");
	dd_dev_dbg(dms->dd, "Raw: %016llx %016llx %08x %08x %08x %08x %08x %08x\n",
		   hdr->qws[0], hdr->qws[1], hdr->bth[0], hdr->bth[1], hdr->bth[2],
		   hdr->kdeth[0], hdr->kdeth[1], hdr->user_kdeth[0]);
	dd_dev_dbg(dms->dd, "Received small data for rx_rift_index %hu, data0 0x%016llx, data1 0x%016llx\n",
		   small->info.rx_rift_index, small->info.data[0], small->info.data[1]);

	rx_tracker = (struct hfi1_dms_rx_tracker *) _rift_lookup(&dms->rx_rift, small->info.rx_rift_index);
	DMS_BUG_ON(rx_tracker == NULL);

	DMS_BUG_ON(rx_tracker->total_payload > 16);
	if (rx_tracker->total_payload <= 8) {
		hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset, &small->info.data[0], rx_tracker->total_payload);
	} else {
		hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset, &small->info.data[0], sizeof(u64));
		hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset + sizeof(u64), &small->info.data[1], rx_tracker->total_payload - sizeof(u64));
	}
	rx_tracker->payload_remaining -= rx_tracker->total_payload;
	DMS_BUG_ON(rx_tracker->payload_remaining > 0);

	if (rx_tracker->payload_remaining == 0) {
		_rift_release(&dms->rx_rift, small->info.rx_rift_index);	// FIXME - blocksome - check the rift pending queue and reuse this rift index for the next guy
		rx_tracker->completion.fn(&rx_tracker->completion.cookie);
		dd_dev_dbg(dms->dd, "Freeing rx_tracker with dms_key %llu.\n", rx_tracker->dms_key);
		hfi1_dms_impl_rx_tracker_free(dms, rx_tracker);
	}
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

/**
 * THE FOLLOWING STATIC FUNCTIONS WERE COPIED OVER FROM CHIP.C
 * THESE NEED TO BE MOVED TO A COMMON LOCATION BUT FOR NOW LETS JUST HAVE
 * THEM HERE
 * 
 * ALL OF THESE BELOW WILL PROBABLY BE TRIMMED OUT AND STREAMLINED
 */

/* cache values derived from the RHF that are chip dependent */
static void cache_rhf_values(struct hfi1_packet *packet)
{
	struct hfi1_ctxtdata *rcd;
	u64 rhf;

	rcd = packet->rcd;
	rhf = packet->rhf;

	if (rcd->dd->params->chip_type == CHIP_WFR) {
		packet->egr_index = wfr_rhf_egr_index(rhf);
		packet->sc4 = !!wfr_rhf_dc_info(rhf);
		packet->rcv_seq = wfr_rhf_rcv_seq(rhf);
		packet->err_flags = wfr_rhf_err_flags(rhf);
		packet->has_errs = packet->err_flags != 0;
	} else {
		packet->egr_index = (rhf >> 16) & 0x3fff; /* RHF.EgrIndex */
		packet->sc4 = (rhf >> 53) & 0x1;	  /* RHF.L2Type9bSc4 */
		packet->rcv_seq = jkr_rhf_rcv_seq(rhf);	  /* RHF.RcvSeq */
		packet->has_errs = (rhf >> 63) & 0x1;	  /* RHF.RheValid */
		/*
		 * NOTE: (1) The divide can be changed to a shift.  Should
		 *           pre-calculate the value.
		 *       (2) rhqoff (head) and rsize are both in words.
		 */
		if (packet->has_errs)
			packet->err_flags = ((u64 *)(rcd->rheq))[packet->rhqoff / packet->rsize];
		else
			packet->err_flags = 0;
	}
}

static inline void *get_egrbuf(const struct hfi1_packet *packet, u8 *update)
{
	struct hfi1_ctxtdata *rcd;
	u32 idx;
	u64 offset;
	void *ret;

	pr_debug("%s:%d:%s() ENTER: packet=%p, update=%p\n", __FILENAME__, __LINE__, __func__, packet, update);
	rcd = packet->rcd;
	idx = packet->egr_index;
	offset = rhf_egr_buf_offset(packet->rhf);

	*update |= !(idx & (rcd->egrbufs.threshold - 1)) && !offset;
	ret = (void *)(((u64)(rcd->egrbufs.rcvtids[idx].addr)) +
			(offset * RCV_BUF_BLOCK_SIZE));
	pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

static inline void init_packet(struct hfi1_ctxtdata *rcd,
				   struct hfi1_packet *packet)
{
	packet->rsize = get_hdrqentsize(rcd); /* words */
	packet->maxcnt = get_hdrq_cnt(rcd) * packet->rsize; /* words */
	packet->rcd = rcd;
	packet->updegr = 0;
	packet->etail = -1;
	packet->rhqoff = hfi1_rcd_head(rcd);
	packet->numpkt = 0;
	packet->rhf_addr = get_rhf_addr(rcd);
	packet->rhf = rhf_to_cpu(packet->rhf_addr);
	cache_rhf_values(packet);
}

static inline void finish_packet(struct hfi1_packet *packet)
{
	/*
	 * Nothing we need to free for the packet.
	 *
	 * The only thing we need to do is a final update and call for an
	 * interrupt
	 */
	if (packet->numpkt > 0) {
		update_usrhead(packet->rcd, hfi1_rcd_head(packet->rcd), packet->updegr,
				packet->etail, rcv_intr_dynamic, packet->numpkt);
	}
}

static inline void process_rcv_update(int last, struct hfi1_packet *packet)
{
	pr_debug("%s:%d:%s() ENTER: last=%d, packet=%p\n", __FILENAME__, __LINE__, __func__, last, packet);
	/*
	 * Update head regs etc., every 256 packets, if not last pkt,
	 * to help prevent rcvhdrq overflows, when many packets
	 * are processed and queue is nearly full.
	 * Don't request an interrupt for intermediate updates.
	 * 256 chosen because that's what we do in BMT
	 */
	if (last || !(packet->rhqoff & 0xff)) {
		update_usrhead(packet->rcd, packet->rhqoff, packet->updegr,
				   packet->etail, 0, 0);
		packet->updegr = 0;
	}
	packet->grh = NULL;
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

static inline int process_rcv_packet(struct hfi1_packet *packet)
{
	int ret = 0;

	pr_debug("%s:%d:%s() ENTER: packet=%p\n", __FILENAME__, __LINE__, __func__, packet);
	packet->etype = rhf_rcv_type(packet->rhf);

	/* total length */
	packet->tlen = rhf_pkt_len(packet->rhf); /* in bytes */
	/* retrieve eager buffer details */
	packet->ebuf = NULL;
	if (rhf_use_egr_bfr(packet->rhf)) {
		packet->etail = packet->egr_index;
		packet->ebuf = get_egrbuf(packet, &packet->updegr);
		/*
		 * Prefetch the contents of the eager buffer.  It is
		 * OK to send a negative length to prefetch_range().
		 * The +2 is the size of the RHF.
		 */
		prefetch_range(packet->ebuf,
				   packet->tlen - ((get_hdrqentsize(packet->rcd) -
						   (rhf_hdrq_offset(packet->rhf)
						+ 2)) * 4));
	}

	/*
	 * Call a type specific handler for the packet. We
	 * should be able to trust that etype won't be beyond
	 * the range of valid indexes. If so something is really
	 * wrong and we can probably just let things come
	 * crashing down. There is no need to eat another
	 * comparison in this performance critical code.
	 */
	packet->rcd->rhf_rcv_function_map[packet->etype](packet);
	packet->numpkt++;

	/* Set up for the next packet */
	packet->rhqoff += packet->rsize;
	if (packet->rhqoff >= packet->maxcnt)
		packet->rhqoff = 0;

	packet->rhf_addr = (__le32 *)packet->rcd->rcvhdrq + packet->rhqoff +
					  packet->rcd->rhf_offset;
	packet->rhf = rhf_to_cpu(packet->rhf_addr);
	cache_rhf_values(packet);

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

static inline void *hfi1_get_header(struct hfi1_ctxtdata *rcd,
					__le32 *rhf_addr)
{
	u64 offset;
	void *ret;

	pr_debug("%s:%d:%s() ENTER: rcd=%p, rhf_addr=%p\n", __FILENAME__, __LINE__, __func__, rcd, rhf_addr);
	offset = rhf_hdrq_offset(rhf_to_cpu(rhf_addr));

	ret = (void *)(rhf_addr - rcd->rhf_offset + offset);
	pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

static inline union hfi1_dms_16b_header
		*hfi1_get_16B_header(struct hfi1_ctxtdata *rcd,
					 __le32 *rhf_addr)
{
	union hfi1_dms_16b_header *ret;

	pr_debug("%s:%d:%s() ENTER: rcd=%p, rhf_addr=%p\n", __FILENAME__, __LINE__, __func__, rcd, rhf_addr);
	ret = (union hfi1_dms_16b_header *)hfi1_get_header(rcd, rhf_addr);
	pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

static inline enum hfi1_dms_msg_type hfi1_dms_impl_message_type_get(union hfi1_dms_16b_header *hdr)
{
	enum hfi1_dms_msg_type ret;

	pr_debug("%s:%d:%s() ENTER: hdr=%p\n", __FILENAME__, __LINE__, __func__, hdr);
	ret = (enum hfi1_dms_msg_type) ((hdr->bth[0] & 0x00FF0000) >> 16); // Extract the message type from BTH
	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

void hfi1_dms_impl_noop_packet(struct hfi1_packet *packet)
{
	pr_debug("%s:%d:%s() ENTER: packet=%p\n", __FILENAME__, __LINE__, __func__, packet);
	(void) packet;
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

void hfi1_dms_impl_handle_packet(struct hfi1_packet *packet)
{
	struct hfi1_bulksvc *svc;
	struct hfi1_dms *dms;
	union hfi1_dms_16b_header *hdr;
	enum hfi1_dms_msg_type msg_type;

	pr_debug("%s:%d:%s() ENTER: packet=%p\n", __FILENAME__, __LINE__, __func__, packet);
	DMS_BUG_ON(packet == NULL);
	DMS_BUG_ON(packet->rcd == NULL);
	DMS_BUG_ON(packet->rcd->dd == NULL);
	DMS_BUG_ON(packet->rcd->dd->bulksvc == NULL);

	svc = packet->rcd->dd->bulksvc;
	dms = &svc->dms;

	// We set hardware to drop 9B packets to our rcd
	dd_dev_dbg(dms->dd, "DMS: Received packet with RHF: 0x%016llx, rcv_seq: %uhas_errs: %d\n",
		   packet->rhf, packet->rcv_seq, packet->has_errs);
	if (DMS_WARN_ON(jkr_rhf_l2_type(packet->rhf) != HFI1_L2_TYPE_16B)) {
		pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
		return;
	}

	hdr = hfi1_get_16B_header(dms->rctxt, packet->rhf_addr);
	msg_type = hfi1_dms_impl_message_type_get(hdr);
	switch (msg_type) {
	case HFI1_DMS_MSG_TYPE_READ_REQUEST:
		hfi1_dms_impl_handle_read_request_packet(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_READ_REQUEST_FIXUP:
		hfi1_dms_impl_handle_read_request_fixup_packet(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_DATA:
		hfi1_dms_handle_data(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_DATA_FIXUP: { // requires some data from eager buffer
		hfi1_dms_handle_data_fixup(dms, hdr, packet->ebuf);
		break;
	}

	case HFI1_DMS_MSG_TYPE_READ_REQUEST_ACK:
		hfi1_dms_impl_handle_read_request_ack(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_READ_REQUEST_EXPECTED:
		hfi1_dms_impl_handle_read_request_expected_packet(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_READ_REQUEST_SMALL:
		hfi1_dms_impl_handle_read_request_small_packet(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_DATA_SMALL:
		hfi1_dms_impl_handle_data_small_packet(dms, hdr);
		break;

	default:
		dd_dev_err(dms->dd, "Received unknown message type: %d\n", msg_type);
		break;
	}
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}


void hfi1_dms_impl_reclaim_ahg(struct hfi1_dms *dms, struct sdma_engine *sde, struct hfi1_dms_sde_rsrc *sde_rsrc)
{
	u32 descq_head;
	u32 descq_tail;
	struct hfi1_dms_ahg_header *ahg_header;
	u32 ahg_desc;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(sde == NULL);
	DMS_WARN_ON(sde_rsrc == NULL);

	descq_head = sde->descq_head;
	descq_tail = sde->descq_tail;
	if (descq_head == descq_tail) {
		// reclaim all
		while (sde_rsrc->active_ahg_headers.head != NULL) {
			ahg_header = (struct hfi1_dms_ahg_header *) sde_rsrc->active_ahg_headers.head;
			ahg_desc = ahg_header->desc_idx;
			dd_dev_dbg(dms->dd, "Reclaiming AHG header used in engine %d at idx %u [head, tail): [%u, %u)\n", sde->this_idx, ahg_desc, descq_head, descq_tail);
			hfi1_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
			hfi1_dms_impl_dlist_append(&dms->ahg_headers.free, &ahg_header->dlist);
		}
	} else if (descq_head < descq_tail) {
		while (sde_rsrc->active_ahg_headers.head != NULL) {
			ahg_header = (struct hfi1_dms_ahg_header *) sde_rsrc->active_ahg_headers.head;
			ahg_desc = ahg_header->desc_idx;
			if (ahg_desc > descq_head && ahg_desc <= descq_tail) {
				// this is within our list and our headers
				// are in-order here so we can just stop
				break;
			}
			dd_dev_dbg(dms->dd, "Reclaiming AHG header used in engine %d at idx %u [head, tail): [%u, %u)\n", sde->this_idx, ahg_desc, descq_head, descq_tail);
			hfi1_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
			hfi1_dms_impl_dlist_append(&dms->ahg_headers.free, &ahg_header->dlist);
		}
	} else {
		while (sde_rsrc->active_ahg_headers.head != NULL) {
			ahg_header = (struct hfi1_dms_ahg_header *) sde_rsrc->active_ahg_headers.head;
			ahg_desc = ahg_header->desc_idx;
			if (ahg_desc <= descq_tail || ahg_desc > descq_head) {
				// tail has wrapped, so this is within our list
				// and we can stop searching
				break;
			}
			dd_dev_dbg(dms->dd, "Reclaiming AHG header used in engine %d at idx %u [head, tail): [%u, %u)\n", sde->this_idx, ahg_desc, descq_head, descq_tail);
			hfi1_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
			hfi1_dms_impl_dlist_append(&dms->ahg_headers.free, &ahg_header->dlist);
		}
	}
}

int hfi1_dms_poll(struct hfi1_dms *dms)
{
	u64 start;
	int i;
	u64 const MAX_PACKETS_PER_POLL = dms->rctxt->rcvhdrq_cnt;
	struct hfi1_packet packet = {0};
	ktime_t now = ktime_get();
	int last = RCV_PKT_OK;
	u64 actual_packet_start;
	u64 actual_packet_end;
	u64 end;

	start = dms_rdtsc();

	dms_trace(dms_poll, dms);

	for (i = 0; i < dms->num_engines; ++i) {
		sdma_gethead_dma(dms->sdma_engines[i]);
		hfi1_dms_impl_reclaim_ahg(dms, dms->sdma_engines[i], &dms->sde_rsrcs[i]);
	}

	if (dms->work_items.active.head) {
		struct hfi1_dms_work_item *item, *next_item;

		item = (struct hfi1_dms_work_item *)dms->work_items.active.head;
		while (item) {
			next_item = (struct hfi1_dms_work_item *)item->dlist.next;
			if (item->work_fn(dms, item) != -EAGAIN) {
				hfi1_dms_impl_work_item_free(dms, item);
			} else {
				u64 elapsed_ns = ktime_to_ns(ktime_sub(now, item->enqueue_time));
				if (elapsed_ns > HFI1_DMS_WORK_ITEM_MAX_RETRY_TIME_NS) {
					dd_dev_err(dms->dd,
						   "DMS work item failed after max retry time, discarding.\n");
					hfi1_dms_impl_work_item_free(dms, item);
				}
			}
			item = next_item;
		}
	}

	init_packet(dms->rctxt, &packet);
	if (last_rcv_seq(dms->rctxt, packet.rcv_seq)) {
		goto bail;
	}

	actual_packet_start = dms_rdtsc();
	while (last == RCV_PKT_OK) {
		last = process_rcv_packet(&packet);
		if (hfi1_seq_incr(dms->rctxt, packet.rcv_seq)) {
			last = RCV_PKT_DONE;
		}
		process_rcv_update(last, &packet);
		if (packet.numpkt > MAX_PACKETS_PER_POLL) {
			break;
		}
	}
	hfi1_set_rcd_head(dms->rctxt, packet.rhqoff);
	actual_packet_end = dms_rdtsc();
	dms->counters.hdrq_drain_packet += actual_packet_end - actual_packet_start;

bail:
	finish_packet(&packet);
	end = dms_rdtsc();
	dms->counters.hdrq_drain += end - start;
	return packet.numpkt;
}


int hfi1_dms_impl_access_ref_inc(struct hfi1_dms *dms, struct hfi1_dms_access * access)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!access);

	if ((access->type == HFI1_DMS_ACCESS_TYPE_EPHEMERAL) && (access->active_count > 0)) {
		// error .. can't have multiple in-flight transfers on an ephemeral access window
		// FIXME - blocksome
		return -1;
	}

	access->active_count += 1;

	return 0;
}

void hfi1_dms_impl_access_ref_dec(struct hfi1_dms *dms, struct hfi1_dms_access * access)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!access);
	DMS_BUG_ON(access->active_count == 0);

	access->active_count -= 1;

	if (access->type == HFI1_DMS_ACCESS_TYPE_EPHEMERAL) {
		hfi1_dms_access_remove(dms, access);
		hfi1_dms_access_freelist_push(dms, access);
	}
}


void hfi1_dms_handle_tx_tracker_completion(struct hfi1_dms *dms, u16 tx_rift_index)
{
	pr_debug("%s:%d:%s() ENTER: dms=%p, tx_rift_index=%hu\n", __FILENAME__, __LINE__, __func__, dms, tx_rift_index);
	DMS_BUG_ON(dms == NULL);

	struct hfi1_dms_tx_tracker *tx_tracker = (struct hfi1_dms_tx_tracker *) _rift_lookup(&dms->tx_rift, tx_rift_index);
	DMS_BUG_ON(tx_tracker == NULL);

	dd_dev_dbg(dms->dd, "All data for tx_tracker with rift index %hu has been received. Invoking completion callback with cookie\n"
						"\t.qw[0] 0x%016llx\n\t.qw[1] 0x%016llx\n\t.qw[2] 0x%016llx\n\t.qw[3] 0x%016llx\n"
						"\t.qw[4] 0x%016llx\n\t.qw[5] 0x%016llx\n\t.qw[6] 0x%016llx\n\t.qw[7] 0x%016llx\n", tx_rift_index, 
						tx_tracker->completion.cookie.qw[0], tx_tracker->completion.cookie.qw[1],
						tx_tracker->completion.cookie.qw[2], tx_tracker->completion.cookie.qw[3],
						tx_tracker->completion.cookie.qw[4], tx_tracker->completion.cookie.qw[5],
						tx_tracker->completion.cookie.qw[6], tx_tracker->completion.cookie.qw[7]);


	// invoke callback for the complete tx tracker
	tx_tracker->completion.fn(&tx_tracker->completion.cookie);

	// REMOVE tx_tracker from tx-rift
	_rift_release(&dms->tx_rift, tx_tracker->rift_index);

	// DECREMENT reference count on access
	//   if access is ephemeral then REMOVE access
	hfi1_dms_impl_access_ref_dec(dms, tx_tracker->access);

	// NOW free the tracker
	hfi1_dms_impl_tx_tracker_free(dms, tx_tracker);

	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

/**
 * These functions exist in some form in hfi1.h but they don't exist in the way
 * we really want them here. Convenience functions for our pre-defined
 * templates
 */
u64 hfi1_dms_impl_pbc_template_create_16Bc(u8 port_idx, u32 dw_len, u32 sctxt)
{
	u64 ret;

	pr_debug("%s:%d:%s() ENTER: port_idx=%u, dw_len=%u, sctxt=%u\n", __FILENAME__, __LINE__, __func__, port_idx, dw_len, sctxt);
	ret = (u64) sctxt << PBC_SEND_CTXT_SHIFT |
		(u64) PBC_L2_16B << PBC_L2_TYPE_SHIFT |
		(u64) port_idx << PBC_PORT_IDX_SHIFT |
		(u64) (dw_len & PBC_LENGTH_DWS_MASK) << PBC_LENGTH_DWS_SHIFT |
		(u64) PBC_IHCRC_LKDETH << PBC_INSERT_HCRC_SHIFT |
		(u64) 1 << 19 | // 16B Compressed
		(u64) PBC_INSERT_BYPASS_ICRC; // InsertNon9BIcrc
	pr_debug("%s:%d:%s() EXIT: ret=0x%llx\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

int hfi1_dms_impl_proto_command_template_make(struct hfi1_dms *dms, union hfi1_dms_proto_cmd *cmd, enum hfi1_dms_msg_type msg_type, u32 pkt_len_qws)
{
	pr_debug("%s:%d:%s() ENTER: dms=%p, cmd=%p, msg_type=%d, pkt_len_qws=%u\n",
		   __FILENAME__, __LINE__, __func__, dms, cmd, msg_type, pkt_len_qws);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(cmd == NULL);
	// Even though the PBC gets stripped, a 16b compressed header will expand by 1 QW as it goes
	// out on the wire, so actually the pktlen_dw in the pbc should be the same as pktlen_qw in the lrh
	cmd->pbc = hfi1_dms_impl_pbc_template_create_16Bc(dms->dd->pport[HFI1_DMS_PORT].hw_pidx, pkt_len_qws << 1, dms->rctxt->sc->hw_context);
	hfi1_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc, pkt_len_qws);
	cmd->bth[0] = HFI1_DMS_BTH_OPCODE | ((u32) msg_type << 16) | ((u32) dms->rctxt->ctxt << 24);
	cmd->bth[1] = (u32) RVT_KDETH_QP_PREFIX << 8;
	cmd->kdeth[0] = 1 << 30; // set KVER
	cmd->kdeth[1] = HFI1_DMS_JKEY;

	dd_dev_info(dms->dd, "Created protocol command template for msg_type %d with pkt_len_qws %u\n", msg_type, pkt_len_qws);
	dd_dev_info(dms->dd, "PBC: 0x%016llx, LRH: 0x%016llx, BTH: 0x%08x, KDETH: 0x%08x %08x\n",
		   (unsigned long long) cmd->pbc,
		   (unsigned long long) cmd->lrh16bc,
		   cmd->bth[0], cmd->kdeth[0], cmd->kdeth[1]);

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0;
}

void hfi1_dms_impl_fill_proto_templates(struct hfi1_dms *dms)
{
	union hfi1_dms_proto_cmd *cmd;

	DMS_BUG_ON(dms == NULL);
	pr_debug("%s:%d:%s() ENTER: dms=%p\n", __FILENAME__, __LINE__, __func__, dms);
 	
	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_REQUEST];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_READ_REQUEST, 8);

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_REQUEST_EXPECTED];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_READ_REQUEST_EXPECTED, 8);

	// union hfi1_dms_proto_cmd_read_request_fixup
	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_REQUEST_FIXUP];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_READ_REQUEST_FIXUP, sizeof(union hfi1_dms_proto_pkt_read_request_fixup)/sizeof(u64));
	
	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_DATA, 8); // <-- 'pkt_len_qws' determined at runtime

	// union hfi1_dms_proto_cmd_data_fixup
	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_FIXUP];
	// we use `hfi1_dms_proto_pkt_data_fixup` here not `cmd_data_fixup` because the tail flit has to be sent over the wire but
	// it gets dropped by the hardware on the receive side. Also we don't need to include all the extra padding that would just use
	// an eager buffer slot
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_DATA_FIXUP, sizeof(union hfi1_dms_proto_pkt_data_fixup)/sizeof(u64));

	// union hfi1_dms_proto_cmd_read_request_ack
	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_REQUEST_ACK];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_READ_REQUEST_ACK, sizeof(union hfi1_dms_proto_pkt_read_request_ack)/sizeof(u64));

	// union hfi1_dms_proto_cmd_read_request_small
	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_REQUEST_SMALL];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_READ_REQUEST_SMALL, sizeof(union hfi1_dms_proto_pkt_read_request_small)/sizeof(u64));

	// union hfi1_dms_proto_cmd_data_small
	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_SMALL];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_DATA_SMALL, sizeof(union hfi1_dms_proto_pkt_data_small)/sizeof(u64));

	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

int hfi1_dms_impl_16bc_state_set(struct hfi1_dms *dms)
{
	struct hfi1_devdata *dd;
	struct hfi1_ctxtdata *rcd;
	u64 slid_reg;
	u64 mask;
	u64 lid;

	pr_debug("%s:%d:%s() ENTER: dms=%p\n", __FILENAME__, __LINE__, __func__, dms);
	DMS_BUG_ON(dms == NULL);
	dd = dms->dd;
	rcd = dms->rctxt;
	mask = ~((1U << dd->pport[HFI1_DMS_PORT].lmc) - 1);
	lid = dd->pport[HFI1_DMS_PORT].lid;

	// TODO: I actually think all the things we need
	// to set are done so by default for us
	// but if not they are SendCtxtCheckSLID and
	// SendCtxtCheckCspecAge
	hfi1_set_ctxt_pkey(dd, rcd, HFI1_DMS_PKEY);
	slid_reg = BIT_ULL(63)
					| (mask & JKR_SEND_CTXT_CHECK_SLID_MASK_MASK) << JKR_SEND_CTXT_CHECK_SLID_MASK_SHIFT 
					| (lid & JKR_SEND_CTXT_CHECK_SLID_VALUE_MASK) << JKR_SEND_CTXT_CHECK_SLID_VALUE_SHIFT;
	write_epsc_csr(dd, dd->pport[HFI1_DMS_PORT].hw_pidx, dms->sctxt->hw_context,
			       dd->params->send_ctxt_check_slid_reg, slid_reg);
	pr_debug("%s:%d:%s() Set SendCtxtCheckSLID to 0x%016llx, mask %u, slid %u\n", __FILENAME__, __LINE__, __func__, slid_reg, dd->pport[HFI1_DMS_PORT].lmc, dd->pport[HFI1_DMS_PORT].lid);

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0;
}

// put somewhere common later
static inline u32 rcvarray_offset(u32 ctxt, u32 index, u32 type)
{
	u32 ret;
/* RcvArray access shifts */
#define JKR_RCV_ARRAY_EGR_TID_SELECT_SHIFT 25
#define JKR_RCV_ARRAY_RCV_CTXT_IDX_SHIFT 17
#define JKR_RCV_ARRAY_CSR_INDEX_SHIFT 3
	pr_debug("%s:%d:%s() ENTER: ctxt=%u, index=%u, type=%u\n", __FILENAME__, __LINE__, __func__, ctxt, index, type);
	ret = (type == PT_EAGER ? 0 : BIT(JKR_RCV_ARRAY_EGR_TID_SELECT_SHIFT))
	       | (ctxt << JKR_RCV_ARRAY_RCV_CTXT_IDX_SHIFT)
	       | (index << JKR_RCV_ARRAY_CSR_INDEX_SHIFT);
	pr_debug("%s:%d:%s() EXIT: ret=0x%x\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

int hfi1_dms_impl_map_tid_entries(struct hfi1_dms *dms, struct hfi1_mem_region * hfi1_mr, u64 start_page_index, u64 npages, s32 tid_set)
{
	u64 start;
	u64 tid_entries[HFI1_DMS_TID_SET_SIZE * 2] = {0};
	u64 tid_start;
	u64 tid_entry_start;
	u64 npages_twos;
	size_t i;
	dma_addr_t next_phys_addr;
	u64 csr_offset;
	u64 end;

	dms_trace(dms_map_tid_entries, dms, hfi1_mr, start_page_index, npages, tid_set);

	pr_debug("%s:%d:%s() ENTER: dms=%p, hfi1_mr=%p, start_page_index=%llu, npages=%llu, tid_set=%d\n",
		   __FILENAME__, __LINE__, __func__, dms, hfi1_mr, start_page_index, npages, tid_set);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(hfi1_mr == NULL);
	DMS_BUG_ON(tid_set < HFI1_DMS_TID_SET_IDX_MIN || tid_set > HFI1_DMS_TID_SET_IDX_MAX);
	DMS_BUG_ON(npages <= 0);
	DMS_BUG_ON(npages > (HFI1_DMS_TID_SET_SIZE*2));
	start = dms_rdtsc();

	tid_start = tid_set * HFI1_DMS_TID_SET_SIZE;
	tid_entry_start = tid_start * 2;

	npages_twos = (npages + 1) & ~1ull;

	for (i = 0; i < npages; ++i) {
		next_phys_addr = hfi1_mr->dma_list[start_page_index + i];
		tid_entries[i] = (u64) (next_phys_addr >> 12) | (1ull << 46) | BIT(63);
	}
	if (npages & 1) {
		tid_entries[npages] = (u64) (dms->zero_page.phys_addr >> 12) | (1ull << 46) | BIT(63);
	}

	csr_offset = rcvarray_offset(dms->rctxt->ctxt, tid_entry_start, PT_EXPECTED);
	for (i = 0; i < npages_twos; ++i) {
		writeq(tid_entries[i], dms->dd->bar_maps[ctxt_bar_idx(dms->rctxt->ctxt)].rcvarray_wc + csr_offset + (i * sizeof(u64)));
	}
	end = dms_rdtsc();
	dms->counters.map_tids += end - start;
	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0;
}

int hfi1_dms_impl_make_fixup_read_request(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker)
{
	union hfi1_dms_proto_cmd_read_request_fixup cmd;
	uintptr_t rbuf_addr;
	u64 rbuf_size;
	u8 head_misalignment;
	u8 tail_misalignment;
	u8 length_adjust;
	u64 dms_key = rx_tracker->dms_key;
	u16 rx_rift_index;
	int ret;

	dms_trace(dms_make_fixup_read_request, dms, rx_tracker);

	rbuf_size = rx_tracker->total_payload;
	DMS_WARN_ON(rbuf_size <= 8);

	if (rbuf_size <= 8) {
		head_misalignment = 0;
		tail_misalignment = 0;
		length_adjust = rbuf_size;

	} else {
		rbuf_addr = rx_tracker->rbuf->rb.addr + rx_tracker->rbuf_start_offset;
		head_misalignment = (8 - (rbuf_addr & 0x7)) & 0x7;
		tail_misalignment = (rbuf_addr + rbuf_size) & 0x7;
		length_adjust = head_misalignment + tail_misalignment;
		
		if (length_adjust == 0) {
			return 0; // nothing to do
		}
	}

	dd_dev_dbg(dms->dd, "Tracker for key %llu has head misalignment %u and tail misalignment %u.\n", dms_key, head_misalignment, tail_misalignment);

	// advance rx tracker state
	// we're going to set this _now_ because
	// even if the sending fails due to PIO not being
	// available, we need to start making read requests
	// from the right offsets
	rx_tracker->rbuf_offset += head_misalignment;
	rx_tracker->sbuf_offset += head_misalignment;
	rx_tracker->payload_requested = length_adjust;

	ret = _rift_reserve(&dms->rx_rift, &rx_rift_index);
	DMS_BUG_ON(ret < 0); // FIXME - blocksome - add to a "pending" queue attached to this rift
	//if (ret < 0) {
	//	dd_dev_dbg(dms->dd, "Rx RDMA In-Flight Table is full.\n");
	//	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
	//	return ret;
	//}

	_rift_assign(&dms->rx_rift, (union hfi1_dms_tracker *)rx_tracker, rx_rift_index);

	cmd = hfi1_dms_proto_cmd_read_request_fixup_make(dms, rx_tracker, rx_tracker->src_lid, rx_rift_index);

	ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
	if (ret < 0) {
		dd_dev_err(dms->dd, "Failed to send or enqueue read request fixup\n");
		return ret;
	}

	return 0;
}

int hfi1_dms_impl_make_read_request(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *tracker, s32 tid_set)
{
	uintptr_t payload_start;
	u64 start;
	u64 recv_offset_bytes;
	u64 recv_offset_dws;
	u64 start_page_index;
	u64 bytes_to_be_requested;
	u64 extent_remaining;
	u64 npages_remaining;
	u64 npages_to_request;
	u64 nbytes_to_request;
	struct hfi1_dms_read_request_state *read_req_state;
	u32 tid_info;
	u32 read_size_qw;
	union hfi1_dms_proto_cmd cmd;
	u32 bth0;
	u64 end;

	dms_trace(dms_make_read_request, dms, tracker, tid_set);

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(tracker == NULL);
	DMS_BUG_ON(tracker->total_payload == 0);

	DMS_BUG_ON(tracker->total_payload - tracker->payload_requested == 0);

	payload_start = tracker->rbuf->rb.addr + tracker->rbuf_offset;
	DMS_BUG_ON(payload_start & 0x7); // Ensure payload_start is QW aligned

	start = dms_rdtsc();
	if (tracker->tx_rift_index == HFI1_DMS_TX_RIFT_INDEX_PENDING) {
		dd_dev_dbg(dms->dd, "tx_rift_index is still pending, cannot make expected read request yet.\n");
		return -EAGAIN;
	}

	/* NOTE: for now we are faking that everything is 4k pages in our
	 * memory registration. If for some reason we get huge pages then
	 * we'll just create fake 4k pages that we still iterate over
	 * TODO: when we get GPU pages or Huge Pages, we should have separate
	 * functions / protocol code paths that handle that so we can do
	 * efficient things like using a single TID with offsets
	 */

	// Figure out how many QWs we're actually requesting here, will be determined based on max number
	// of pages per tid set we can map and also the rbuf offset into the first page

	// calculate byte offset into first page to receive data position
	recv_offset_bytes = (payload_start & (PAGE_SIZE - 1));
	// on first read request this might be non-zero but it should be zero
	// on most read requests
	recv_offset_dws = recv_offset_bytes >> 2;

	// determine which os page contains the first byte to request
	// rbuf_offset contains recv_offset_bytes already
	start_page_index = tracker->rbuf_offset / PAGE_SIZE;

	// determine the number of pages to map into the tidset; also the number of bytes to request from the remote
	bytes_to_be_requested =  tracker->total_payload - tracker->payload_requested;
	extent_remaining = recv_offset_bytes + bytes_to_be_requested;
	npages_remaining = (extent_remaining + (PAGE_SIZE - 1)) / PAGE_SIZE;
	npages_to_request = min(npages_remaining, (u64) HFI1_DMS_TID_SET_PAGES_MAX);
	nbytes_to_request = min(extent_remaining, (npages_to_request * PAGE_SIZE)) - recv_offset_bytes;

	dd_dev_dbg(dms->dd, "Mem Key %llu - Read request for %llu bytes at tid_offset %llu, starting page index %llu, npages_to_request %llu, nbytes_to_request %llu, tid_set %d\n",
			   tracker->dms_key, nbytes_to_request, recv_offset_bytes, start_page_index, npages_to_request, nbytes_to_request, tid_set);

	int ret = hfi1_mem_region_pinned_check(tracker->rbuf, start_page_index, npages_to_request);
	if (ret < 0) {
		return -EAGAIN;
	}

	hfi1_dms_impl_map_tid_entries(dms, tracker->rbuf, start_page_index, npages_to_request, tid_set);

	read_size_qw = nbytes_to_request >> 3;

	read_req_state = &dms->read_requests[tid_set];
	*read_req_state = (struct hfi1_dms_read_request_state){
		.total_requested_qws = read_size_qw,
		.remaining_qws = read_size_qw,
		.rx_tracker = tracker,
	};

	tid_info = hfi1_dms_tid_info_make(tid_set * HFI1_DMS_TID_SET_SIZE, recv_offset_dws);
	if (tracker->tx_rift_index == HFI1_DMS_TX_RIFT_INDEX_NOT_SET) {
		cmd = dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_REQUEST];
		struct hfi1_dms_read_request_payload * payload = (struct hfi1_dms_read_request_payload *) &cmd.user_kdeth[0];
		payload->tid_info = tid_info;
		payload->offset = tracker->sbuf_offset;
		payload->dms_key = tracker->dms_key;
		tracker->tx_rift_index = HFI1_DMS_TX_RIFT_INDEX_PENDING;
	} else if (tracker->tx_rift_index >= 0) {
		cmd = dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_REQUEST_EXPECTED];
		struct hfi1_dms_read_request_payload * payload = (struct hfi1_dms_read_request_payload *) &cmd.user_kdeth[0];
		payload->tid_info = tid_info;
		payload->offset = tracker->sbuf_offset;
		payload->tx_rift_index = tracker->tx_rift_index;
	} else {
		DMS_WARN_ON(tracker->tx_rift_index != HFI1_DMS_TX_RIFT_INDEX_PENDING);
		dd_dev_dbg(dms->dd, "tx_rift_index is still pending, cannot make expected read request yet.\n");
		return -EAGAIN;
	}

	hfi1_dms_impl_pbc_dlid_set(&cmd.pbc, tracker->src_lid);
	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, tracker->src_lid);
	bth0 = cmd.bth[0] & ~(0xffu << 24);
	cmd.bth[0] = bth0 | dms->rctxt->ctxt << 24;
	cmd.bth[2] = (read_size_qw << 16) | (cmd.bth[2] & 0xff);

	ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, &cmd);
	if (ret < 0) {
		dd_dev_dbg(dms->dd, "Unable to send read request.\n");
		return ret;
	}

	tracker->payload_requested += nbytes_to_request;
	tracker->sbuf_offset += nbytes_to_request;
	tracker->rbuf_offset += nbytes_to_request;
	end = dms_rdtsc();
	dms->counters.make_read_request += end - start;
	return 0;
}

int hfi1_dms_impl_make_read_requests(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *tracker)
{
	s32 tid_set;
	int rc = 0;

	pr_debug("%s:%d:%s() ENTER: dms=%p, tracker=%p\n", __FILENAME__, __LINE__, __func__, dms, tracker);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(tracker == NULL);

	tid_set = hfi1_dms_impl_tid_set_peek(dms);

	while (rc == 0 && tid_set >= 0 && (tracker->payload_requested < tracker->total_payload)) {
		rc = hfi1_dms_impl_make_read_request(dms, tracker, tid_set);
		if (rc == 0) {
			hfi1_dms_impl_tid_set_get(dms);
			tid_set = hfi1_dms_impl_tid_set_peek(dms);
		}
	}

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, rc);
	return rc;
}

static int hfi1_dms_impl_queue_work_item(struct hfi1_dms *dms, void * data, size_t len, hfi1_dms_work_fn work_fn)
{
	struct hfi1_dms_work_item *item;

	if (len > sizeof(item->data)) {
		return -EINVAL;
	}
	item = hfi1_dms_impl_work_item_new(dms);
	if (!item) {
		return -ENOMEM;
	}

	item->work_fn = work_fn;
	item->enqueue_time = ktime_get();
	memcpy(item->data, data, len);
	return 0; /* successfully queued */
}

int _calculate_byte_offset_from_first_mr_page(struct hfi1_dms *dms, struct hfi1_dms_access * access, u64 offset, u64 *byte_offset_from_first_page)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!access);
	DMS_BUG_ON(!byte_offset_from_first_page);

	if (access->mr->mode == HFI1_DMS_MR_MODE_VADDR) {
		// offset is interpreted as a user virtual address
		if (offset < access->mr->user.addr) {
			dd_dev_err(dms->dd, "Invalid virtual address offset.\n");
			return -EINVAL;
		}
		*byte_offset_from_first_page = offset - access->mr->user.addr;
	} else {
		*byte_offset_from_first_page = access->mr->region_offset + access->offset + offset;
	}

	return 0;
}

struct hfi1_dms_tx_tracker * hfi1_dms_impl_tx_tracker_new(struct hfi1_dms *dms, struct hfi1_dms_access *access, u64 nbytes, u16 tx_rift_index)
{
	struct hfi1_dms_tx_tracker * tx_tracker;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!access);

	tx_tracker = (struct hfi1_dms_tx_tracker *) hfi1_dms_impl_tracker_new(&dms->tx_trackers, sizeof(struct hfi1_dms_tx_tracker));
	hfi1_dms_impl_tx_tracker_initialize(tx_tracker, access, nbytes, tx_rift_index);

	return tx_tracker;
}

int hfi1_dms_impl_handle_read_request(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr, enum hfi1_dms_msg_type const type)
{
	u64 start;
	struct hfi1_dms_read_request_payload *rr;
	struct hfi1_dms_client_state * client = NULL;
	u64 offset;
	u32 size_qw;
	u32 nbytes;
	struct hfi1_dms_access *access;
	struct hfi1_dms_tx_tracker *tx_tracker;
	u16 tx_rift_index;
	int ret = 0;
	u64 end;

	dms_trace(dms_handle_read_request, dms, hdr);

	pr_debug("%s:%d:%s() ENTER: dms=%p, hdr=%p\n", __FILENAME__, __LINE__, __func__, dms, hdr);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(hdr == NULL);
	DMS_BUG_ON((type != HFI1_DMS_MSG_TYPE_READ_REQUEST) && (type != HFI1_DMS_MSG_TYPE_READ_REQUEST_EXPECTED));
	DMS_BUG_ON(hfi1_dms_impl_message_type_get(hdr) != type);

	start = dms_rdtsc();
	if (dms->counters.rcv_first_rr == 0) {
		dms->counters.rcv_first_rr = ktime_get();
	}

	rr = (struct hfi1_dms_read_request_payload *) &hdr->user_kdeth[0];

	offset = rr->offset;
	size_qw = hfi1_dms_impl_read_request_size_qw_get(hdr);
	nbytes = size_qw << 3;
	u32 dlid = hfi1_dms_lrh16B_slid_get((u32 *) &hdr->lrh[0]);
	u8 rx_id = hdr->bth[0] >> 24;
	u32 tid_info = rr->tid_info;

	u64 page_offset = 0;

	if (type == HFI1_DMS_MSG_TYPE_READ_REQUEST) {

		access = hfi1_dms_access_lookup(dms, rr->dms_key, &client);
		if (!client) {
			dd_dev_dbg(dms->dd, "Client not found for dms_key %llu.\n", rr->dms_key);
			pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -ENOENT);
			return -ENOENT;
		}

		if (!access) {
			dd_dev_dbg(dms->dd, "Access not found for key %llu.\n", rr->dms_key);
			pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -ENOMSG);
			return -ENOMSG;
		}

		ret = hfi1_dms_impl_access_ref_inc(dms, access);
		if (ret < 0) {
			dd_dev_dbg(dms->dd, "Unable to increment access active count for key %llu. Likely because of a previously active transfer on an ephemeral access window\n", rr->dms_key);
			pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -ENOMSG);
			return -EINVAL;
		}

		ret = _rift_reserve(&dms->tx_rift, &tx_rift_index);
		if (ret < 0) {
			dd_dev_dbg(dms->dd, "Tx RDMA In-Flight Table is full%llu.\n", rr->dms_key);
			pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
			return ret;
		}

		tx_tracker = hfi1_dms_impl_tx_tracker_new(dms, access, nbytes, tx_rift_index);

		_rift_assign(&dms->tx_rift, (union hfi1_dms_tracker *)tx_tracker, tx_rift_index);

	} else if (type == HFI1_DMS_MSG_TYPE_READ_REQUEST_EXPECTED) {

		tx_tracker = (struct hfi1_dms_tx_tracker *) _rift_lookup(&dms->tx_rift, rr->tx_rift_index);
	}

	DMS_BUG_ON(tx_tracker == NULL);

#if 0 // TODO - blocksome - check pinned pages
	u64 extent = tx_tracker->start_offset + offset + nbytes;
	unsigned int last_requested_page = (unsigned int)(extent / PAGE_SIZE) + (unsigned int)((extent & (PAGE_SIZE-1)) != 0);

	ret = hfi1_mem_region_pinned_check(tx_tracker->mr->hfi1_mr, 0, last_requested_page);
	if (ret < 0) {
		// pin the memory now; something like:
		//   hfi1_mem_region_pin_pages(tx_tracker->mr->hfi1_mr, 0, last_requested_page);
	}
#endif


	ret = _calculate_byte_offset_from_first_mr_page(dms, tx_tracker->access, rr->offset, &page_offset);
	if (ret < 0) {
		// bad read request range ... what now? tear down the rift entry? access window?
		return ret;
	}

	ret = hfi1_dms_impl_sdma_send(dms, tx_tracker->access->mr, page_offset, nbytes, dlid, rx_id, tid_info, tx_tracker->rift_index);
	if (ret == 0) {
		tx_tracker->payload_remaining -= nbytes; // TODO: decrement payload_remaining on sdma completion not send
		if (tx_tracker->payload_remaining == 0 && dms->counters.last_sdma_sent == 0) {
			dms->counters.last_sdma_sent = ktime_get();
		}
	}

	end = dms_rdtsc();
	dms->counters.handle_read_request += end - start;

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

int hfi1_dms_impl_handle_read_request_work(struct hfi1_dms *dms, struct hfi1_dms_work_item *item)
{
	static_assert(sizeof(union hfi1_dms_16b_header) <= sizeof(item->data));
	union hfi1_dms_16b_header *hdr = (union hfi1_dms_16b_header *)item->data;
	int ret = hfi1_dms_impl_handle_read_request(dms, hdr, HFI1_DMS_MSG_TYPE_READ_REQUEST);

	if (ret == -ENOMSG)
		ret = -EAGAIN;

	return ret;
}

int hfi1_dms_impl_handle_read_request_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	int ret = hfi1_dms_impl_handle_read_request(dms, hdr, HFI1_DMS_MSG_TYPE_READ_REQUEST);
	if (ret < 0) {
		return hfi1_dms_impl_queue_work_item(dms, (void*)hdr, sizeof(*hdr), hfi1_dms_impl_handle_read_request_work);
	}
	return 0;
}

int hfi1_dms_impl_handle_read_request_expected_work(struct hfi1_dms *dms, struct hfi1_dms_work_item *item)
{
	static_assert(sizeof(union hfi1_dms_16b_header) <= sizeof(item->data));
	union hfi1_dms_16b_header *hdr = (union hfi1_dms_16b_header *)item->data;
	int ret = hfi1_dms_impl_handle_read_request(dms, hdr, HFI1_DMS_MSG_TYPE_READ_REQUEST_EXPECTED);

	if (ret == -ENOMSG)
		ret = -EAGAIN;

	return ret;
}
int hfi1_dms_impl_handle_read_request_expected_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	int ret = hfi1_dms_impl_handle_read_request(dms, hdr, HFI1_DMS_MSG_TYPE_READ_REQUEST_EXPECTED);
	if (ret < 0) {
		return hfi1_dms_impl_queue_work_item(dms, (void*)hdr, sizeof(*hdr), hfi1_dms_impl_handle_read_request_expected_work);
	}
	return 0;
}

int hfi1_dms_impl_handle_read_request_small(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	enum hfi1_dms_msg_type msg_type;
	u64 dms_key;
	u64 offset;
	u16 size;
	u16 rx_rift_index;
	struct hfi1_dms_access * access;
	struct hfi1_dms_client_state *client;
	u64 byte_offset_from_first_mr_page;
	int ret;
	u64 data[2];
	u32 dlid;
	u64 nbytes;
	union hfi1_dms_proto_cmd_data_small cmd;
	union hfi1_dms_proto_pkt_read_request_small  * rr;

	dms_trace(dms_handle_read_request_small, dms, hdr);

	pr_debug("%s:%d:%s() ENTER: dms=%p, hdr=%p\n", __FILENAME__, __LINE__, __func__, dms, hdr);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(hdr == NULL);

	msg_type = hfi1_dms_impl_message_type_get(hdr);
	DMS_BUG_ON(msg_type != HFI1_DMS_MSG_TYPE_READ_REQUEST_SMALL);

	rr = (union hfi1_dms_proto_pkt_read_request_small *)hdr;

	size = rr->info.size;
	DMS_WARN_ON(size > 16);

	dms_key = rr->info.dms_key;
	offset = rr->info.offset;
	rx_rift_index = rr->info.rx_rift_index;

	access = hfi1_dms_access_lookup(dms, dms_key, &client);
	if (!client) {
		int ret = -ENOENT;
		dd_dev_err(dms->dd, "Client not found for dms_key %llu.\n", dms_key);
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
		return ret;
	}
	if (!access) {
		int ret = -ENOMSG;
		dd_dev_dbg(dms->dd, "Access not found for key %llu.\n", dms_key);
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
		return ret;
	}

	byte_offset_from_first_mr_page = 0;
	ret = _calculate_byte_offset_from_first_mr_page(dms, access, offset, &byte_offset_from_first_mr_page);
	if (ret < 0) {
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
		return ret;
	}
	if ((byte_offset_from_first_mr_page + size) > access->mr->hfi1_mr->rb.len) {
		dd_dev_err(dms->dd, "Invalid length from offset.\n");
		return -EINVAL;
	}

	dd_dev_dbg(dms->dd, "DMS: Received read request small for dms_key %llu, offset %llu, rx_rift_index: %hu, size: %hu, byte_offset_from_first_mr_page: %llu\n",
			   dms_key, offset, rx_rift_index, size, byte_offset_from_first_mr_page);

	nbytes = min((u16)sizeof(u64),size);
	data[0] = hfi1_dms_impl_slow_read_from_user(access->mr->hfi1_mr, byte_offset_from_first_mr_page, nbytes);
	if (size > sizeof(u64)) {
		byte_offset_from_first_mr_page += sizeof(u64);
		nbytes = size - sizeof(u64);
		data[1] = hfi1_dms_impl_slow_read_from_user(access->mr->hfi1_mr, byte_offset_from_first_mr_page, nbytes);
	}
	dd_dev_dbg(dms->dd, "DMS: Sending small with data: 0x%016llx 0x%016llx\n", data[0], data[1]);

	dlid = hfi1_dms_lrh16B_slid_get((u32 *) &hdr->lrh[0]);
	cmd = hfi1_dms_proto_cmd_data_small_make(dms, dlid, rx_rift_index, data[0], data[1]);

	// -1 here because the pbc is included in the pbc dw length
	u64 size_qw = (hfi1_dms_impl_pbc_length_dws_get(cmd.pbc) >> 1) - 1;
	ret = hfi1_dms_impl_pio_send(dms, cmd.pbc, &cmd.qws[1], size_qw);
	if (ret < 0) {
		ret = -EAGAIN;
		dd_dev_dbg(dms->dd, "Failed to pio send small read request response.\n");
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
		return ret;
	}

	hfi1_dms_impl_access_ref_inc(dms, access);
	access->completion.fn(&access->completion.cookie);
	hfi1_dms_impl_access_ref_dec(dms, access);

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0; // Success
}

int hfi1_dms_impl_handle_read_request_small_work(struct hfi1_dms *dms, struct hfi1_dms_work_item *item)
{
	static_assert(sizeof(union hfi1_dms_16b_header) <= sizeof(item->data));
	union hfi1_dms_16b_header *hdr = (union hfi1_dms_16b_header *)item->data;
	int ret = hfi1_dms_impl_handle_read_request_small(dms, hdr);

	if (ret == -ENOMSG)
		ret = -EAGAIN;

	return ret;
}

int hfi1_dms_impl_handle_read_request_small_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	int ret = hfi1_dms_impl_handle_read_request_small(dms, hdr);
	if (ret < 0) {
		return hfi1_dms_impl_queue_work_item(dms, (void*)hdr, sizeof(*hdr), hfi1_dms_impl_handle_read_request_small_work);
	}
	return 0;
}

int hfi1_dms_impl_handle_read_request_fixup(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	enum hfi1_dms_msg_type msg_type;
	union hfi1_dms_proto_pkt_read_request_fixup * rr;
	u64 dms_key;
	u64 offset;
	u32 size;
	u32 length_adjust;
	struct hfi1_dms_access * access;
	u64 head, tail;
	u32 dlid;
	u16 rx_rift_index;
	union hfi1_dms_proto_cmd_data_fixup cmd;
	struct hfi1_dms_client_state *client = NULL;

	dms_trace(dms_handle_read_request_fixup, dms, hdr);

	pr_debug("%s:%d:%s() ENTER: dms=%p, hdr=%p\n", __FILENAME__, __LINE__, __func__, dms, hdr);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(hdr == NULL);

	msg_type = hfi1_dms_impl_message_type_get(hdr);
	DMS_BUG_ON(msg_type != HFI1_DMS_MSG_TYPE_READ_REQUEST_FIXUP);

	rr = (union hfi1_dms_proto_pkt_read_request_fixup *)hdr;

	rx_rift_index = (u16) ((hdr->bth[2] >> 16) & 0xFFFF);
	dms_key = rr->info.dms_key;
	offset = rr->info.offset;
	size = rr->info.size;
	//pr_debug("%s:%d:%s() rx_rift_index=%hu, dms_key=0x%016llx, offset=0x%016llx, size=%u\n", __FILENAME__, __LINE__, __func__, rx_rift_index, dms_key, offset, size);
	// DMS_BUG_ON(size == 0);

	access = hfi1_dms_access_lookup(dms, dms_key, &client);
	if (!client) {
		int ret = -ENOENT;
		dd_dev_err(dms->dd, "Client not found for dms_key %llu.\n", dms_key);
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
		return ret;
	}
	if (!access) {
		int ret = -ENOMSG;
		dd_dev_dbg(dms->dd, "Access not found for key %llu.\n", dms_key);
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
		return ret;
	}

	u64 byte_offset_from_first_mr_page = 0;
	int ret = _calculate_byte_offset_from_first_mr_page(dms, access, offset, &byte_offset_from_first_mr_page);
	if (ret < 0) {
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
		return ret;
	}
	if ((byte_offset_from_first_mr_page + size) > access->mr->hfi1_mr->rb.len) {
		dd_dev_err(dms->dd, "Invalid length from offset.\n");
		return -EINVAL;
	}

	dd_dev_dbg(dms->dd, "DMS: Received read request fixup for dms_key %llu, offset %llu, rx_rift_index: %hu, size: %u, byte_offset_from_first_mr_page: %llu\n",
			   dms_key, offset, rx_rift_index, size, byte_offset_from_first_mr_page);

	if (size <= sizeof(u64)) {
		//head = hfi1_dms_impl_slow_read_from_user(access->mr->hfi1_mr, byte_offset_from_first_mr_page, size);
		//tail = head;
		ret = -EINVAL;
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
		return ret;

	} else {
		head = hfi1_dms_impl_slow_read_from_user(access->mr->hfi1_mr, byte_offset_from_first_mr_page, sizeof(u64));
		tail = hfi1_dms_impl_slow_read_from_user(access->mr->hfi1_mr, byte_offset_from_first_mr_page + size - sizeof(u64), sizeof(u64));
	}
	dd_dev_dbg(dms->dd, "DMS: Sending fixup with head: 0x%016llx, tail: 0x%016llx, length_adjust: %u\n", head, tail, length_adjust);

	dlid = hfi1_dms_lrh16B_slid_get((u32 *) &hdr->lrh[0]);
	cmd = hfi1_dms_proto_cmd_data_fixup_make(dms, dlid, rx_rift_index, head, tail);

	ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
	if (ret < 0) {
		dd_dev_dbg(dms->dd, "Failed to pio send fixup read request response.\n");
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
		return ret;
	}

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0; // Success
}

int hfi1_dms_impl_handle_read_request_fixup_work(struct hfi1_dms *dms, struct hfi1_dms_work_item *item)
{
	static_assert(sizeof(union hfi1_dms_16b_header) <= sizeof(item->data));
	union hfi1_dms_16b_header *hdr = (union hfi1_dms_16b_header *)item->data;
	int ret = hfi1_dms_impl_handle_read_request_fixup(dms, hdr);

	if (ret == -ENOMSG)
		ret = -EAGAIN;

	return ret;
}

int hfi1_dms_impl_handle_read_request_fixup_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	int ret = hfi1_dms_impl_handle_read_request_fixup(dms, hdr);
	if (ret < 0) {
		return hfi1_dms_impl_queue_work_item(dms, (void*)hdr, sizeof(*hdr), hfi1_dms_impl_handle_read_request_fixup_work);
	}
	return 0;
}

int hfi1_dms_impl_handle_read_request_ack(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	enum hfi1_dms_msg_type msg_type;
	union hfi1_dms_proto_pkt_read_request_ack * ack;
	struct hfi1_dms_tx_tracker *tx_tracker;

	pr_debug("%s:%d:%s() ENTER: dms=%p, hdr=%p\n", __FILENAME__, __LINE__, __func__, dms, hdr);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(hdr == NULL);

	msg_type = hfi1_dms_impl_message_type_get(hdr);
	DMS_BUG_ON(msg_type != HFI1_DMS_MSG_TYPE_READ_REQUEST_ACK);

	ack = (union hfi1_dms_proto_pkt_read_request_ack *)hdr;

	tx_tracker = (struct hfi1_dms_tx_tracker *) _rift_lookup(&dms->tx_rift, ack->info.tx_rift_index);
	DMS_BUG_ON(tx_tracker == NULL);

	dd_dev_dbg(dms->dd, "Received read request ACK with tx rift index: %hu, size: %llu\n", ack->info.tx_rift_index, ack->info.size);

	hfi1_dms_handle_tx_tracker_completion(dms, ack->info.tx_rift_index);

	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, 0);
	return 0; // Success
}

u32 hfi1_dms_impl_read_request_size_qw_get(union hfi1_dms_16b_header *hdr)
{
	u32 ret;

	pr_debug("%s:%d:%s() ENTER: hdr=%p\n", __FILENAME__, __LINE__, __func__, hdr);
	DMS_BUG_ON(hdr == NULL);
	ret = (u32) ((hdr->bth[2] >> 16) & 0xFFFF);
	pr_debug("%s:%d:%s() EXIT: ret=%u\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

void hfi1_dms_impl_lrh16bc_dlid_set(u64 *lrh16bc, u32 dlid)
{
	u64 newlrh;

	pr_debug("%s:%d:%s() ENTER: lrh16bc=%p, dlid=%u\n", __FILENAME__, __LINE__, __func__, lrh16bc, dlid);
	DMS_BUG_ON(lrh16bc == NULL);
	newlrh = (*lrh16bc & ~0xFFFFFFull) | (dlid & 0xFFFFFF);
	pr_debug("DMS: Setting DLID %u in LRH16BC. Prev= 0x%llx, New= 0x%llx\n", dlid, *lrh16bc, newlrh);

	*lrh16bc = newlrh;
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

void hfi1_dms_impl_lrh16bc_len_qws_set(u64 *lrh16bc, u32 len_qws)
{
	pr_debug("%s:%d:%s() ENTER: lrh16bc=%p, len_qws=%u\n", __FILENAME__, __LINE__, __func__, lrh16bc, len_qws);
	DMS_BUG_ON(lrh16bc == NULL);

	// Set the length in QWs in the LRH16BC
	*lrh16bc = (*lrh16bc & ~(HFI1_DMS_LRH16BC_LEN_QW_MASK << HFI1_DMS_LRH16BC_LEN_QW_SHIFT)) | (
		((u64) (len_qws & HFI1_DMS_LRH16BC_LEN_QW_MASK) << HFI1_DMS_LRH16BC_LEN_QW_SHIFT));
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

void hfi1_dms_impl_pbc_dlid_set(u64 *pbc, u32 dlid)
{
	pr_debug("%s:%d:%s() ENTER: pbc=%p, dlid=%u\n", __FILENAME__, __LINE__, __func__, pbc, dlid);
	DMS_BUG_ON(pbc == NULL);

	// Set the DLID in the PBC
	*pbc = (*pbc & ~(((u64) PBC_DLID_MASK << PBC_DLID_SHIFT))) |
	       ((u64) (dlid & PBC_DLID_MASK) << PBC_DLID_SHIFT);
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

void hfi1_dms_impl_pbc_length_dws_set(u64 *pbc, u32 length_dws)
{
	pr_debug("%s:%d:%s() ENTER: pbc=%p, length_dws=%u\n", __FILENAME__, __LINE__, __func__, pbc, length_dws);
	DMS_BUG_ON(pbc == NULL);

	// Set the length in DWords in the PBC
	*pbc = (*pbc & ~(((u64) PBC_LENGTH_DWS_MASK << PBC_LENGTH_DWS_SHIFT))) |
	       ((u64) (length_dws & PBC_LENGTH_DWS_MASK) << PBC_LENGTH_DWS_SHIFT);
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

u64 hfi1_dms_impl_pbc_length_dws_get(u64 pbc)
{
	return (pbc >> PBC_LENGTH_DWS_SHIFT) & PBC_LENGTH_DWS_MASK;
}

/*
	return the 16bc size including PBC in DWs of the data
	packet type we send given the current payload size
*/
static u32 hfi1_dms_impl_data_pktlen_dws_from_payload_dws(u32 payload_dws)
{
	u32 ret;

	pr_debug("%s:%d:%s() ENTER: payload_dws=%u\n", __FILENAME__, __LINE__, __func__, payload_dws);
	// 64 byte 16B compressed header (with PBC) + payload + 2 dws for 16B tail flit
	ret = 16 + payload_dws + 2;
	pr_debug("%s:%d:%s() EXIT: ret=%u\n", __FILENAME__, __LINE__, __func__, ret);
	return ret;
}

void hfi1_dms_impl_data_packet_header_make(struct hfi1_dms *dms, union hfi1_dms_proto_cmd *cmd, u32 nbytes, u32 dlid, u8 rx, u32 tid_info, u16 tx_rift_index)
{
	u32 payload_dws;
	u32 pbc_pktlen_dws;
	u32 pktlen_qws;
	union hfi1_dms_proto_cmd_data *data_template;
	u64 cmd_data_qw_size;
	u64 i;
	union hfi1_dms_proto_cmd_data * cmd_data;

	pr_debug("%s:%d:%s() ENTER: dms=%p, cmd=%p, nbytes=%u, dlid=%u, rx=%u, tid_info=0x%x, tx_rift_index=%hu\n",
		   __FILENAME__, __LINE__, __func__, dms, cmd, nbytes, dlid, rx, tid_info, tx_rift_index);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(cmd == NULL);

	payload_dws = (nbytes + 3) >> 2;
	pbc_pktlen_dws = hfi1_dms_impl_data_pktlen_dws_from_payload_dws(payload_dws);
	pktlen_qws = pbc_pktlen_dws >> 1;

	data_template = (union hfi1_dms_proto_cmd_data *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA];
	cmd_data_qw_size = sizeof(union hfi1_dms_proto_cmd_data) >> 3;
	for (i = 0; i < cmd_data_qw_size; ++i) {
		cmd->qws[i] = data_template->qws[i];
	}
	hfi1_dms_impl_lrh16bc_dlid_set(&cmd->lrh16bc, dlid);
	hfi1_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc, pktlen_qws);

	cmd->kdeth[0] = tid_info;
	cmd_data = (union hfi1_dms_proto_cmd_data *)cmd;
	cmd_data->info.tx_rift_index = tx_rift_index;
	dd_dev_dbg(dms->dd, "Setting rx in bth - rx=%u, bth[1]=0x%08x\n", rx, cmd->bth[1]);
	cmd->bth[1] = (cmd->bth[1] & ~(0xffu << 24)) | (rx << 24); // Set RX QP prefix
	hfi1_dms_impl_pbc_dlid_set(&cmd->pbc, dlid);
	hfi1_dms_impl_pbc_length_dws_set(&cmd->pbc, pbc_pktlen_dws);
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

/**
 * We might be able to tweak this usage but it's an easy way to track
 * the different counters we have to track
 */
struct hfi1_dms_impl_fill_state {
	struct sdma_desc *cur_desc;
	dma_addr_t *phys_addrs;
	u64 page_offset;
};

/**
 * Helper function for filling in descriptors that are _just_ the payload of the message
 * 
 * this is not quite right, something's up here with the phys page offset
 */
struct hfi1_dms_impl_fill_state hfi1_dms_impl_fill_payload(struct sdma_desc *start_desc, u64 nbytes, u64 sbuf_page_offset, dma_addr_t *phys_addrs)
{
	u64 PHYS_PAGE_SIZE = PAGE_SIZE;
	u64 offset;
	struct sdma_desc *desc;
	u64 chunk_align_bytes;
	u64 page_idx;
	dma_addr_t phys_addr;
	u64 bytes_until_page_end;
	u64 nbytes_256_chunks;
	u64 page_align_bytes;
	u64 page_count;
	u64 i;
	u64 phy_addr;
	u64 chunk_tail_bytes;
	u64 tail_bytes;

	pr_debug("%s:%d:%s() ENTER: start_desc=%p, nbytes=%llu, sbuf_page_offset=%llu, phys_addrs=%p\n",
		   __FILENAME__, __LINE__, __func__, start_desc, nbytes, sbuf_page_offset, phys_addrs);
	DMS_BUG_ON(start_desc == NULL);
	DMS_BUG_ON(phys_addrs == NULL);
	DMS_BUG_ON((PHYS_PAGE_SIZE & (PHYS_PAGE_SIZE - 1)) != 0);
	DMS_BUG_ON(nbytes > HFI1_DMS_MAX_PAYLOAD_SIZE);

	offset = sbuf_page_offset;
	desc = start_desc;

	pr_debug("Filling payload descriptors with nbytes %llu, offset %llu\n", nbytes, offset);

	chunk_align_bytes = min((HFI1_DMS_PAYLOAD_CHUNK_SIZE - (offset & (HFI1_DMS_PAYLOAD_CHUNK_SIZE - 1))) & (HFI1_DMS_PAYLOAD_CHUNK_SIZE - 1), nbytes);
	if (chunk_align_bytes > 0) {
		page_idx = offset / PHYS_PAGE_SIZE;
		phys_addr = phys_addrs[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
		*desc = (struct sdma_desc){0};
		jkr_sdma_qw_set_byte_count(&desc->qw[0], chunk_align_bytes);
		jkr_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
		desc += 1;

		offset += chunk_align_bytes;
		nbytes -= chunk_align_bytes;
	}

	// fill 256 chunks until end of current page (if 4096 page) or end of 256 chunks in this page
	bytes_until_page_end = (PHYS_PAGE_SIZE - (offset & (PHYS_PAGE_SIZE - 1))) & (PHYS_PAGE_SIZE - 1);
	nbytes_256_chunks = nbytes & ~(HFI1_DMS_PAYLOAD_CHUNK_SIZE - 1);
	page_align_bytes = min(bytes_until_page_end, nbytes_256_chunks);
	DMS_BUG_ON((page_align_bytes & (HFI1_DMS_PAYLOAD_CHUNK_SIZE - 1)) != 0);
	if (page_align_bytes > 0) {
		page_idx = offset / PHYS_PAGE_SIZE;
		phys_addr = phys_addrs[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
		*desc = (struct sdma_desc){0};
		jkr_sdma_qw_set_byte_count(&desc->qw[0], page_align_bytes);
		jkr_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
		desc += 1;

		offset += page_align_bytes;
		nbytes -= page_align_bytes;
	}

	// in reality this should be MAX 1, but it could be 0 if we are
	// given a huge page
	page_count = nbytes / PHYS_PAGE_SIZE;
	for (i = 0; i < page_count; ++i) {
		DMS_BUG_ON((offset & (HFI1_DMS_PAYLOAD_CHUNK_SIZE - 1)) != 0);
		page_idx = offset / PHYS_PAGE_SIZE;
		phy_addr = phys_addrs[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
		*desc = (struct sdma_desc){0};
		jkr_sdma_qw_set_byte_count(&desc->qw[0], PHYS_PAGE_SIZE);
		jkr_sdma_qw_set_phy_addr(&desc->qw[0], phy_addr);
		desc += 1;

		offset += PHYS_PAGE_SIZE;
		nbytes -= PHYS_PAGE_SIZE;
	}

	// tail chunks
	chunk_tail_bytes = nbytes & ~(HFI1_DMS_PAYLOAD_CHUNK_SIZE - 1);
	if (chunk_tail_bytes > 0) {
		page_idx = offset / PHYS_PAGE_SIZE;
		phys_addr = phys_addrs[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
		*desc = (struct sdma_desc){0};
		jkr_sdma_qw_set_byte_count(&desc->qw[0], chunk_tail_bytes);
		jkr_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
		desc += 1;

		offset += chunk_tail_bytes;
		nbytes -= chunk_tail_bytes;
	}

	// finally, tail bytes
	tail_bytes = nbytes & (HFI1_DMS_PAYLOAD_CHUNK_SIZE - 1);
	if (tail_bytes > 0) {
		page_idx = offset / PHYS_PAGE_SIZE;
		phys_addr = phys_addrs[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
		*desc = (struct sdma_desc){0};
		jkr_sdma_qw_set_byte_count(&desc->qw[0], tail_bytes);
		jkr_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
		desc += 1;

		offset += tail_bytes;
		nbytes -= tail_bytes;
	}

	DMS_BUG_ON(nbytes != 0); // We should have consumed all bytes

	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
	return (struct hfi1_dms_impl_fill_state){
		.cur_desc = desc,
		.phys_addrs = phys_addrs,
		.page_offset = offset, // This is the total offset we filled
	};
}

/**
 * Helper function for `hfi1_dms_impl_sdma_send` - do not call directly
 * 
 * nbytes should be calculated ahead of time such that (nbytes + tid_info.offset * 4) <= MTU_SIZE
 * 
 */
struct hfi1_dms_impl_fill_state hfi1_dms_impl_fill_first_packet_descriptors(struct hfi1_dms *dms, struct hfi1_dms_impl_fill_state initial_fill_state, u16 tx_rift_index, u32 nbytes, u32 dlid, u8 rx, u32 tid_info, u8 ahg_idx, struct hfi1_dms_ahg_header **out_ahg_mem)
{
	u64 start;
	struct sdma_desc *desc;
	struct hfi1_dms_impl_fill_state fill_state;
	struct hfi1_dms_ahg_header *ahg_mem;
	union hfi1_dms_proto_cmd *data_header;
	u64 HEADER_SIZE = 64;
	phys_addr_t phys_addr;
	u64 end;

	pr_debug("%s:%d:%s() ENTER: dms=%p, initial_fill_state.cur_desc=%p, tx_rift_index=%hu, nbytes=%u, dlid=%u, rx=%u, tid_info=0x%x, ahg_idx=%u, out_ahg_mem=%p\n",
		   __FILENAME__, __LINE__, __func__, dms, initial_fill_state.cur_desc, tx_rift_index, nbytes, dlid, rx, tid_info, ahg_idx, out_ahg_mem);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(initial_fill_state.cur_desc == NULL);
	DMS_BUG_ON(initial_fill_state.phys_addrs == NULL);
	DMS_BUG_ON(nbytes == 0);
	DMS_BUG_ON((nbytes & 0x7) != 0);
	DMS_BUG_ON(dlid == 0);
	DMS_BUG_ON(out_ahg_mem == NULL);
	start = dms_rdtsc();

	// Fill the first packet descriptor
	desc = initial_fill_state.cur_desc;
	fill_state = initial_fill_state;
	ahg_mem = hfi1_dms_impl_ahg_header_get(dms);
	if (DMS_WARN_ON(ahg_mem == NULL)) {
		pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
		return (struct hfi1_dms_impl_fill_state){0}; // Failed to get AHG memory tracker
	}

	data_header = (union hfi1_dms_proto_cmd *) ahg_mem->mem_coh.kvaddr;
	hfi1_dms_impl_data_packet_header_make(dms, data_header, nbytes, dlid, rx, tid_info, tx_rift_index);


	*desc = (struct sdma_desc){0};
	phys_addr = ahg_mem->mem_coh.phys_addr;
	jkr_sdma_qw_set_byte_count(&desc->qw[0], HEADER_SIZE);
	jkr_sdma_qw_set_first_desc(&desc->qw[0]);
	jkr_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
	jkr_sdma_qw_set_header_mode(&desc->qw[0], SDMA_AHG_NO_AHG);

	desc += 1;

	fill_state = hfi1_dms_impl_fill_payload(desc, nbytes, fill_state.page_offset, fill_state.phys_addrs);

	*fill_state.cur_desc = (struct sdma_desc) {0};
	jkr_sdma_qw_set_byte_count(&fill_state.cur_desc->qw[0], sizeof(u64));
	jkr_sdma_qw_set_phy_addr(&fill_state.cur_desc->qw[0], dms->zero_page.phys_addr);
	jkr_sdma_qw_set_last_desc(&fill_state.cur_desc->qw[0]);

	fill_state.cur_desc += 1;
	*out_ahg_mem = ahg_mem;
	end = dms_rdtsc();
	dms->counters.first_packet_send += end - start;

	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
	return fill_state; // Success
}

struct hfi1_dms_impl_fill_state hfi1_dms_impl_fill_payload_ahg(struct sdma_desc *start_desc, u64 nbytes, u64 sbuf_page_offset, dma_addr_t *phys_addrs, u8 ahg_idx, u32 update_with_desc, struct sdma_desc *header_udpate_descs, s32 num_header_update_descs)
{
	struct sdma_desc *cur_desc;
	struct hfi1_dms_impl_fill_state fill_state;
	u64 i;

	pr_debug("%s:%d:%s() ENTER: start_desc=%p, nbytes=%llu, sbuf_page_offset=%llu, phys_addrs=%p, ahg_idx=%u, update_with_desc=0x%x, num_header_update_descs=%d\n",
		   __FILENAME__, __LINE__, __func__, start_desc, nbytes, sbuf_page_offset, phys_addrs, ahg_idx, update_with_desc, num_header_update_descs);
	cur_desc = start_desc;
	start_desc += num_header_update_descs;
	fill_state = hfi1_dms_impl_fill_payload(start_desc, nbytes, sbuf_page_offset, phys_addrs);
	*cur_desc = *start_desc;
	jkr_sdma_qw_set_header_mode(&cur_desc->qw[0], SDMA_AHG_APPLY_UPDATE2);
	jkr_sdma_qw_set_header_index(&cur_desc->qw[0], ahg_idx);
	jkr_sdma_qw_set_header_dws(&cur_desc->qw[0], 0); // 64 bytes
	jkr_sdma_qw_set_first_desc(&cur_desc->qw[0]);
	cur_desc->qw[1] = (cur_desc->qw[1] & ~((u64) (U32_MAX) << 32)) | ((u64) update_with_desc) << 32;
	cur_desc += 1;
	for (i = 0; i < num_header_update_descs; ++i) {
		cur_desc[i] = header_udpate_descs[i];
	}

	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
	return fill_state;
}

/**
 * Helper function for `hfi1_dms_impl_sdma_send` - do not call directly
 * 
 * nbytes should be calculated ahead of time such that (nbytes + tid_info.offset * 4) <= MTU_SIZE
 * 
 */
struct hfi1_dms_impl_fill_state hfi1_dms_impl_fill_next_packet_descriptors(struct hfi1_dms *dms, struct hfi1_dms_impl_fill_state initial_fill_state, u16 tid_start, u32 nbytes, u8 ahg_idx)
{
	u64 start;
	u32 const TID_OFFSET = 7;
	u32 const TID_BIT_OFFSET = 16;
	u32 const TID_OFFSET_BIT_OFFSET = 0;
	u32 const PBC_PKTLEN_OFFSET = 0;
	u32 const PBC_PKTLEN_BIT_OFFSET = 0;
	u32 const LRH_LEN_OFFSET = 3;
	u32 const LRH_LEN_BIT_OFFSET = 16;
	u32 const MSG_TYPE_OFFSET = 4;
	u32 const MSG_TYPE_BIT_OFFSET = 16;
	u32 nbytes_dw;
	u32 pbc_pktlen_dws;
	struct hfi1_dms_impl_fill_state fill_state;
	u32 ahg_update_with;
	u32 ahg_updates[4];
	u64 end;

	pr_debug("%s:%d:%s() ENTER: dms=%p, initial_fill_state.cur_desc=%p, tid_start=%u, nbytes=%u, ahg_idx=%u, \n",
		   __FILENAME__, __LINE__, __func__, dms, initial_fill_state.cur_desc, tid_start, nbytes, ahg_idx);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(initial_fill_state.cur_desc == NULL);
	DMS_BUG_ON(initial_fill_state.phys_addrs == NULL);
	DMS_BUG_ON(nbytes == 0);
	DMS_BUG_ON((nbytes & 0x7) != 0);

	start = dms_rdtsc();

	nbytes_dw = (nbytes + 3) >> 2;
	pbc_pktlen_dws = hfi1_dms_impl_data_pktlen_dws_from_payload_dws(nbytes_dw);

	fill_state = initial_fill_state;

	ahg_update_with = sdma_build_ahg_descriptor(tid_start, TID_OFFSET, TID_BIT_OFFSET, 10);
	ahg_updates[0] = sdma_build_ahg_descriptor(pbc_pktlen_dws, PBC_PKTLEN_OFFSET, PBC_PKTLEN_BIT_OFFSET, 16);
	ahg_updates[1] = sdma_build_ahg_descriptor(pbc_pktlen_dws >> 1, LRH_LEN_OFFSET, LRH_LEN_BIT_OFFSET, 16);
	ahg_updates[2] = sdma_build_ahg_descriptor(HFI1_DMS_MSG_TYPE_DATA, MSG_TYPE_OFFSET, MSG_TYPE_BIT_OFFSET, 8);
	ahg_updates[3] = sdma_build_ahg_descriptor(0, TID_OFFSET, TID_OFFSET_BIT_OFFSET, 15);

	fill_state = hfi1_dms_impl_fill_payload_ahg(fill_state.cur_desc, nbytes, fill_state.page_offset, fill_state.phys_addrs, ahg_idx, ahg_update_with, (struct sdma_desc *) ahg_updates, 1);

	*fill_state.cur_desc = (struct sdma_desc){0};
	jkr_sdma_qw_set_byte_count(&fill_state.cur_desc->qw[0], sizeof(u64));
	jkr_sdma_qw_set_phy_addr(&fill_state.cur_desc->qw[0], dms->zero_page.phys_addr);
	jkr_sdma_qw_set_last_desc(&fill_state.cur_desc->qw[0]);
	fill_state.cur_desc += 1;

	end = dms_rdtsc();

	dms->counters.next_packet_send += end - start;

	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
	return fill_state; // Success
}

int hfi1_dms_impl_sdma_send(struct hfi1_dms *dms, struct hfi1_dms_mr * mr, u64 page_offset, u32 nbytes, u32 dlid, u8 rx_id, u32 tid_info, u16 tx_rift_index)
{
	u64 start;
	u32 tid_offset;
	u32 tid;
	u64 bytes_first_packet;
	u64 num_full_mtu_packets;
	u64 bytes_last_packet;
	u8 ahg_idx = 0;
	struct sdma_desc *cur_desc;
	struct hfi1_dms_impl_fill_state current_fill_state;
	u64 i;
	struct sdma_desc *last_desc;
	u64 ndesc_filled;
	u64 ndesc_unused;
	struct sdma_desc *tail;
	u64 ndesc_total;
	s32 cur_sdma_engine;
	s32 sdma_engine_count;
	s32 num_sdma_engines;
	struct sdma_engine *sdma;
	u32 desc_tail;
	u32 descq_cnt;
	struct sdma_desc *desc;
	struct hfi1_dms_sde_rsrc *sdma_rsrc;
	s32 nahg_mem = 0;
	u64 end;

	dms_trace(dms_sdma_send, dms, mr);

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(mr == NULL);

	start = dms_rdtsc();

	tid_offset = (tid_info & 0x7fff) << 2;
	tid = (tid_info >> 16) & 0x3ff;

	bytes_first_packet = min(nbytes, (u32) HFI1_DMS_MAX_PAYLOAD_SIZE - tid_offset);
	num_full_mtu_packets = (nbytes - bytes_first_packet) / HFI1_DMS_MAX_PAYLOAD_SIZE;
	bytes_last_packet = nbytes - (num_full_mtu_packets * HFI1_DMS_MAX_PAYLOAD_SIZE) - bytes_first_packet;

	cur_desc = &dms->desc_stack[0];


	current_fill_state = (struct hfi1_dms_impl_fill_state){
		.cur_desc = cur_desc,
		.phys_addrs = mr->hfi1_mr->dma_list,
		.page_offset = page_offset,
	};

	current_fill_state = hfi1_dms_impl_fill_first_packet_descriptors(dms, current_fill_state, tx_rift_index, bytes_first_packet, dlid, rx_id, tid_info, ahg_idx, &dms->ahg_header_stack[nahg_mem]);
	tid += 1;
	nahg_mem += 1;
	tid_info = hfi1_dms_tid_info_update_tid(tid_info, tid);
	// clear tid_offset for the rest of the packets
	tid_info &= ~0x7fff;

	for (i = 0; i < num_full_mtu_packets; ++i) {
		// Fill the next MTU packet
		u64 bytes_to_fill = HFI1_DMS_MAX_PAYLOAD_SIZE;
		current_fill_state = hfi1_dms_impl_fill_first_packet_descriptors(dms, current_fill_state, tx_rift_index, bytes_to_fill, dlid, rx_id, tid_info, ahg_idx, &dms->ahg_header_stack[nahg_mem]);
		nahg_mem += 1;
		tid += 1;
		tid_info = hfi1_dms_tid_info_update_tid(tid_info, tid);
	}

	if (bytes_last_packet > 0) {
		current_fill_state = hfi1_dms_impl_fill_first_packet_descriptors(dms, current_fill_state, tx_rift_index, bytes_last_packet, dlid, rx_id, tid_info, ahg_idx, &dms->ahg_header_stack[nahg_mem]);
		nahg_mem += 1;
		tid += 1;
		tid_info = hfi1_dms_tid_info_update_tid(tid_info, tid);
	}

	last_desc = current_fill_state.cur_desc - 1;
	ndesc_filled = (u64) (current_fill_state.cur_desc - dms->desc_stack);
	ndesc_unused = (HFI1_DMS_DESC_CHUNK_SIZE - (ndesc_filled & (HFI1_DMS_DESC_CHUNK_SIZE-1))) & (HFI1_DMS_DESC_CHUNK_SIZE-1);
	tail = last_desc + ndesc_unused;
	*tail = *last_desc;
	jkr_sdma_qw_set_head_to_host(&tail->qw[0]);
	// jkr_sdma_qw_set_int_req(&tail->qw[0]);
	for (i = 0; i < ndesc_unused; ++i) {
		*last_desc = (struct sdma_desc){0};
		last_desc = last_desc + 1;
	}
	if (last_desc != tail) {
		dd_dev_dbg(dms->dd, "dms: Last descriptor %p is not the tail %p, something is wrong.\n", last_desc, tail);
	}

	current_fill_state.cur_desc = last_desc + 1;
	ndesc_total = (u64) (current_fill_state.cur_desc - dms->desc_stack);
	if ((ndesc_total & (HFI1_DMS_DESC_CHUNK_SIZE - 1)) != 0) {
		dd_dev_warn(dms->dd, "dms: Descriptor count %llu is not a multiple of %u, some bug in descriptor padding.\n", ndesc_total, HFI1_DMS_DESC_CHUNK_SIZE);
	}

	cur_sdma_engine = dms->cur_sdma_engine;
	sdma_engine_count = dms->num_engines;
	num_sdma_engines = dms->num_engines;
	sdma = dms->sdma_engines[cur_sdma_engine];

	while ((--sdma_engine_count >= 0) && (sdma_descq_freecnt(sdma) < ndesc_total)) {
		cur_sdma_engine = (cur_sdma_engine + 1) % num_sdma_engines;
		sdma = dms->sdma_engines[cur_sdma_engine];
	}
	dms->cur_sdma_engine = cur_sdma_engine;
	if (sdma_engine_count < 0) {
		// check once more now that we have read all the head values
		sdma_engine_count = num_sdma_engines;
		while ((--sdma_engine_count >= 0)) {
			sdma_gethead_dma(sdma);
			if (sdma_descq_freecnt(sdma) >= ndesc_total) {
				break;
			}
			cur_sdma_engine = (cur_sdma_engine + 1) % num_sdma_engines;
			sdma = dms->sdma_engines[cur_sdma_engine];
		}
		dms->cur_sdma_engine = cur_sdma_engine;	
	}
	if (sdma_engine_count < 0) {
		dd_dev_warn(dms->dd, "dms: No sdma engine available. Tracker will be put back on the todo list\n");
		for (i = 0; i < nahg_mem; ++i) {
			struct hfi1_dms_ahg_header *ahg_mem = dms->ahg_header_stack[i];
			hfi1_dms_impl_dlist_append(&dms->ahg_headers.free, &ahg_mem->dlist);
		}
		return -1; // TODO: this should not be an error but we don't have a "todo" list
	}

	// write all descriptors into the descriptor queue
	desc_tail = sdma->descq_tail;
	descq_cnt = sdma->descq_cnt;

	for (i = 0; i < ndesc_total; ++i) {
		desc = &dms->desc_stack[i];
		sdma->descq[desc_tail].qw[0] = desc->qw[0];
		sdma->descq[desc_tail].qw[1] = desc->qw[1];
		desc_tail += 1;
		if (desc_tail == descq_cnt) {
			desc_tail = 0;
		}
	}

	sdma->descq_tail = desc_tail;
	smp_wmb();
	writeq(sdma->descq_tail, sdma->tail_csr);
	sdma_rsrc = &dms->sde_rsrcs[cur_sdma_engine];
	for (i = 0; i < nahg_mem; ++i) {
		struct hfi1_dms_ahg_header *ahg_mem = dms->ahg_header_stack[i];
		ahg_mem->desc_idx = desc_tail;
		hfi1_dms_impl_dlist_append(&sdma_rsrc->active_ahg_headers, &ahg_mem->dlist);
	}
	dd_dev_dbg(dms->dd, "dms: Sent sdma descs %llu on engine %d, new tail/ahg desc idx %u\n", ndesc_total, cur_sdma_engine, desc_tail);

	dms->cur_sdma_engine = (dms->cur_sdma_engine + 1) % dms->num_engines;

	end = dms_rdtsc();
	dms->counters.tid_send += end - start;
	return 0;
}

int hfi1_dms_impl_work_item_block_alloc(struct hfi1_dms *dms)
{
	size_t sz = sizeof(struct hfi1_dms_dlist_element) + 100 * sizeof(struct hfi1_dms_work_item);
	struct hfi1_dms_dlist_element *block;
	struct hfi1_dms_dlist_element *item;
	size_t i;

	block = (struct hfi1_dms_dlist_element *)kzalloc(sz, GFP_KERNEL);
	if (block == NULL) {
		return -1;
	}

	hfi1_dms_impl_dlist_push(&dms->work_items.blocklist, block);

	item = block + 1;
	for (i = 0; i < 100; ++i) {
		hfi1_dms_impl_dlist_push(&dms->work_items.free, item);
		item = (struct hfi1_dms_dlist_element *)((u64)item + sizeof(struct hfi1_dms_work_item));
	}

	return 0;
}

int hfi1_dms_impl_tracker_block_alloc(size_t elemsz, struct hfi1_dms_tracker_mgr *trackers)
{
	size_t sz = sizeof(struct hfi1_dms_dlist_element) + 100 * elemsz;
	struct hfi1_dms_dlist_element * block;
	struct hfi1_dms_dlist_element * tracker;
	size_t i;

	block = (struct hfi1_dms_dlist_element *) kzalloc(sz, GFP_KERNEL);
	if (block == NULL) {
		return -1;
	}

	hfi1_dms_impl_dlist_push(&trackers->blocklist, block);

	tracker = block + 1;
	for (i = 0; i < 100; ++i) {
		hfi1_dms_impl_dlist_push(&trackers->free, tracker);
		tracker = (struct hfi1_dms_dlist_element *)((u64) tracker + elemsz);
	}

	return 0;
}
int hfi1_dms_impl_rx_tracker_block_alloc(struct hfi1_dms *dms)
{
	int ret;

	ret = hfi1_dms_impl_tracker_block_alloc(sizeof(struct hfi1_dms_rx_tracker), &dms->rx_trackers);
	return ret;
}
int hfi1_dms_impl_tx_tracker_block_alloc(struct hfi1_dms *dms)
{
	int ret;

	ret = hfi1_dms_impl_tracker_block_alloc(sizeof(struct hfi1_dms_tx_tracker), &dms->tx_trackers);
	return ret;
}
int hfi1_dms_impl_ahg_header_block_alloc(struct hfi1_dms *dms)
{
	u64 const AHG_BACKING_ALLOC_SIZE = HFI1_DMS_AHG_HEADER_BLOCK_SIZE * sizeof(union hfi1_dms_proto_cmd);
	struct hfi1_dms_dlist_element *block;
	struct hfi1_dms_ahg_header_block *ahg_block;
	u64 i;
	struct hfi1_dms_mem_coh ahg_memory;
	struct hfi1_dms_ahg_header *tracker;

	block = (struct hfi1_dms_dlist_element *) kzalloc(sizeof(struct hfi1_dms_ahg_header_block), GFP_KERNEL);
	if (block == NULL) {
		return -ENOMEM;
	}
	hfi1_dms_impl_dlist_push(&dms->ahg_headers.blocklist, block);
	ahg_block = (struct hfi1_dms_ahg_header_block *) block;
	ahg_block->backing_mem.kvaddr = dma_alloc_coherent(&dms->dd->pcidev->dev, AHG_BACKING_ALLOC_SIZE, &ahg_block->backing_mem.phys_addr, GFP_DMA);
	ahg_block->backing_mem.len = AHG_BACKING_ALLOC_SIZE;
	if (!ahg_block->backing_mem.kvaddr) {
		kfree(block);
		return -ENOMEM;
	}

	for (i = 0; i < HFI1_DMS_AHG_HEADER_BLOCK_SIZE; ++i) {
		ahg_memory = (struct hfi1_dms_mem_coh){
			.kvaddr = ahg_block->backing_mem.kvaddr + (i * sizeof(union hfi1_dms_proto_cmd)),
			.phys_addr = ahg_block->backing_mem.phys_addr + (i * sizeof(union hfi1_dms_proto_cmd)),
			.len = sizeof(union hfi1_dms_proto_cmd),
		};
		tracker = &ahg_block->headers[i];
		tracker->mem_coh = ahg_memory;
		hfi1_dms_impl_dlist_push(&dms->ahg_headers.free, &tracker->dlist);
	}

	return 0;
}

void hfi1_dms_impl_work_item_block_free(struct hfi1_dms *dms)
{
	struct hfi1_dms_dlist_element *block;

	DMS_BUG_ON(dms == NULL);
	DMS_WARN_ON(dms->work_items.active.head != NULL || dms->work_items.active.tail != NULL);

	block = hfi1_dms_impl_dlist_pop(&dms->work_items.blocklist);
	while (block) {
		kfree(block);
		block = hfi1_dms_impl_dlist_pop(&dms->work_items.blocklist);
	}

	DMS_BUG_ON(dms->work_items.blocklist.head != NULL);
	DMS_BUG_ON(dms->work_items.blocklist.tail != NULL);

	dms->work_items.free.head = NULL;
	dms->work_items.free.tail = NULL;
}

void hfi1_dms_impl_tracker_block_free(struct hfi1_dms *dms, struct hfi1_dms_tracker_mgr *trackers)
{
	struct hfi1_dms_dlist_element * block;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(trackers == NULL);
	DMS_WARN_ON(trackers->active.head != NULL || trackers->active.tail != NULL);

	block = hfi1_dms_impl_dlist_pop(&trackers->blocklist);
	while (block) {
		kfree(block);
		block = hfi1_dms_impl_dlist_pop(&trackers->blocklist);
	}

	DMS_BUG_ON(trackers->blocklist.head != NULL);
	DMS_BUG_ON(trackers->blocklist.tail != NULL);

	trackers->free.head = NULL;
	trackers->free.tail = NULL;
}
void hfi1_dms_impl_rx_tracker_block_free(struct hfi1_dms *dms)
{
	hfi1_dms_impl_tracker_block_free(dms, &dms->rx_trackers);
}
void hfi1_dms_impl_tx_tracker_block_free(struct hfi1_dms *dms)
{
	hfi1_dms_impl_tracker_block_free(dms, &dms->tx_trackers);
}
void hfi1_dms_impl_ahg_header_block_free(struct hfi1_dms *dms)
{
	struct hfi1_dms_ahg_header_block *block;

	while (dms->ahg_headers.blocklist.head != NULL) {
		block = (struct hfi1_dms_ahg_header_block *) hfi1_dms_impl_dlist_pop(&dms->ahg_headers.blocklist);
		if (!DMS_WARN_ON(block->backing_mem.kvaddr == NULL)) {
			dma_free_coherent(&dms->dd->pcidev->dev, block->backing_mem.len, block->backing_mem.kvaddr, block->backing_mem.phys_addr);
			block->backing_mem.kvaddr = NULL;
			block->backing_mem.phys_addr = 0;
			block->backing_mem.len = 0;
		}
		kfree(block);
	}
}

struct hfi1_dms_work_item *hfi1_dms_impl_work_item_new(struct hfi1_dms *dms)
{
	struct hfi1_dms_dlist_element *item;

	item = hfi1_dms_impl_dlist_pop(&dms->work_items.free);
	if (item == NULL) {
		hfi1_dms_impl_work_item_block_alloc(dms);
		item = hfi1_dms_impl_dlist_pop(&dms->work_items.free);
	}
	if (!item) {
		return NULL;
	}

	/* add this item to the 'active' list */
	hfi1_dms_impl_dlist_append(&dms->work_items.active, item);

	return (struct hfi1_dms_work_item *)item;
}

void hfi1_dms_impl_work_item_free(struct hfi1_dms *dms, struct hfi1_dms_work_item *item)
{
	hfi1_dms_impl_dlist_remove(&dms->work_items.active, &item->dlist);
	hfi1_dms_impl_dlist_push(&dms->work_items.free, &item->dlist);
}

struct hfi1_dms_dlist_element * hfi1_dms_impl_tracker_new(struct hfi1_dms_tracker_mgr *trackers, size_t elemsz)
{
	struct hfi1_dms_dlist_element * tracker;

	tracker = hfi1_dms_impl_dlist_pop(&trackers->free);
	if (tracker == NULL) {
		hfi1_dms_impl_tracker_block_alloc(elemsz, trackers);
		tracker = hfi1_dms_impl_dlist_pop(&trackers->free);
	}
	DMS_BUG_ON(tracker == NULL);

	// add this tracker to the 'active' list
	hfi1_dms_impl_dlist_append(&trackers->active, tracker);

	return tracker;
}
struct hfi1_dms_rx_tracker *hfi1_dms_impl_rx_tracker_new(struct hfi1_dms *dms,
							   u64 size,
							   u64 starting_sbuf_offset, u64 dms_key,
							   u32 src_lid, struct hfi1_mem_region *rbuf, u64 rbuf_offset, struct hfi1_dms_tracker_completion const *completion)
{
	struct hfi1_dms_rx_tracker * tracker;

	DMS_BUG_ON(dms == NULL);

	tracker = (struct hfi1_dms_rx_tracker *) hfi1_dms_impl_tracker_new(&dms->rx_trackers, sizeof(struct hfi1_dms_rx_tracker));

	// initialize tracker state
	tracker->total_payload = size;
	tracker->payload_requested = 0;
	tracker->payload_remaining = size;
	tracker->sbuf_offset = starting_sbuf_offset;
	tracker->sbuf_start_offset = starting_sbuf_offset;
	tracker->rbuf_offset = rbuf_offset;
	tracker->rbuf_start_offset = rbuf_offset;
	tracker->dms_key = dms_key;
	tracker->src_lid = src_lid;
	tracker->tx_rift_index = HFI1_DMS_TX_RIFT_INDEX_NOT_SET;

	tracker->rbuf = rbuf;

	if (!completion || !completion->fn) {
		tracker->completion.fn = hfi1_dms_tracker_completion_fn_noop;
	} else {
		tracker->completion = *completion;
	}

	return tracker;
}

int hfi1_dms_impl_tx_tracker_initialize(struct hfi1_dms_tx_tracker * tx_tracker,
							   struct hfi1_dms_access *access, u64 size, u16 tx_rift_index)
{
	DMS_BUG_ON(tx_tracker == NULL);
	DMS_BUG_ON(access == NULL);

	// initialize tracker state
	tx_tracker->access = access;
	tx_tracker->total_payload = size;
	tx_tracker->payload_remaining = size;
	tx_tracker->rift_index = tx_rift_index;

	tx_tracker->completion = access->completion;

	return 0;
}

struct hfi1_dms_ahg_header *hfi1_dms_impl_ahg_header_get(struct hfi1_dms *dms)
{
	struct hfi1_dms_dlist_element * header;
	struct hfi1_dms_ahg_header *ret;

	DMS_BUG_ON(dms == NULL);

	header = hfi1_dms_impl_dlist_pop(&dms->ahg_headers.free);
	if (header == NULL) {
		dd_dev_info(dms->dd, "dms: No free AHG header available, allocating a new block.\n");
		hfi1_dms_impl_ahg_header_block_alloc(dms);
		header = hfi1_dms_impl_dlist_pop(&dms->ahg_headers.free);
		DMS_WARN_ON(header == NULL);
	}

	ret = (struct hfi1_dms_ahg_header *) header;
	return ret;
}

void hfi1_dms_impl_tracker_free(struct hfi1_dms_tracker_mgr * trackers, struct hfi1_dms_dlist_element * tracker)
{
	hfi1_dms_impl_dlist_remove(&trackers->active, tracker);
	hfi1_dms_impl_dlist_push(&trackers->free, tracker);
}
void hfi1_dms_impl_rx_tracker_free(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker * tracker)
{
	hfi1_dms_impl_tracker_free(&dms->rx_trackers, (struct hfi1_dms_dlist_element *)tracker);
}
void hfi1_dms_impl_tx_tracker_free(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker * tracker)
{
	hfi1_dms_impl_tracker_free(&dms->tx_trackers, (struct hfi1_dms_dlist_element *)tracker);
}

struct hfi1_dms_dlist_element * hfi1_dms_impl_dlist_pop(struct hfi1_dms_dlist * dlist)
{
	struct hfi1_dms_dlist_element * element;

	element = dlist->head;
	if (element == NULL) {
		return NULL;
	}

	dlist->head = element->next;
	if (dlist->head) {
		dlist->head->prev = NULL;
	} else {
		dlist->tail = NULL;
	}

	element->prev = NULL;
	element->next = NULL;

	return element;
}

void hfi1_dms_impl_dlist_push(struct hfi1_dms_dlist * dlist, struct hfi1_dms_dlist_element * element)
{
	element->prev = NULL;
	element->next = NULL;

	if (dlist->head == NULL) {
		DMS_BUG_ON(dlist->tail != NULL);
		dlist->head = element;
		dlist->tail = element;
		element->prev = NULL;
		element->next = NULL;
	} else {
		element->next = dlist->head;
		element->next->prev = element; //?
		dlist->head = element;
		element->prev = NULL;
	}

	DMS_BUG_ON(dlist->head->prev != NULL);
	DMS_BUG_ON(dlist->tail->next != NULL);
}

void hfi1_dms_impl_dlist_append(struct hfi1_dms_dlist * dlist, struct hfi1_dms_dlist_element * element)
{
	element->prev = NULL;
	element->next = NULL;

	if (dlist->tail == NULL) {
		DMS_BUG_ON(dlist->head != NULL);
		dlist->head = element;
		dlist->tail = element;
		element->prev = NULL;
		element->next = NULL;
	} else {
		element->prev = dlist->tail;
		element->prev->next = element;
		dlist->tail = element;
		element->next = NULL;
	}

	DMS_BUG_ON(dlist->head->prev != NULL);
	DMS_BUG_ON(dlist->tail->next != NULL);
}

void hfi1_dms_impl_dlist_remove(struct hfi1_dms_dlist * dlist, struct hfi1_dms_dlist_element * element)
{
	DMS_BUG_ON(dlist->head == NULL);
	DMS_BUG_ON(dlist->tail == NULL);
	
	if (element->prev != NULL) {
		element->prev->next = element->next;
	} else {
		dlist->head = element->next;
	}

	if (element->next != NULL) {
		element->next->prev = element->prev;
	} else {
		dlist->tail = element->prev;
	}

	element->prev = NULL;
	element->next = NULL;

}

struct hfi1_dms_rx_tracker * hfi1_dms_impl_rx_tracker_next_active(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *tracker)
{
	struct hfi1_dms_rx_tracker * next;

	pr_debug("%s:%d:%s() ENTER: dms=%p, tracker=%p\n", __FILENAME__, __LINE__, __func__, dms, tracker);
	next = (struct hfi1_dms_rx_tracker *) tracker->dlist.next;

	if (dms->rx_trackers.active.head == &tracker->dlist) {
		while (next && ((next->payload_requested == next->total_payload) || (next->tx_rift_index == HFI1_DMS_TX_RIFT_INDEX_PENDING))) {
			next = (struct hfi1_dms_rx_tracker *) next->dlist.next;
		}
		pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, next);
		return next;
	}

	// tracker tracker is not in head position
	while (next && ((next->payload_requested == next->total_payload) || (next->tx_rift_index == HFI1_DMS_TX_RIFT_INDEX_PENDING))) {
		next = (struct hfi1_dms_rx_tracker *) next->dlist.next;
	}
	if (next == NULL) {
		// go back and check from the head?
		next = (struct hfi1_dms_rx_tracker *) dms->rx_trackers.active.head;

		while (next && ((next->payload_requested == next->total_payload) || (next->tx_rift_index == HFI1_DMS_TX_RIFT_INDEX_PENDING))) {
			next = (struct hfi1_dms_rx_tracker *) next->dlist.next;
		}
	}
	pr_debug("%s:%d:%s() EXIT: ret=%p\n", __FILENAME__, __LINE__, __func__, next);
	return next;
}

s32 hfi1_dms_impl_tid_set_peek(struct hfi1_dms *dms)
{
	s32 tid_set;
	s32 ret;

	pr_debug("%s:%d:%s() ENTER: dms=%p\n", __FILENAME__, __LINE__, __func__, dms);
	DMS_BUG_ON(dms == NULL);
	if (dms->free_tid_sets_stack_top <= 0) {
		dd_dev_dbg(dms->dd, "No free TID sets available.\n");
		ret = -1; // No free TID sets available
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
		return ret;
	}
	tid_set = dms->free_tid_sets_stack[dms->free_tid_sets_stack_top - 1];
	dd_dev_dbg(dms->dd, "Next free TID set %d\n", tid_set);
	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, tid_set);
	return tid_set;
}

s32 hfi1_dms_impl_tid_set_get(struct hfi1_dms *dms)
{
	s32 tid_set;

	pr_debug("%s:%d:%s() ENTER: dms=%p\n", __FILENAME__, __LINE__, __func__, dms);
	DMS_BUG_ON(dms == NULL);
	if (dms->free_tid_sets_stack_top <= 0) {
		dd_dev_dbg(dms->dd, "No free TID sets available.\n");
		pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, -1);
		return -1; // No free TID sets available
	}

	tid_set = dms->free_tid_sets_stack[--dms->free_tid_sets_stack_top];
	dd_dev_dbg(dms->dd, "Allocated TID set %d\n", tid_set);
	pr_debug("%s:%d:%s() EXIT: ret=%d\n", __FILENAME__, __LINE__, __func__, tid_set);
	return tid_set;
}

void hfi1_dms_impl_tid_set_put(struct hfi1_dms *dms, s32 tid_set)
{
	pr_debug("%s:%d:%s() ENTER: dms=%p, tid_set=%d\n", __FILENAME__, __LINE__, __func__, dms, tid_set);
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(tid_set < HFI1_DMS_TID_SET_IDX_MIN || tid_set > HFI1_DMS_TID_SET_IDX_MAX);

	if (dms->free_tid_sets_stack_top >= HFI1_DMS_TID_SET_IDX_MAX) {
		dd_dev_err(dms->dd, "Tried to put TID set %d but stack is full.\n", tid_set);
		pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
		return; // Stack is full, cannot put TID set
	}

	dms->free_tid_sets_stack[dms->free_tid_sets_stack_top++] = tid_set;
	dd_dev_dbg(dms->dd, "Put TID set %d back into free stack.\n", tid_set);
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

void hfi1_dms_impl_rcv_context_disable9B(struct hfi1_dms *dms, u8 pidx, struct hfi1_ctxtdata *rcd)
{
	u64 reg;

	pr_debug("%s:%d:%s() ENTER: dms=%p, pidx=%u, rcd=%p\n", __FILENAME__, __LINE__, __func__, dms, pidx, rcd);
	dd_dev_info(dms->dd, "Disabling 9B context for pidx %u, ctxt %u\n", pidx, rcd->ctxt);

	reg = read_iprc_csr(dms->dd, pidx, rcd->ctxt, JKR_RCV_PKT_CTRL);
	dd_dev_info(dms->dd, "Current JKR_RCV_PKT_CTRL: 0x%016llx\n", reg);
	reg &= ~JKR_RCV_PKT_CTRL_L2_TYPE_ENABLE_MASK_SMASK;
	reg |= 0x4ull << JKR_RCV_PKT_CTRL_L2_TYPE_ENABLE_MASK_SHIFT;
	dd_dev_info(dms->dd, "Setting JKR_RCV_PKT_CTRL to 0x%016llx\n", reg);
	write_iprc_csr(dms->dd, pidx, rcd->ctxt, JKR_RCV_PKT_CTRL, reg);
	pr_debug("%s:%d:%s() EXIT\n", __FILENAME__, __LINE__, __func__);
}

void hfi1_dms_impl_slow_write_to_user(struct hfi1_mem_region *mr, u64 offset, const void *data, u64 size)
{
	DMS_BUG_ON(mr == NULL);

	if (size > sizeof(u64)) {
		pr_debug("DMS: tried to copy in more than a u64 to user buffer. Not currently supported");
		return;
	}

	if (offset > mr->rb.len - size) {
		pr_warn("DMS: Attempted to write beyond the end of the memory region. Offset: %llu, Size: %llu, Region Length: %lu\n", offset, size, mr->rb.len);
		return;
	}

	u64 page_index = offset / PAGE_SIZE;
	u64 offset_in_page = offset % PAGE_SIZE;

	if (offset_in_page + size > PAGE_SIZE) {
		// need to map two pages
		struct page *first_page = mr->pages[page_index];
		struct page *second_page = mr->pages[page_index + 1];
		void *kaddr_first = kmap_atomic(first_page);
		void *kaddr_second = kmap_atomic(second_page);
		u64 size_first_page = PAGE_SIZE - offset_in_page;
		u64 size_second_page = size - size_first_page;
		memcpy(kaddr_first + offset_in_page, data, size_first_page);
		memcpy(kaddr_second, data + size_first_page, size_second_page);
		kunmap_atomic(kaddr_second);
		kunmap_atomic(kaddr_first);
	} else {
		struct page *target_page = mr->pages[page_index];
		void *kaddr = kmap_atomic(target_page);
		memcpy(kaddr + offset_in_page, data, size);
		kunmap_atomic(kaddr);
	}
}

// max size is u64
// offset is "byte offset from the start of the first page in the memory region"
u64 hfi1_dms_impl_slow_read_from_user(struct hfi1_mem_region *mr, u64 offset, u64 size)
{
	DMS_BUG_ON(mr == NULL);

	u64 value = 0;

	if (size > sizeof(u64)) {
		pr_debug("DMS: tried to copy out more than a u64 from user buffer. Not currently supported - size: %llu\n", size);
		return value;
	}

	if (offset > mr->rb.len - size) {
		pr_warn("DMS: Attempted to read beyond the end of the memory region. Offset: %llu, Size: %llu, Region Length: %lu\n", offset, size, mr->rb.len);
		return value;
	}

	u64 page_index = offset / PAGE_SIZE;
	u64 offset_in_page = offset % PAGE_SIZE;

	if (offset_in_page + size > PAGE_SIZE) {
		pr_debug("DMS: Reading across page boundary. Page index: %llu, Offset in page: %llu, Size: %llu\n", page_index, offset_in_page, size);
		// need to map two pages
		struct page *first_page = mr->pages[page_index];
		struct page *second_page = mr->pages[page_index + 1];
		void *kaddr_first = kmap_atomic(first_page);
		void *kaddr_second = kmap_atomic(second_page);
		u64 size_first_page = PAGE_SIZE - offset_in_page;
		u64 size_second_page = size - size_first_page;
		memcpy(&value, kaddr_first + offset_in_page, size_first_page);
		memcpy(((char *)&value) + size_first_page, kaddr_second, size_second_page);
		kunmap_atomic(kaddr_second);
		kunmap_atomic(kaddr_first);
	} else {
		pr_debug("DMS: Reading within a single page. Page index: %llu, Offset in page: %llu, Size: %llu\n", page_index, offset_in_page, size);
		struct page *target_page = mr->pages[page_index];
		void *kaddr = kmap_atomic(target_page);
		memcpy(&value, kaddr + offset_in_page, size);
		kunmap_atomic(kaddr);
	}

	return value;
}


#define SOP_DISTANCE (TXE_PIO_SIZE / 2)
#define QWORD2BLOCK_SHIFT (3)
#define QWORD2BLOCK_MASK ((1 << QWORD2BLOCK_SHIFT) - 1)
#define QWORD2BLOCK_ROUND_UP(qws) (((qws) >> QWORD2BLOCK_SHIFT) + (((qws) & QWORD2BLOCK_MASK) != 0))

int hfi1_dms_impl_pio_send(struct hfi1_dms *dms, u64 pbc, void *data, u64 size_qw)
{
	struct send_context *sc = dms->sctxt;
	u64 total_size_qw = size_qw + 1; // +1 for pbc
	u32 blocks = QWORD2BLOCK_ROUND_UP(total_size_qw); // include pbc
	u32 pad_qws = ((PIO_BLOCK_SIZE - ((total_size_qw << 3) & (PIO_BLOCK_SIZE - 1))) >> 3) & 0x7;
	u32 avail = (u32) sc->credits - (sc->fill - sc->alloc_free);
	// only retry once because we've got our work queue anyway
	if (blocks > avail) {
		pr_debug("PIO Not enough space, trying again");
		u64 hw_free = le64_to_cpu(*sc->hw_free);
		sc->free = hw_free & CR_COUNTER_SMASK;
		sc->alloc_free = sc->free;
		avail = (u32) sc->credits - (sc->fill - sc->alloc_free);
		if (blocks > avail) {
			return -ENOMEM;
		}
	}
	pr_debug("PIO Sending %u blocks, %u pad qws, size_qw=%llu, pbc=0x%016llx\n", blocks, pad_qws, size_qw, pbc);

	u32 head = sc->sr_head;

	sc->fill += blocks;
	u32 fill_wrap = sc->fill_wrap;
	sc->fill_wrap += blocks;
	if (sc->fill_wrap >= sc->credits)
		sc->fill_wrap -= sc->credits;
	
	u32 next = head + 1;
	if (next >= sc->sr_size)
		next = 0;
	
	void __iomem *dest = (sc->base_addr + fill_wrap * PIO_BLOCK_SIZE) + SOP_DISTANCE;
	void __iomem *send = dest + PIO_BLOCK_SIZE;
	void __iomem *dend; // data end
	void __iomem *buf_end = sc->base_addr + sc->size;


	
	writeq(pbc, dest);
	dest += sizeof(u64);
	dend = dest + size_qw * sizeof(u64);
	
	if (blocks == 1) {
		while (dest < dend) {
			writeq(*(u64 *)data, dest);
			data += sizeof(u64);
			dest += sizeof(u64);
		}
	} else {
		while (dest < send) {
			writeq(*(u64 *)data, dest);
			data += sizeof(u64);
			dest += sizeof(u64);
		}
		/* drop out of the SOP range */
		dest -= SOP_DISTANCE;
		dend -= SOP_DISTANCE;

		// check for wrap and do it
		// TODO: just use autowrap hw feature
		if (buf_end <= dend) {
			while (dest < buf_end) {
				writeq(*(u64 *)data, dest);
				data += sizeof(u64);
				dest += sizeof(u64);
			}
			// wrap
			dest -= sc->size;
			dend -= sc->size;
		}

		while (dest < dend) {
			writeq(*(u64 *)data, dest);
			data += sizeof(u64);
			dest += sizeof(u64);
		}
	}

	for (u32 i = 0; i < pad_qws; ++i) {
		writeq(0, dest);
		dest += sizeof(u64);
	}

	wmb();
	sc->sr_head = next;


	return 0;
}

int hfi1_dms_impl_pio_send_work(struct hfi1_dms *dms, struct hfi1_dms_work_item *item)
{
	union hfi1_dms_proto_cmd * cmd = (union hfi1_dms_proto_cmd *)item->data;
	u64 size_qw = (hfi1_dms_impl_pbc_length_dws_get(cmd->pbc) >> 1) - 1;
	int rc = hfi1_dms_impl_pio_send(dms, cmd->pbc, &cmd->qws[1], size_qw);
	if (rc < 0) {
		// TODO - maybe count the number of times we fail to do the pio send?
		return -EAGAIN;
	}
	return 0;
}

int hfi1_dms_impl_pio_send_or_enqueue_work(struct hfi1_dms *dms, union hfi1_dms_proto_cmd * cmd)
{
	int ret;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!cmd);

	// -1 here because the pbc is included in the pbc dw length
	u64 size_qw = (hfi1_dms_impl_pbc_length_dws_get(cmd->pbc) >> 1) - 1;
	ret = hfi1_dms_impl_pio_send(dms, cmd->pbc, &cmd->qws[1], size_qw);
	if (ret < 0) {
		hfi1_dms_impl_queue_work_item(dms, (void*)cmd, sizeof(*cmd), hfi1_dms_impl_pio_send_work);
	}
	return 0;
}

