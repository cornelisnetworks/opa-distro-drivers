// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2025 Cornelis Networks.
 */
#include "dms.h"
#include "asm-generic/bug.h"
#include "asm/page_types.h"
#include "chip.h"
#include "hfi.h"
#include "linux/dma-mapping.h"
#include "linux/gfp_types.h"
#include "pio.h"
#include "sdma.h"
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
#define HFI1_DMS_WORK_ITEM_MAX_RETRY_TIME_NS  (10000000000) //   10 s
#define HFI1_DMS_ACCESS_STALL_MAX_RETRIES	(3)

#define USEC_IN_NS (1000ull)
#define MS_IN_NS   (1000ull * USEC_IN_NS)
#define SEC_IN_NS  (1000ull * MS_IN_NS)
#define MIN_IN_NS  (  60ull * SEC_IN_NS)

// elapsed ns between each "staleness check" poll
#define HFI1_DMS_STALE_POLL_TIME_NS          (100 * MS_IN_NS)

// elapsed ns since last activity after which the tracker is considered "stale" and must request remote status
#define HFI1_DMS_STALE_THRESHOLD_TIME_NS       (10 * SEC_IN_NS)

// elapsed ns since last activity after which the tracker is considered "dead" and must be canceled; must be greater than stale threshold
#define HFI1_DMS_DEAD_ELAPSED_NS               (100 * SEC_IN_NS)

// elapsed ns since last activity after which a disabled tidset can be free'd
#define HFI1_DMS_FABRIC_PACKET_MAX_LIFETIME_NS  (10 * SEC_IN_NS)

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
#define HFI1_DMS_CTRL_HDR_SIZE (12ull)
#define HFI1_DMS_MAX_TX_TRACKERS_FAST ((u64) U16_MAX)

#define HFI1_DMS_TID_SET_PAGES_MAX (HFI1_DMS_TID_SET_SIZE * 2)
#define HFI1_DMS_DESC_CHUNK_SIZE (32)
#define HFI1_DMS_PAYLOAD_CHUNK_SIZE (256)

#define HFI1_DMS_LRH16BC_LEN_QW_MASK (0x7ffull)
#define HFI1_DMS_LRH16BC_LEN_QW_SHIFT (48)

#define HFI1_DMS_ARRAY_SIZE(arr) ((sizeof(arr) / sizeof(arr[0])))

enum hfi1_dms_msg_type {
	HFI1_DMS_MSG_TYPE_READ_START = 0,
	HFI1_DMS_MSG_TYPE_READ_RESPONSE_SMALL,
	HFI1_DMS_MSG_TYPE_DATA_START,
	HFI1_DMS_MSG_TYPE_DATA_REQUEST,
	HFI1_DMS_MSG_TYPE_DATA_REQUEST_FIXUP,
	HFI1_DMS_MSG_TYPE_DATA_REQUEST_SMALL,
	HFI1_DMS_MSG_TYPE_DATA,
	HFI1_DMS_MSG_TYPE_DATA_FIXUP,
	HFI1_DMS_MSG_TYPE_DATA_SMALL,
	HFI1_DMS_MSG_TYPE_WRITE_START,
	HFI1_DMS_MSG_TYPE_ACK,
	HFI1_DMS_MSG_TYPE_NACK,
	HFI1_DMS_MSG_TYPE_STATUS,

	HFI1_DMS_MSG_TYPE_COUNT,
};

enum hfi1_dms_err_type {
	HFI1_DMS_ERR_TYPE_NONE = 0,
	HFI1_DMS_ERR_TYPE_CLIENT_NOT_FOUND,
	HFI1_DMS_ERR_TYPE_ACCESS_NOT_FOUND,
	HFI1_DMS_ERR_TYPE_ACCESS_RANGE_VIOLATION,
	HFI1_DMS_ERR_TYPE_NO_MEMORY,
	HFI1_DMS_ERR_TYPE_ACCESS_BUSY,

	HFI1_DMS_ERR_TYPE_COUNT,
};

struct hfi1_dms_proto_info_nack {
	enum hfi1_dms_msg_type msg_type;
	enum hfi1_dms_err_type err_type;
	hfi1_dms_rift_key_t rift_key;
	u16 unused;
} __attribute__((packed, aligned(4)));

enum hfi1_dms_status_type {
	HFI1_DMS_STATUS_TYPE_RX_REQUEST = 0,
	HFI1_DMS_STATUS_TYPE_RX_RESPONSE_OK,
	HFI1_DMS_STATUS_TYPE_RX_RESPONSE_NOT_FOUND,
	HFI1_DMS_STATUS_TYPE_TX_REQUEST,
	HFI1_DMS_STATUS_TYPE_TX_RESPONSE_OK,
	HFI1_DMS_STATUS_TYPE_TX_RESPONSE_NOT_FOUND,

	HFI1_DMS_STATUS_TYPE_COUNT,
};

struct hfi1_dms_proto_info_status {
	hfi1_dms_rift_key_t rx_rift_key;
	hfi1_dms_rift_key_t tx_rift_key;
	enum hfi1_dms_status_type type;
	u32 data;
} __attribute__((packed, aligned(4)));

struct hfi1_dms_proto_info_data_request_small {
	u32 bth[3];
	u32 kdeth[2];
	u16 size;
	hfi1_dms_rift_key_t rx_rift_key;
	u32 offset;
	hfi1_dms_rift_key_t tx_rift_key;
} __attribute__((packed, aligned(8)));

struct hfi1_dms_proto_info_data_request_fixup {
	u32 bth[3];
	u32 kdeth[2];
	hfi1_dms_rift_key_t tx_rift_key;
	hfi1_dms_rift_key_t rx_rift_key;
	u64 size;
} __attribute__((packed, aligned(8)));

struct hfi1_dms_proto_info_ack {
	u32 bth[3];
	u32 kdeth[2];
	hfi1_dms_rift_key_t tx_rift_key;
	u16 flags;
	u64 imm_data;
} __attribute__((packed, aligned(8)));

struct hfi1_dms_proto_info_data_small {
	u32 bth[3];
	u32 kdeth[2];
	hfi1_dms_rift_key_t tx_rift_key;
	hfi1_dms_rift_key_t rx_rift_key;
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
	hfi1_dms_rift_key_t tx_rift_key;
	hfi1_dms_rift_key_t rx_rift_key;
	u64 head; // first 8 bytes of sbuf
	u64 tail; // last 8 bytes of sbuf
} __attribute__((packed, aligned(8)));

struct hfi1_dms_proto_info_data {
	u32 bth[3];
	u32 kdeth[2];
	hfi1_dms_rift_key_t tx_rift_key;
	u16 unused;
	u64 head;
	u64 tail;
} __attribute__((packed, aligned(8)));

struct hfi1_dms_proto_info_write_start {
	u32 bth[3];
	u32 kdeth[2];
	u32 size;
	union hfi1_dms_key dms_key;
	u64 key_offset_or_vaddr;
	u64 imm_data;
} __attribute__((packed, aligned(8)));

// HFI1_DMS_MSG_TYPE_READ_RESPONSE_SMALL
struct hfi1_dms_proto_info_read_response_small {
	u32 bth[3];
	u32 kdeth[2];
	hfi1_dms_rift_key_t tx_rift_key;
	hfi1_dms_rift_key_t rx_rift_key;
	u64 data[2];
} __attribute__((packed, aligned(8)));

union hfi1_dms_cmd_read_response_small {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_read_response_small info; // 5 qws
		u64 tail_flit;
	};
};

union hfi1_dms_pkt_read_response_small {
	u64 qws[8];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_read_response_small info; // 5 qws
		u64 tail_flit; // <-- dropped on receive
	};
};

struct hfi1_dms_proto_info_data_request {
	u32 bth[3];
	u32 kdeth[2];
	u32 tid_info; // first 32 bits of non-optional KDETH on first data packet returned
	u32 offset;
	hfi1_dms_rift_key_t tx_rift_key;
	u16 unused;
} __attribute__((packed, aligned(8)));

union hfi1_dms_cmd_data_request {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_data_request info; // 4 qws
		u64 tail_flit;
	};
};

union hfi1_dms_pkt_data_request {
	u64 qws[7];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_data_request info; // 4 qws
		u64 tail_flit; // <-- dropped on receive
	};
};


//
// HFI1_DMS_MSG_TYPE_READ_START
//

struct hfi1_dms_proto_read_start {
	u32 bth[3];
	u32 kdeth[2];
	u32 size;
	union hfi1_dms_key dms_key;
	u64 key_offset_or_vaddr;
	u32 tid_info; // first 32 bits of non-optional KDETH on first data packet returned
	u16 flags;
	u8 include_fixup_data;
	u8 head_misalignment;
	u64 imm_data;
} __attribute__((packed, aligned(4)));


union hfi1_dms_cmd_read_start {
	u64 qws[16];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_read_start info; // 7 qws
		u64 tail_flit;
		u64 padding[6];
	};
};

union hfi1_dms_pkt_read_start {
	u64 qws[10];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_read_start info; // 7 qws
		u64 tail_flit; // <-- dropped on receive
	};
};







union hfi1_dms_proto_cmd_data_request_small {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_data_request_small info; // 5 qws
		u64 tail_flit;
	};
};

union hfi1_dms_proto_pkt_data_request_small {
	u64 qws[8];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_data_request_small info; // 5 qws
		u64 tail_flit; // <-- dropped on receive
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
		u64 tail_flit; // <-- dropped on receive
	};
};

union hfi1_dms_proto_cmd_data_request_fixup {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_data_request_fixup info; // 4 qws
		u64 tail_flit;
	};
};

union hfi1_dms_proto_pkt_data_request_fixup {
	u64 qws[8];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_data_request_fixup info; // 4 qws
		u64 tail_flit; // <-- dropped on receive
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
		u64 tail_flit; // <-- dropped on receive
	};
};

union hfi1_dms_proto_cmd_data {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_data info;	// 5 qws
		u64 tail_flit;
	};
};

union hfi1_dms_proto_pkt_data {
	u64 qws[8];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_data info; // 5 qws
		u64 tail_flit; // <-- dropped on receive
	};
};



union hfi1_dms_proto_cmd_ack {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_ack info; // 4 qws
		u64 tail_flit;
		u64 padding[1];
	};
};

union hfi1_dms_proto_pkt_ack {
	u64 qws[7];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_ack info; // 4 qws
		u64 tail_flit; // <-- dropped on receive
	};
};


union hfi1_dms_proto_cmd_write_start {
	u64 qws[16];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi1_dms_proto_info_write_start info; // 6 qws
		u64 tail_flit;
		u64 padding[7];
	};
};

union hfi1_dms_proto_pkt_write_start {
	u64 qws[8];
	struct {
		u64 lrh[2];
		struct hfi1_dms_proto_info_write_start info; // 6 qws
		u64 tail_flit; // <-- dropped on receive
	};
};

struct dms_handle_data_request_parameters {
	u32 size_qw;
	u32 tid_info;
	u32 sbuf_offset;
	hfi1_dms_rift_key_t tx_rift_key;
	u8 rx_id;
};




struct dms_proto_read_sdma_parameters {
	struct hfi1_dms_tx_tracker *tx_tracker;
	struct hfi1_dms_mr *mr;
	u64 page_offset;
	u32 nbytes;
	u32 tid_info;
	u8 rx_id;
	u64 head;
	u64 tail;
	enum hfi1_dms_msg_type msg_type;
};

union hfi1_dms_cmd_nack {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		u32 bth[3];
		u32 kdeth[2];
		struct hfi1_dms_proto_info_nack info; // 3 dws
		u64 tail_flit;
		u64 padding[1];
	};
};
union hfi1_dms_pkt_nack {
	u64 qws[7];
	struct {
		u64 lrh[2];
		u32 bth[3];
		u32 kdeth[2];
		struct hfi1_dms_proto_info_nack info; // 3 dws
		u64 tail_flit; // <-- dropped on receive
	};
};

union hfi1_dms_cmd_status {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		u32 bth[3];
		u32 kdeth[2];
		struct hfi1_dms_proto_info_status info; // 3 dws
		u64 tail_flit;
		u64 padding[1];
	};
};
union hfi1_dms_pkt_status {
	u64 qws[7];
	struct {
		u64 lrh[2];
		u32 bth[3];
		u32 kdeth[2];
		struct hfi1_dms_proto_info_status info; // 3 dws
		u64 tail_flit; // <-- dropped on receive
	};
};

// redundant now but keeping it here just in case
static void hfi1_sdma_disable_gen_check(struct hfi1_dms *dms, struct sdma_engine *sde)
{
	u64 reg;

	sde->check_generation = SDMA_CHECK_GEN_DISABLE; // disabled
	reg = read_sdma_csr(dms->dd, sde->this_idx, sde->dd->params->send_dma_len_gen_reg);
	reg &= ~(((u64) (BIT(3) - 1)) << SEND_DMA_LEN_GEN_GENERATION_SHIFT);
	write_sdma_csr(dms->dd, sde->this_idx, sde->dd->params->send_dma_len_gen_reg, reg);
}

static inline u32 hfi1_dms_lrh16B_slid_get(u32 *lrh)
{
	u32 ret;

	ret = (u32)((lrh[0] & OPA_16B_LID_MASK) |
			 (((lrh[2] & OPA_16B_SLID_MASK) >>
			 OPA_16B_SLID_HIGH_SHIFT) << OPA_16B_SLID_SHIFT));
	return ret;
}

static inline u32 hfi1_dms_lrh16B_pkt_len_get(u64 *lrh)
{
	u32 ret;

	ret = (u32)((lrh[0] & OPA_16B_LEN_MASK) >> OPA_16B_LEN_SHIFT);
	return ret;
}

static inline u32 hfi1_dms_16b_data_payload_qws_get(union hfi1_dms_16b_header *hdr)
{
	u32 pktlen_qws;
	u32 ret;

	// For DMS data messages the amount of payload is
	// pktlen_qws - HEADER_SIZE_QWs (8) - 1 (tail flit)
	pktlen_qws = hfi1_dms_lrh16B_pkt_len_get(hdr->lrh);
	ret = pktlen_qws - 8 - 1; // 8 QWs for header, 1 QW for tail flit
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

	ret = kver | tid_ctrl | (((u32) tid & TID_MASK) << TID_SHIFT) | (offset_dw & OFFSET_DW_MASK);
	return ret;
}

static inline u32 hfi1_dms_tid_info_update_tid(u32 tid_info, u16 tid)
{
	u32 const TID_MASK = 0x3ffu;
	u32 const TID_SHIFT = 16;

	// Clear the old TID
	tid_info &= ~(TID_MASK << TID_SHIFT);
	// Set the new TID
	tid_info |= ((u32) tid & TID_MASK) << TID_SHIFT;

	return tid_info;
}

/**
 * Sets the RX-ID in the DestQP field of the BTH for a KDETH packet
 * bth should be the start of the bth header field
 */
static inline void _dms_destqp_rx_set(u32 *bth, u16 rx_id)
{
	bth[1] = (bth[1] & ~(0xffu << 24)) | (u32) (rx_id << 24); // Set RX QP prefix
}

/**
 * Sets the RX ID of the context data should be returned to.
 * This is used in the protocol messages e.g. READ_START
 * bth should be the start of the bth header field
 */
static inline void _dms_return_rx_set(u32 *bth, u16 rx_id)
{
	bth[0] = (bth[0] & ~(0xffu << 24)) | (u32) (rx_id << 24);
}

static inline u16 _dms_return_rx_get(u32 *bth)
{
	return (bth[0] >> 24) & 0xFFFF;
}

void hfi1_dms_impl_pbc_dlid_set(u64 *pbc, u32 dlid);
void hfi1_dms_impl_lrh16bc_dlid_set(u64 *lrh16bc, u32 dlid);
void hfi1_dms_impl_lrh16bc_len_qws_set(u64 *lrh16bc, u32 len_qws);


// General Utilities
// NOTE: size has to be <= sizeof(u64) for now. Maybe later this can be a full utility
void hfi1_dms_impl_slow_write_to_user(struct hfi1_dms_mr *mr, u64 offset, const void *data, u64 size);
// NOTE: size has to be <= sizeof(u64) for now. Maybe later this can be a full utility
u64 hfi1_dms_impl_slow_read_from_user(struct hfi1_dms_mr *mr, u64 offset, u64 size);

// Context and CSR utility functions
void _configure_ctrl_rcd(struct hfi1_dms *dms, u8 pidx, struct hfi1_ctxtdata *rcd);
void _configure_data_rcd(struct hfi1_dms *dd, u8 pidx, struct hfi1_ctxtdata *rcd);

void hfi1_dms_impl_rcv_context_disable9B(struct hfi1_dms *dms, u8 pidx, struct hfi1_ctxtdata *rcd);
// Sets the split point for a particular RCD to the required split point for a control
// packet i.e. the full 128 bytes
void _set_ctrl_split_point(struct hfi1_dms *dms, u8 pidx, struct hfi1_ctxtdata *rcd);

// Data structure functions
int hfi1_dms_impl_work_item_block_alloc(struct hfi1_dms *dms);
void hfi1_dms_impl_work_item_block_free(struct hfi1_dms *dms);
struct hfi1_dms_work_item *hfi1_dms_impl_work_item_new(struct hfi1_dms *dms);
void hfi1_dms_impl_work_item_free(struct hfi1_dms *dms, struct hfi1_dms_work_item *item);
int hfi1_dms_impl_tracker_block_alloc(struct hfi1_dms *dms);
void hfi1_dms_impl_tracker_block_free(struct hfi1_dms *dms);
int hfi1_dms_impl_ahg_header_block_alloc(struct hfi1_dms *dms);
void hfi1_dms_impl_ahg_header_block_free(struct hfi1_dms *dms);

int hfi1_dms_access_block_new(struct hfi1_dms *dms);
struct hfi1_dms_access * hfi1_dms_access_freelist_pop(struct hfi1_dms *dms);

union hfi1_dms_tracker * hfi1_dms_impl_tracker_new(struct hfi1_dms *dms);
struct hfi1_dms_rx_tracker *hfi1_dms_impl_rx_tracker_read_new(struct hfi1_dms *dms,
							   u32 size,
							   u64 starting_sbuf_offset, union hfi1_dms_key dms_key,
							   u32 src_lid, struct hfi1_dms_mr *rbuf, u64 rbuf_offset,
								 u16 flags, u64 imm_data,
								 struct hfi1_dms_tracker_completion const *completion);
void hfi1_dms_impl_rx_tracker_free(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker * tracker);

struct hfi1_dms_tx_tracker *hfi1_dms_impl_tx_tracker_write_new(struct hfi1_dms *dms, u32 size,
		u64 byte_offset_from_first_page, u32 remote_lid, struct hfi1_dms_mr *mr, u64 mr_offset,
		u16 flags, u64 imm_data, struct hfi1_dms_tracker_completion const *completion, union hfi1_dms_key rx_dms_key,
		u64 rx_offset);
void hfi1_dms_impl_tx_tracker_free(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker * tracker);

struct hfi1_dms_ahg_header_set *hfi1_dms_impl_ahg_header_set_get(struct hfi1_dms *dms);

struct hfi1_dms_dlist_element * hfi1_dms_impl_dlist_pop(struct hfi1_dms_dlist * dlist);
void hfi1_dms_impl_dlist_push(struct hfi1_dms_dlist * dlist, struct hfi1_dms_dlist_element * element);
void hfi1_dms_impl_dlist_append(struct hfi1_dms_dlist * dlist, struct hfi1_dms_dlist_element * element);
void hfi1_dms_impl_dlist_remove(struct hfi1_dms_dlist * dlist, struct hfi1_dms_dlist_element * element);

int _tidset_idx_peek(struct hfi1_dms *dms, u32 *tid_set);
void _tidset_idx_reserve(struct hfi1_dms *dms, u32 tid_set);
void _tidset_idx_release(struct hfi1_dms *dms, u32 tid_set);

void _tidset_reset(struct hfi1_dms *dms, u32 tid_set, enum hfi1_dms_tidset_state new_state);
void _tidset_disable(struct hfi1_dms *dms, u32 tid_set);
void _tidset_enable(struct hfi1_dms *dms, u32 tid_set, struct hfi1_dms_rx_tracker *rx_tracker, u32 *tid_info, u64 *tidset_nbytes);

void hfi1_dms_impl_lrh16bc_dlid_set(u64 *lrh16bc, u32 dlid);

// protocol message creation functions
void hfi1_dms_impl_fill_proto_templates(struct hfi1_dms *dms);
int hfi1_dms_impl_16bc_state_set(struct hfi1_dms *dms);

u32 hfi1_dms_impl_data_request_size_qw_get(union hfi1_dms_16b_header *hdr);

// protocol functions
int hfi1_dms_impl_make_data_request(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *tracker, u32 tid_set);
int hfi1_dms_impl_make_data_requests(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *tracker);
void hfi1_dms_rx_tracker_handle_completion(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker, int status, u32 do_ack);
void hfi1_dms_impl_handle_read_start_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
int hfi1_dms_impl_handle_read_start(struct hfi1_dms *dms, struct hfi1_dms_read_start_parameters const parameters, bool const access_lookup_is_error);
int hfi1_dms_sdma_send(struct hfi1_dms *dms, struct hfi1_dms_sdma_parameters const * parameters);
union hfi1_dms_proto_cmd_data_fixup hfi1_dms_proto_cmd_data_fixup_make(struct hfi1_dms *dms, u32 dlid, u16 rx_id, hfi1_dms_rift_key_t tx_rift_key, hfi1_dms_rift_key_t rx_rift_key, u64 head, u64 tail);
union hfi1_dms_proto_cmd_data_small hfi1_dms_proto_cmd_data_small_make(struct hfi1_dms *dms, u32 dlid, u16 rx_id, hfi1_dms_rift_key_t tx_rift_key, hfi1_dms_rift_key_t rx_rift_key, u64 data0, u64 data1);

union hfi1_dms_proto_cmd_data_request_fixup hfi1_dms_proto_cmd_data_request_fixup_make(struct hfi1_dms *dms,
		struct hfi1_dms_rx_tracker const * const rx_tracker, u32 dlid, hfi1_dms_rift_key_t tx_rift_key, hfi1_dms_rift_key_t rx_rift_key);

// protocol packet handling functions
static int hfi1_dms_impl_queue_work_item(struct hfi1_dms *dms, void * data, size_t len, hfi1_dms_work_fn work_fn);
static void _handle_ctrl_packet(struct hfi1_packet *packet);
static void _handle_data_packet(struct hfi1_packet *packet);
static void _noop_handle_packet(struct hfi1_packet *packet);

int hfi1_dms_impl_handle_data_request_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
int hfi1_dms_impl_handle_data_request_fixup_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
void hfi1_dms_impl_handle_ack(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
int hfi1_dms_impl_handle_data_request_small_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);

void hfi1_dms_impl_handle_read_response_small_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);

void hfi1_dms_handle_data(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
void hfi1_dms_handle_data_fixup(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
void hfi1_dms_impl_handle_data_small_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);

void hfi1_dms_impl_handle_write_start_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
int hfi1_dms_impl_handle_write_start(struct hfi1_dms *dms, struct hfi1_dms_write_start_parameters const parameters, bool const access_lookup_is_error);
void hfi1_dms_impl_handle_nack_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);
void hfi1_dms_impl_handle_status_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr);

int hfi1_dms_impl_sdma_send(struct hfi1_dms *dms, struct hfi1_dms_mr * mr, u64 page_offset, u32 nbytes, u32 dlid, u8 rx_id, u32 tid_info, hfi1_dms_rift_key_t tx_rift_key,
	u64 head_qw, u64 tail_qw, enum hfi1_dms_sdma_type sdma_type);

// PIO functions - note: these should only be used in bulksvc/dms or similar.
// the assumption here is only one thread is controlling the PIO buffers at any given time

// since DMS exclusively uses 16B packets all sizes are QW anyway
// also this is function assumes we're either doing 1 or 2 PIO blocks
int hfi1_dms_impl_pio_send(struct hfi1_dms *dms, u64 pbc, void *data, u64 size_qw);
int hfi1_dms_cmd_pio_send(struct hfi1_dms *dms, union hfi1_dms_proto_cmd * cmd);
int hfi1_dms_impl_pio_send_or_enqueue_work(struct hfi1_dms *dms, union hfi1_dms_proto_cmd * cmd);

u64 hfi1_dms_impl_pbc_length_dws_get(u64 pbc);

int calculate_access_mr_page_offset(struct hfi1_dms *dms, struct hfi1_dms_access * access, u64 offset, u32 size, u64 *page_offset);
int calculate_mr_page_offset(struct hfi1_dms *dms, struct hfi1_dms_mr * mr, u64 offset, u32 size, u64 *page_offset);

void hfi1_dms_rx_tracker_cancel(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker, int err);
void hfi1_dms_tx_tracker_cancel(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker *tx_tracker, int err);

union hfi1_dms_proto_cmd_write_start hfi1_dms_proto_cmd_write_start_make(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker *tx_tracker,
		u32 dlid, hfi1_dms_rift_key_t tx_rift_key, u32 size, union hfi1_dms_key dms_key, u64 key_offset_or_vaddr, u16 flags, u64 imm_data);

union hfi1_dms_cmd_read_response_small hfi1_dms_cmd_read_response_small_make(struct hfi1_dms *dms,
			struct hfi1_dms_mr * mr, u64 page_offset, u32 size, u32 dlid, u16 rx_id, hfi1_dms_rift_key_t rx_rift_key, hfi1_dms_rift_key_t tx_rift_key);

void _rift_init(struct hfi1_dms_rift * rift);
static hfi1_dms_rift_key_t _rift_key_create_err(enum hfi1_dms_rift_err const err);

/** For now just use the same functions
 * but TODO: make these receive type specific
 */
const rhf_rcv_function_ptr _dms_rhf_rcv_functions_data[] = {
	[RHF_RCV_TYPE_EAGER] = _handle_data_packet,
	[RHF_RCV_TYPE_EXPECTED] = _handle_data_packet,
	[RHF_RCV_TYPE_ERROR] = _handle_data_packet,
	[RHF_RCV_TYPE_BYPASS] = _handle_data_packet,

	[RHF_RCV_TYPE_IB] = _noop_handle_packet,
	[RHF_RCV_TYPE_INVALID5] = _noop_handle_packet,
	[RHF_RCV_TYPE_INVALID6] = _noop_handle_packet,
	[RHF_RCV_TYPE_INVALID7] = _noop_handle_packet,
};

const rhf_rcv_function_ptr _dms_rhf_rcv_functions_ctrl[] = {
	[RHF_RCV_TYPE_EAGER] = _handle_ctrl_packet,
	[RHF_RCV_TYPE_EXPECTED] = _handle_ctrl_packet,
	[RHF_RCV_TYPE_ERROR] = _handle_ctrl_packet,
	[RHF_RCV_TYPE_BYPASS] = _handle_ctrl_packet,

	[RHF_RCV_TYPE_IB] = _noop_handle_packet,
	[RHF_RCV_TYPE_INVALID5] = _noop_handle_packet,
	[RHF_RCV_TYPE_INVALID6] = _noop_handle_packet,
	[RHF_RCV_TYPE_INVALID7] = _noop_handle_packet,
};

int hfi1_dms_init(struct hfi1_dms *dms, struct hfi1_devdata *dd, struct hfi1_ctxtdata **rcds, int num_rcds, struct sdma_engine **sdma_engines, int num_engines)
{
	struct hfi1_dms_access *access = NULL;
	int ret = 0;
	s32 max_tid_set_idx;
	int i;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(dd == NULL);
	DMS_BUG_ON(rcds == NULL);
	DMS_BUG_ON(num_rcds <= 0);
	DMS_BUG_ON(sdma_engines == NULL);
	DMS_BUG_ON(num_engines <= 0);

	*dms = (struct hfi1_dms){0}; // Initialize the dms structure to zero
	dms->dd = dd;

	if (num_rcds < 2) {
		dd_dev_warn(dd, "DMS Init called with too few contexts. Got %d, Need at least 2\n", num_rcds);
		ret = -EINVAL;
		goto bail;
	}

	dms->rcd_ctrl = rcds[0];
	dms->rcd_data = rcds[1];
	dms->sctxt = dms->rcd_ctrl->sc;
	dms->sdma_engines = sdma_engines;
	dms->num_engines = num_engines;
	max_tid_set_idx = (dms->rcd_data->expected_count / 2) / HFI1_DMS_TID_SET_SIZE;

	for (i = 0; i < num_engines; ++i) {
		hfi1_sdma_disable_gen_check(dms, dms->sdma_engines[i]);
	}

	_configure_ctrl_rcd(dms, HFI1_DMS_PORT, dms->rcd_ctrl);
	_configure_data_rcd(dms, HFI1_DMS_PORT, dms->rcd_data);

	
	for (i = 0; i < max_tid_set_idx; ++i) {
		dms->free_tid_sets_stack[i] = i;
		dms->read_requests[i].tid_set = i;
	}
	dms->free_tid_sets_stack_top = max_tid_set_idx;

	dms->protocol_cmd_templates = (union hfi1_dms_proto_cmd *) kcalloc(HFI1_DMS_MSG_TYPE_COUNT, sizeof(union hfi1_dms_proto_cmd), GFP_KERNEL);
	if (!dms->protocol_cmd_templates) {
		ret = -ENOMEM;
		goto bail;
	}
	hfi1_dms_impl_fill_proto_templates(dms);

	// initialize a set of trackers
	if (hfi1_dms_impl_tracker_block_alloc(dms)) {
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
	
	dms->client_rbtree = RB_ROOT;

	if (hfi1_dms_access_block_new(dms)) {
		ret = -ENOMEM;
		goto bail;
	}

	_rift_init(&dms->rx_rift);
	_rift_init(&dms->tx_rift);

	dms->disabled_rx_tracker.hdr.local_rift_key = _rift_key_create_err(HFI1_DMS_RIFT_ERR_KEY_DISABLED);
	dms->disabled_rx_tracker.hdr.remote_rift_key = _rift_key_create_err(HFI1_DMS_RIFT_ERR_KEY_DISABLED);
	dms->last_stale_check = ktime_get();

	dd_dev_warn(dms->dd, "DMS initialized with %d SDMA engines.\n", num_engines);

	return 0;

bail:
	while ((access = hfi1_dms_access_freelist_pop(dms))) {
		kfree(access);
	}

	hfi1_dms_impl_ahg_header_block_free(dms);

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

	hfi1_dms_impl_tracker_block_free(dms);

	if (dms->protocol_cmd_templates) {
		kfree(dms->protocol_cmd_templates);
		dms->protocol_cmd_templates = NULL;
	}

	return ret;
}

void hfi1_dms_uninit(struct hfi1_dms *dms)
{
	int i;

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

	kfree(dms->desc_stack);
	dms->desc_stack = NULL;
	kfree(dms->sde_rsrcs);
	dms->sde_rsrcs = NULL;
	hfi1_dms_impl_tracker_block_free(dms);

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
}

static struct hfi1_dms_client_state * hfi1_dms_client_rbtree_search(struct hfi1_dms *dms, u32 client_key)
{
	struct rb_root *root = &dms->client_rbtree;
	struct rb_node *node = root->rb_node;
	struct hfi1_dms_client_state *client;

	while (node) {
		client = container_of(node, struct hfi1_dms_client_state, node);

		if (client_key < client->key)
			node = node->rb_left;
		else if (client_key > client->key)
			node = node->rb_right;
		else {
			return client;
		}
	}
	return NULL;
}

static int hfi1_dms_client_rbtree_insert(struct hfi1_dms *dms, u32 client_key, struct hfi1_dms_client_state * client)
{
	struct rb_root *root = &dms->client_rbtree;
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct hfi1_dms_client_state *this = container_of(*new, struct hfi1_dms_client_state, node);

		parent = *new;
		if (client_key < this->key)
			new = &((*new)->rb_left);
		else if (client_key > this->key)
			new = &((*new)->rb_right);
		else {
			return -ENOSPC;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&client->node, parent, new);
	rb_insert_color(&client->node, &dms->client_rbtree);

	return 0;
 }

static void hfi1_dms_client_rbtree_remove(struct hfi1_dms *dms, struct hfi1_dms_client_state *client)
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

static struct hfi1_dms_access * hfi1_dms_access_rbtree_search(struct hfi1_dms_client_state *client, u32 access_key)
{
	struct rb_root *root = &client->access.rbt;
	struct rb_node *node = root->rb_node;
	struct hfi1_dms_access *access;

	while (node) {
		access = container_of(node, struct hfi1_dms_access, node);

		if (access_key < access->dms_key.access)
			node = node->rb_left;
		else if (access_key > access->dms_key.access)
			node = node->rb_right;
		else {
			return access;
		}
	}
	return NULL;
}

static int hfi1_dms_access_rbtree_insert(struct hfi1_dms_client_state *client, u32 access_key, struct hfi1_dms_access *access)
{
	struct rb_root *root = &client->access.rbt;
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct hfi1_dms_access *this = container_of(*new, struct hfi1_dms_access, node);

		parent = *new;
		if (access_key < this->dms_key.access)
			new = &((*new)->rb_left);
		else if (access_key > this->dms_key.access)
			new = &((*new)->rb_right);
		else {
			return -ENOSPC;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&access->node, parent, new);
	rb_insert_color(&access->node, &client->access.rbt);

	return 0;
}

static void hfi1_dms_access_freelist_push(struct hfi1_dms *dms, struct hfi1_dms_access *access)
{
	// PRE - not active ...
	hfi1_dms_impl_dlist_push(&dms->access.freelist, &access->element);
}

struct hfi1_dms_access *hfi1_dms_access_freelist_pop(struct hfi1_dms *dms)
{
	struct hfi1_dms_dlist_element * element;
	element = hfi1_dms_impl_dlist_pop(&dms->access.freelist);
	if (!element) {
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

static struct hfi1_dms_access * hfi1_dms_access_new(struct hfi1_dms *dms)
{
	struct hfi1_dms_access *access;

	access = hfi1_dms_access_freelist_pop(dms);
	if (!access) {
		if (hfi1_dms_access_block_new(dms)) {
			dd_dev_err(dms->dd, "Failed to allocate new access block.\n");
			return NULL;
		}

		access = hfi1_dms_access_freelist_pop(dms);
		if (!access) {
			dd_dev_err(dms->dd, "Free list error.\n");
			return NULL;
		}
	}
	return access;
}

static int hfi1_dms_access_assign(struct hfi1_dms *dms, union hfi1_dms_key dms_key, struct hfi1_dms_access *access)
{
	u64 const client_key = dms_key.client;
	u64 const access_key = dms_key.access;
	struct hfi1_dms_client_state * client;
	int rc;

	client = hfi1_dms_client_rbtree_search(dms, client_key);
	if (!client) {
		dd_dev_err(dms->dd, "Client key %llu not found.\n", client_key);
		return -EINVAL;
	}

	access->dms_key = dms_key;

	if (access_key < HFI1_DMS_MAX_ACCESS_FAST) {
		if (client->access.arr[access_key]) {
			dd_dev_err(dms->dd, "Client access already active for id %llu.\n", access_key);
			return -EEXIST;
		}
		client->access.arr[access_key] = access;
	} else {
		rc = hfi1_dms_access_rbtree_insert(client, access_key, access);
		if (rc < 0) {
			dd_dev_err(dms->dd, "Client access rbtree insertion error.\n");
			return -1;
		}
	}

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

static int hfi1_dms_access_remove(struct hfi1_dms *dms, struct hfi1_dms_access * access)
{
	// FIXME - There must be a faster/better way to remove access from the rbtree since we already have pointers to it ....

	u64 client_key = access->dms_key.client;
	u64 access_key = access->dms_key.access;
	struct hfi1_dms_client_state * client;

	client = hfi1_dms_client_rbtree_search(dms, client_key);
	if (!client) {
		dd_dev_err(dms->dd, "Invalid client error. key = 0x%016llx (%llu)\n", client_key, client_key);
		return -1;
	}

	if (access_key < HFI1_DMS_MAX_ACCESS_FAST) {
		if (!client->access.arr[access_key]) {
			dd_dev_err(dms->dd, "Access not active error. id = %llu\n", access_key);
			return -1;
		}
		client->access.arr[access_key] = NULL;
	} else {
		rb_erase(&access->node, &client->access.rbt);
	}
	return 0;
}

static struct hfi1_dms_access * hfi1_dms_access_lookup(struct hfi1_dms *dms, union hfi1_dms_key dms_key, struct hfi1_dms_client_state **client_out)
{
	WARN_ON(client_out == NULL);
	struct hfi1_dms_access * access = NULL;
	u64 client_key = dms_key.client;
	u64 access_key = dms_key.access;
	struct hfi1_dms_client_state * client;

	client = hfi1_dms_client_rbtree_search(dms, client_key);
	if (!client) {
		*client_out = NULL;
		dd_dev_err(dms->dd, "Invalid client error. key = 0x%016llx (%llu)\n", client_key, client_key);
		return NULL;
	}
	*client_out = client;

	if (access_key < HFI1_DMS_MAX_ACCESS_FAST) {
		access = client->access.arr[access_key];
	} else {
		access = hfi1_dms_access_rbtree_search(client, access_key);
	}

	if (!access) {
		return NULL;
	}
	return access;
}

void hfi1_dms_tracker_completion_fn_noop(union hfi1_dms_completion_cookie *cookie, int status)
{
	(void) cookie;
	(void) status;
}

void hfi1_dms_access_completion_fn_noop(union hfi1_dms_completion_cookie *cookie, u16 flags, u64 imm_data, int status)
{
	(void) cookie;
	(void) imm_data;
	(void) flags;
	(void) status;
}

static void hfi1_dms_impl_access_initialize(struct hfi1_dms_access *access, enum hfi1_dms_access_type access_type, struct hfi1_dms_mr *mr, u64 offset, u32 size, union hfi1_dms_key dms_key, struct hfi1_dms_access_completion const *completion)
{
	access->node = (struct rb_node){ 0 };
	access->element = (struct hfi1_dms_dlist_element){ 0 };

	access->dms_key = dms_key;
	access->type = access_type;

	if (completion) {
		access->completion = *completion;
	} else {
		access->completion.fn = hfi1_dms_access_completion_fn_noop;
	}

	access->mr = mr;
	access->offset = offset;
	access->size = size;
	access->active_count = 0;
}

int hfi1_dms_register_access(struct hfi1_dms *dms, struct hfi1_dms_mr *mr, u64 offset, u32 size, union hfi1_dms_key dms_key, struct hfi1_dms_access_completion const completion, enum hfi1_dms_access_type access_type, struct hfi1_dms_access **out)
{
	struct hfi1_dms_access *access;
	int ret;
	u64 page_offset;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!mr);

	ret = calculate_mr_page_offset(dms, mr, offset, size, &page_offset); // validate offset and size
	if (ret < 0) {
		if (out) *out = NULL;
		return ret;
	}

	access = hfi1_dms_access_new(dms);
	if (!access) {
		if (out) *out = NULL;
		return -ENOMEM;
	} 

	hfi1_dms_impl_access_initialize(access, access_type, mr, offset, size, dms_key, &completion);

	ret = hfi1_dms_access_assign(dms, dms_key, access);
	if (ret < 0) {
		if (out) *out = NULL;
		dd_dev_err(dms->dd, "Access not assigned.\n");
		hfi1_dms_access_freelist_push(dms, access);
		return ret;
	}

	if (out) *out = access;

	return 0;
}

int hfi1_dms_unregister_access(struct hfi1_dms *dms, union hfi1_dms_key dms_key)
{
	struct hfi1_dms_access *access;
	struct hfi1_dms_client_state *client = NULL;

	access = hfi1_dms_access_lookup(dms, dms_key, &client);
	if (!access || !client) {
		dd_dev_warn(dms->dd,
			    "Invalid dms_key %llu for unregistering access.\n",
			    dms_key.value);
		return -EINVAL;
	}

	if (access->active_count > 0) {
		dd_dev_warn(dms->dd, "Attempt to unregister access with dms_key %llu while it is active.\n", dms_key.value);
	}

	hfi1_dms_access_remove(dms, access);
	hfi1_dms_access_freelist_push(dms, access);

	return 0;
}

static int access_xfer_begin(struct hfi1_dms *dms, struct hfi1_dms_access * access)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!access);

	if ((access->active_count == 1) && (access->type == HFI1_DMS_ACCESS_TYPE_EPHEMERAL)) {
		return -EBUSY; // can't have multiple in-flight transfers on an ephemeral access window
	}

	access->active_count += 1;
	return 0;
}

static void access_xfer_end(struct hfi1_dms *dms, struct hfi1_dms_access * access, u16 flags, u64 imm_data, int status)
{
	int ret;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!access);
	DMS_BUG_ON(access->active_count == 0);

	access->active_count -= 1;

	if (access->type == HFI1_DMS_ACCESS_TYPE_EPHEMERAL && access->active_count == 0) {
		ret = hfi1_dms_access_remove(dms, access);
		DMS_BUG_ON(ret < 0);
		access->completion.fn(&access->completion.cookie, flags, imm_data, status);
		hfi1_dms_access_freelist_push(dms, access);
	} else {
		access->completion.fn(&access->completion.cookie, flags, imm_data, status);
	}
}

static void _tracker_timestamp_init(struct hfi1_dms *dms, union hfi1_dms_tracker *tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tracker);
	tracker->hdr.init_activity = dms->now;
	tracker->hdr.first_activity = dms->now;
	tracker->hdr.last_activity = dms->now;
	tracker->hdr.remote_status_pending = false;
}

static void _tracker_timestamp_first(struct hfi1_dms *dms, union hfi1_dms_tracker *tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tracker);
	tracker->hdr.first_activity = dms->now;
	tracker->hdr.last_activity = dms->now;
}

static void _tracker_timestamp_update(struct hfi1_dms *dms, union hfi1_dms_tracker *tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tracker);
	tracker->hdr.last_activity = dms->now;
}

static hfi1_dms_rift_key_t _rift_key_create(u16 const generation, u16 const index)
{
	DMS_BUG_ON(index >= HFI1_DMS_RIFT_IDX_SIZE);
	return (hfi1_dms_rift_key_t){.value = (((generation << HFI1_DMS_RIFT_IDX_BITS) & HFI1_DMS_RIFT_GEN_MASK) | index)};
}

static hfi1_dms_rift_key_t _rift_key_create_err(enum hfi1_dms_rift_err const err)
{
	return (hfi1_dms_rift_key_t){.value = (HFI1_DMS_RIFT_ERR_MASK | (u16)err)};
}

static u16 _rift_key_index(hfi1_dms_rift_key_t const key)
{
	return key.value & HFI1_DMS_RIFT_IDX_MASK;
}

static u16 _rift_key_generation(hfi1_dms_rift_key_t const key)
{
	return (key.value & HFI1_DMS_RIFT_GEN_MASK) >> HFI1_DMS_RIFT_IDX_BITS;
}

static enum hfi1_dms_xfer_type _rift_key_type(hfi1_dms_rift_key_t const key) {
	return (enum hfi1_dms_xfer_type)(key.value & HFI1_DMS_RIFT_KEY_TYPE_MASK);
}

static enum hfi1_dms_rift_err _rift_key_error(hfi1_dms_rift_key_t const key)
{
	return (enum hfi1_dms_rift_err)
		(((key.value & HFI1_DMS_RIFT_ERR_MASK) != 0) *
		 (key.value & ~HFI1_DMS_RIFT_ERR_MASK));
}

static enum hfi1_dms_xfer_type _rift_key_opposite_type(hfi1_dms_rift_key_t const key)
{
	enum hfi1_dms_xfer_type const type = _rift_key_type(key);

	return (enum hfi1_dms_xfer_type)(type ^ 1);
}

void _rift_init(struct hfi1_dms_rift * rift)
{
	for (u32 t = 0; t < HFI1_DMS_ARRAY_SIZE(rift->type); ++t) {
		rift->type[t].stack_top = 0;
		rift->type[t].waitlist.head = NULL;
		rift->type[t].waitlist.tail = NULL;
	}

	for (u16 i = 0; i < HFI1_DMS_ARRAY_SIZE(rift->arr); ++i) {
		hfi1_dms_rift_key_t const key = _rift_key_create(0, i);
		enum hfi1_dms_xfer_type const t = _rift_key_type(key);

		rift->type[t].stack[rift->type[t].stack_top++] = key;
		rift->arr[i] = NULL;
	}
}

static union hfi1_dms_tracker * _rift_search(struct hfi1_dms_rift *rift, hfi1_dms_rift_key_t const remote_rift_key)
{
	for (u16 i = 0; i < HFI1_DMS_ARRAY_SIZE(rift->arr); ++i) {
		if (!rift->arr[i]) continue;

		union hfi1_dms_tracker * tracker = rift->arr[i];
		if (tracker->hdr.remote_rift_key.value == remote_rift_key.value) {
			return tracker;
		}
	}
	return NULL;
}

static bool _rift_available(struct hfi1_dms_rift *rift, enum hfi1_dms_xfer_type const t)
{
	return (rift->type[t].stack_top > 0);
}

static int _rift_reserve(struct hfi1_dms_rift *rift, enum hfi1_dms_xfer_type const t, hfi1_dms_rift_key_t *key)
{
	DMS_BUG_ON(!rift);
	DMS_BUG_ON(!key);

	if (!_rift_available(rift, t)) {
		return -ENOSPC;
	}
	*key = rift->type[t].stack[--rift->type[t].stack_top];
	return 0;
}

static void _rift_assign(struct hfi1_dms_rift *rift, union hfi1_dms_tracker *tracker, hfi1_dms_rift_key_t const key)
{
	static u16 const sz = HFI1_DMS_ARRAY_SIZE(rift->arr);
	u16 const idx = _rift_key_index(key);

	DMS_BUG_ON(!rift);
	DMS_BUG_ON(!tracker);
	DMS_BUG_ON(sz <= idx);

	rift->arr[idx] = tracker;
}

static union hfi1_dms_tracker * _rift_lookup(struct hfi1_dms_rift *rift, hfi1_dms_rift_key_t const key)
{
	static u16 const sz = HFI1_DMS_ARRAY_SIZE(rift->arr);
	u16 const idx = _rift_key_index(key);

	DMS_BUG_ON(!rift);
	DMS_BUG_ON(sz <= idx);

	union hfi1_dms_tracker * tracker = rift->arr[idx];

	if ((tracker == NULL) || (tracker->hdr.local_rift_key.value != key.value))
		return NULL;

	return rift->arr[idx];
}

static void _rift_release(struct hfi1_dms_rift *rift, hfi1_dms_rift_key_t const key)
{
	DMS_BUG_ON(!rift);
	DMS_BUG_ON(_rift_key_error(key));

	static u16 const sz = HFI1_DMS_ARRAY_SIZE(rift->arr);
	u16 const idx = _rift_key_index(key);
	enum hfi1_dms_xfer_type const t = _rift_key_type(key);

	DMS_BUG_ON(!rift);
	DMS_BUG_ON(sz <= idx);
	DMS_BUG_ON(rift->type[t].stack_top == sz);

	rift->arr[idx] = NULL;
	rift->type[t].stack[rift->type[t].stack_top++] = key;
}

static void _rift_cancel(struct hfi1_dms_rift *rift, hfi1_dms_rift_key_t const key) {
	u16 const gen = _rift_key_generation(key);
	hfi1_dms_rift_key_t const new_key = _rift_key_create(gen+1, _rift_key_index(key));
	_rift_release(rift, new_key);
}

static void _rift_waitlist_add(struct hfi1_dms_rift *rift, enum hfi1_dms_xfer_type const t, struct hfi1_dms_dlist_element * waiter)
{
	DMS_BUG_ON(!rift);
	DMS_BUG_ON(!waiter);

	hfi1_dms_impl_dlist_append(&rift->type[t].waitlist, waiter);
}

static struct hfi1_dms_dlist_element * _rift_waitlist_pop(struct hfi1_dms_rift *rift, enum hfi1_dms_xfer_type const t)
{
	DMS_BUG_ON(!rift);
	return hfi1_dms_impl_dlist_pop(&rift->type[t].waitlist);
}

static struct hfi1_dms_dlist_element * _rift_waitlist_peek(struct hfi1_dms_rift *rift, enum hfi1_dms_xfer_type const t)
{
	DMS_BUG_ON(!rift);
	return rift->type[t].waitlist.head;
}

static struct hfi1_dms_sdma_tracker * _sdma_waitlist_peek(struct hfi1_dms *dms)
{
	DMS_BUG_ON(!dms);
	return (struct hfi1_dms_sdma_tracker *) dms->sdma_waiters.waitlist.head;
}

static struct hfi1_dms_sdma_tracker * _sdma_waitlist_next(struct hfi1_dms *dms)
{
	DMS_BUG_ON(!dms);

	struct hfi1_dms_dlist_element * waiter = hfi1_dms_impl_dlist_pop(&dms->sdma_waiters.waitlist);
	if (waiter) {
		hfi1_dms_impl_dlist_push(&dms->trackers.free, waiter);
		return _sdma_waitlist_peek(dms);
	}
	return NULL;
}

static int _sdma_waitlist_add(struct hfi1_dms *dms, struct hfi1_dms_sdma_parameters const * parameters) {
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!parameters);

	struct hfi1_dms_sdma_tracker * waiter = (struct hfi1_dms_sdma_tracker *) hfi1_dms_impl_tracker_new(dms);
	if (!waiter) {
		return -ENOMEM;
	}
	waiter->parameters = *parameters;
	
	hfi1_dms_impl_dlist_append(&dms->sdma_waiters.waitlist, (struct hfi1_dms_dlist_element *)waiter);
	return 0;
}

static void _sdma_waitlist_poll(struct hfi1_dms *dms) {
	DMS_BUG_ON(!dms);
	struct hfi1_dms_sdma_tracker * waiter = _sdma_waitlist_peek(dms);
	while (waiter) {
		int ret = hfi1_dms_sdma_send(dms, &waiter->parameters);
		waiter = ret == 0 ? _sdma_waitlist_next(dms) : NULL;
	}
}

static int hfi1_dms_impl_inject_read_response_small(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker *tx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tx_tracker);

	union hfi1_dms_cmd_read_response_small const cmd =
			hfi1_dms_cmd_read_response_small_make(dms, tx_tracker->read.access->mr, tx_tracker->xfer_start_byte_offset,
				tx_tracker->total_payload, tx_tracker->hdr.remote_lid, tx_tracker->read.start.rx_id, tx_tracker->hdr.remote_rift_key, tx_tracker->hdr.local_rift_key);

	return hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
}

static int _dms_tx_rift_continue_read_start(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker *tx_tracker)
{
	int ret = 0;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tx_tracker);

	hfi1_dms_rift_key_t const local_rift_key = tx_tracker->hdr.local_rift_key;
	DMS_BUG_ON(_rift_key_error(local_rift_key));

	if (_rift_lookup(&dms->tx_rift, local_rift_key) == NULL) {
		dd_dev_warn(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", local_rift_key.value, _rift_key_generation(local_rift_key), _rift_key_index(local_rift_key));
		return 0;
	}

	DMS_BUG_ON(_rift_lookup(&dms->tx_rift, local_rift_key) != (union hfi1_dms_tracker *)tx_tracker);

	_tracker_timestamp_update(dms, (union hfi1_dms_tracker *)tx_tracker);

	if (tx_tracker->total_payload <= 16) {
		return hfi1_dms_impl_inject_read_response_small(dms, tx_tracker);
	}

	struct hfi1_dms_sdma_parameters const sdma_parameters = {
		.tx_tracker = tx_tracker,
		.mr = tx_tracker->read.access->mr,
		.page_offset = tx_tracker->xfer_start_byte_offset + tx_tracker->read.start.head_misalignment,
		.nbytes = tx_tracker->read.start.size_qw << 3,
		.tid_info = tx_tracker->read.start.tid_info,
		.sdma_type = HFI1_DMS_SDMA_TYPE_START,
		.rx_id = tx_tracker->read.start.rx_id,
		.include_fixup_data = tx_tracker->read.start.include_fixup_data,
	};

	if (_sdma_waitlist_peek(dms)) {
		ret = _sdma_waitlist_add(dms, &sdma_parameters);
		_sdma_waitlist_poll(dms);
	} else if (hfi1_dms_sdma_send(dms, &sdma_parameters) < 0) {
		ret = _sdma_waitlist_add(dms, &sdma_parameters);
	}
	
	return ret;
}

static int hfi1_dms_impl_inject_write_start(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker *tx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tx_tracker);

	union hfi1_dms_proto_cmd_write_start const cmd =
		hfi1_dms_proto_cmd_write_start_make(dms, tx_tracker, tx_tracker->hdr.remote_lid, tx_tracker->hdr.local_rift_key,
			tx_tracker->total_payload, tx_tracker->write.dms_key, tx_tracker->write.rx_offset,
			tx_tracker->write.flags, tx_tracker->write.imm_data);

		return hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
}

static int _dms_tx_rift_continue_write_data(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker *tx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tx_tracker);

	hfi1_dms_rift_key_t const local_rift_key = tx_tracker->hdr.local_rift_key;
	DMS_BUG_ON(_rift_key_error(local_rift_key));

	if (_rift_lookup(&dms->tx_rift, local_rift_key) == NULL) {
		dd_dev_warn(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", local_rift_key.value, _rift_key_generation(local_rift_key), _rift_key_index(local_rift_key));
		return 0;
	}

	DMS_BUG_ON(_rift_lookup(&dms->tx_rift, local_rift_key) != (union hfi1_dms_tracker *)tx_tracker);

	_tracker_timestamp_first(dms, (union hfi1_dms_tracker *)tx_tracker);

	return hfi1_dms_impl_inject_write_start(dms, tx_tracker);
}

static int _dms_tx_rift_poll(struct hfi1_dms *dms, enum hfi1_dms_xfer_type const t)
{
	int ret;
	struct hfi1_dms_dlist_element *waiter;
	struct hfi1_dms_tx_tracker *tx_tracker;

	struct hfi1_dms_rift *tx_rift = &dms->tx_rift;

	if (!_rift_available(tx_rift, t)) {
		return 0;
	}

	waiter = _rift_waitlist_peek(tx_rift, t);
	if (!waiter) {
		return -ENOENT;
	}

	tx_tracker = container_of(waiter, struct hfi1_dms_tx_tracker, hdr.dlist);

	ret = _rift_reserve(tx_rift, t, &tx_tracker->hdr.local_rift_key);
	DMS_BUG_ON(ret < 0);

	_rift_assign(tx_rift, (union hfi1_dms_tracker *)tx_tracker, tx_tracker->hdr.local_rift_key);

	if (tx_tracker->op == HFI1_DMS_TX_TRACKER_OP_RDMA_READ) {
		ret = _dms_tx_rift_continue_read_start(dms, tx_tracker);
		if (ret < 0) {
			goto err;
		}
	} else { // HFI1_DMS_RX_TRACKER_OP_RDMA_WRITE
		ret = _dms_tx_rift_continue_write_data(dms, tx_tracker);
		if (ret < 0) {
			goto err;
		}
	}

	_rift_waitlist_pop(tx_rift, t);
	return 0;

err:
	_rift_release(tx_rift, tx_tracker->hdr.local_rift_key);
	tx_tracker->hdr.local_rift_key = _rift_key_create_err(HFI1_DMS_RIFT_ERR_KEY_NOT_SET);
	return ret;
}


int hfi1_dms_write_data(struct hfi1_dms *dms, u32 dest_lid, union hfi1_dms_key dms_key, u64 rx_offset,
			u32 size, struct hfi1_dms_mr *mr, u64 mr_offset, u16 flags, u64 imm_data,
			struct hfi1_dms_tracker_completion const completion)
{
	int ret;
	u64 byte_offset_from_first_page;
	struct hfi1_dms_tx_tracker * tx_tracker;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(mr == NULL);
	DMS_BUG_ON(dest_lid == 0);

	ret = calculate_mr_page_offset(dms, mr, mr_offset, size, &byte_offset_from_first_page);
	if (ret < 0) {
		goto err;
	}

	tx_tracker = hfi1_dms_impl_tx_tracker_write_new(dms, size, byte_offset_from_first_page, dest_lid,
			mr, mr_offset, flags, imm_data, &completion, dms_key, rx_offset);
	if (!tx_tracker) {
		ret = -ENOMEM;
		goto err;
	}

	ret = _rift_reserve(&dms->tx_rift, HFI1_DMS_XFER_TYPE_INITIATOR, &tx_tracker->hdr.local_rift_key);
	if (ret < 0) {
		_rift_waitlist_add(&dms->tx_rift, HFI1_DMS_XFER_TYPE_INITIATOR, &tx_tracker->hdr.dlist);
		return 0; // try again later
	}
	_rift_assign(&dms->tx_rift, (union hfi1_dms_tracker *)tx_tracker, tx_tracker->hdr.local_rift_key);

	ret = _dms_tx_rift_continue_write_data(dms, tx_tracker);
	if (ret < 0) {
		goto err2;
	}

	// Successfully started rdma write bulk transfer operation
	return 0;

err2:
	_rift_release(&dms->tx_rift, tx_tracker->hdr.local_rift_key);
	hfi1_dms_impl_tx_tracker_free(dms, tx_tracker);
err:
	// Unable to start rdma write bulk transfer operation
	return ret;
}

static union hfi1_dms_cmd_nack hfi1_dms_cmd_nack_make(struct hfi1_dms *dms, enum hfi1_dms_msg_type msg_type, enum hfi1_dms_err_type err_type, u32 dlid, hfi1_dms_rift_key_t rift_key)
{
	DMS_BUG_ON(!dms);

	union hfi1_dms_cmd_nack * tmpl;
	union hfi1_dms_cmd_nack cmd;
	int i;
	static int const cmd_len_qws = sizeof(cmd) / sizeof(u64);

	tmpl = (union hfi1_dms_cmd_nack *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_NACK];
	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}
	cmd.info.err_type = err_type;
	cmd.info.msg_type = msg_type;
	cmd.info.rift_key = rift_key;
	cmd.tail_flit = 0;
	// remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);
	return cmd;
}

static void _inject_nack(struct hfi1_dms *dms, enum hfi1_dms_msg_type msg_type, enum hfi1_dms_err_type reason, u32 dlid, hfi1_dms_rift_key_t rift_key)
{
	union hfi1_dms_cmd_nack nack_cmd = hfi1_dms_cmd_nack_make(dms, msg_type, reason, dlid, rift_key);
	int ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&nack_cmd);
	if (ret < 0) {
		dd_dev_err(dms->dd, "Failed to send or enqueue nack packet! ret = %d\n", ret);
	}
}

static union hfi1_dms_cmd_status hfi1_dms_cmd_status_make(struct hfi1_dms *dms, u32 dlid, hfi1_dms_rift_key_t rx_rift_key, hfi1_dms_rift_key_t tx_rift_key, enum hfi1_dms_status_type type, u32 data)
{
	DMS_BUG_ON(!dms);

	union hfi1_dms_cmd_status *tmpl;
	union hfi1_dms_cmd_status cmd;
	int i;
	static int const cmd_len_qws = sizeof(cmd) / sizeof(u64);

	tmpl = (union hfi1_dms_cmd_status *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_STATUS];
	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}
	cmd.info.rx_rift_key = rx_rift_key;
	cmd.info.tx_rift_key = tx_rift_key;
	cmd.info.type = type;
	cmd.info.data = data;
	cmd.tail_flit = 0;

	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);
	return cmd;
}

static int hfi1_dms_impl_inject_status(struct hfi1_dms *dms, u32 dlid, hfi1_dms_rift_key_t rx_rift_key, hfi1_dms_rift_key_t tx_rift_key, enum hfi1_dms_status_type type, u32 data)
{
	DMS_BUG_ON(!dms);

	union hfi1_dms_cmd_status const cmd =
		hfi1_dms_cmd_status_make(dms, dlid, rx_rift_key, tx_rift_key, type, data);

	return hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
}

static union hfi1_dms_cmd_read_start hfi1_dms_cmd_read_start_make(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker const * const rx_tracker, s32 tid_set, u32 tid_set_nbytes)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);

	int i;
	union hfi1_dms_cmd_read_start * tmpl;
	union hfi1_dms_cmd_read_start cmd;
	static int const cmd_len_qws = sizeof(cmd) / sizeof(u64);

	tmpl = (union hfi1_dms_cmd_read_start *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_START];
	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}

	cmd.info.size = rx_tracker->total_payload;
	cmd.info.dms_key = rx_tracker->read.dms_key;
	cmd.info.key_offset_or_vaddr = rx_tracker->sbuf_start_offset;
	cmd.info.tid_info = 0;
	cmd.info.flags = rx_tracker->read.flags;
	cmd.info.include_fixup_data = rx_tracker->head_misalignment || rx_tracker->tail_misalignment;
	cmd.info.head_misalignment = rx_tracker->head_misalignment;
	cmd.info.imm_data = rx_tracker->read.imm_data;
	cmd.tail_flit = 0;

	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, rx_tracker->hdr.remote_lid);
	_dms_return_rx_set(&cmd.info.bth[0], dms->rcd_data->ctxt); // For now rcd_data, but could be rcd_data[i] in the future
	cmd.info.bth[2] = (rx_tracker->hdr.local_rift_key.value << 16) | ((tid_set_nbytes >> 3) & 0xffff);

	return cmd;
}

union hfi1_dms_cmd_read_response_small hfi1_dms_cmd_read_response_small_make(struct hfi1_dms *dms,
			struct hfi1_dms_mr * mr, u64 page_offset, u32 size, u32 dlid, u16 rx_id, hfi1_dms_rift_key_t rx_rift_key, hfi1_dms_rift_key_t tx_rift_key)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!mr);

	int i;
	union hfi1_dms_cmd_read_response_small * tmpl;
	union hfi1_dms_cmd_read_response_small cmd;
	static int const cmd_len_qws = sizeof(cmd) / sizeof(u64);

	tmpl = (union hfi1_dms_cmd_read_response_small *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_RESPONSE_SMALL];
	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}
	_dms_destqp_rx_set(&cmd.info.bth[0], rx_id);

	if (size <= 8) {
		cmd.info.data[0] = hfi1_dms_impl_slow_read_from_user(mr, page_offset, size);
		cmd.info.data[1] = 0;
	} else {
		cmd.info.data[0] = hfi1_dms_impl_slow_read_from_user(mr, page_offset, sizeof(u64));
		cmd.info.data[1] = hfi1_dms_impl_slow_read_from_user(mr, page_offset + sizeof(u64), size - sizeof(u64));
	}

	cmd.info.tx_rift_key = tx_rift_key;
	cmd.info.rx_rift_key = rx_rift_key;
	cmd.tail_flit = 0;
	// remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi1_dms_impl_pbc_dlid_set(&cmd.pbc, dlid);
	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);

	return cmd;
}

static union hfi1_dms_proto_cmd_data_request_small hfi1_dms_proto_cmd_data_request_small_make(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker const * const rx_tracker, u32 dlid, hfi1_dms_rift_key_t rx_rift_key)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(rx_tracker->total_payload > 16);
	DMS_BUG_ON(rx_tracker->op != HFI1_DMS_RX_TRACKER_OP_RDMA_WRITE);

	union hfi1_dms_proto_cmd_data_request_small * tmpl;
	union hfi1_dms_proto_cmd_data_request_small cmd;
	int i;
	int cmd_len_qws;

	tmpl = (union hfi1_dms_proto_cmd_data_request_small *)
		&dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_REQUEST_SMALL];
	cmd_len_qws = sizeof(cmd) / sizeof(u64);
	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}
	_dms_return_rx_set(&cmd.info.bth[0], dms->rcd_data->ctxt);
	cmd.info.tx_rift_key = rx_tracker->hdr.remote_rift_key;
	cmd.info.offset = rx_tracker->sbuf_offset;
	cmd.info.size = (u16) rx_tracker->total_payload;
	cmd.info.rx_rift_key = rx_rift_key;
	cmd.tail_flit = 0;
	// remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);
	return cmd;
}

union hfi1_dms_proto_cmd_write_start hfi1_dms_proto_cmd_write_start_make(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker *tx_tracker,
		u32 dlid, hfi1_dms_rift_key_t tx_rift_key, u32 size, union hfi1_dms_key dms_key, u64 key_offset_or_vaddr, u16 flags, u64 imm_data)
{
	union hfi1_dms_proto_cmd_write_start * tmpl;
	union hfi1_dms_proto_cmd_write_start cmd;
	u64 i;

	static u64 const cmd_len_qws = sizeof(cmd) / sizeof(u64);
	
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tx_tracker);

	tmpl = (union hfi1_dms_proto_cmd_write_start *)
		&dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_WRITE_START];

	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}

	cmd.info.dms_key = dms_key;
	cmd.info.key_offset_or_vaddr = key_offset_or_vaddr;
	cmd.info.size = size;
	cmd.info.imm_data = imm_data;
	cmd.tail_flit = 0;
	// any remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);
	cmd.info.bth[2] = (tx_rift_key.value << 16) | (u32)flags;

	return cmd;
}

static union hfi1_dms_proto_cmd_ack hfi1_dms_proto_cmd_ack_make(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker, u32 dlid, hfi1_dms_rift_key_t tx_rift_key, u16 flags, u64 imm_data)
{
	union hfi1_dms_proto_cmd_ack * tmpl;
	union hfi1_dms_proto_cmd_ack cmd;
	int i;

	DMS_BUG_ON(dms == NULL);

	tmpl = (union hfi1_dms_proto_cmd_ack *)
		&dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_ACK];

	for (i = 0; i < 5; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}

	cmd.info.tx_rift_key = tx_rift_key;
	cmd.info.flags = flags;
	cmd.info.imm_data = imm_data;
	cmd.tail_flit = 0;
	// remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi1_dms_impl_pbc_dlid_set(&cmd.pbc, dlid);
	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);

	return cmd;
}

static int hfi1_dms_impl_inject_data_request_small(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(rx_tracker->total_payload > 16);

	union hfi1_dms_proto_cmd_data_request_small small_cmd;
	int ret;

	small_cmd = hfi1_dms_proto_cmd_data_request_small_make(dms, rx_tracker, rx_tracker->hdr.remote_lid, rx_tracker->hdr.local_rift_key);
	ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&small_cmd);
	if (ret == 0) {
		rx_tracker->payload_requested += rx_tracker->total_payload;
		rx_tracker->sbuf_offset += rx_tracker->total_payload;
		rx_tracker->rbuf_offset += rx_tracker->total_payload;		
	}
	return ret;
}

static int hfi1_dms_impl_inject_data_request_fixup(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(rx_tracker->total_payload <= 16);

	union hfi1_dms_proto_cmd_data_request_fixup cmd;
	int ret;

	cmd = hfi1_dms_proto_cmd_data_request_fixup_make(dms, rx_tracker, rx_tracker->hdr.remote_lid, rx_tracker->hdr.remote_rift_key, rx_tracker->hdr.local_rift_key);
	ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
	if (ret == 0) {
		rx_tracker->payload_requested += rx_tracker->head_misalignment;	
		rx_tracker->rbuf_offset += rx_tracker->head_misalignment;
		rx_tracker->sbuf_offset += rx_tracker->head_misalignment;
		rx_tracker->payload_requested += rx_tracker->tail_misalignment;	
	}
	return ret;
}

static int hfi1_dms_impl_inject_read_start_small(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(rx_tracker->total_payload > 16);

	union hfi1_dms_cmd_read_start cmd;
	int ret;

	cmd = hfi1_dms_cmd_read_start_make(dms, rx_tracker, -1, 0);
	ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
	if (ret == 0) {
		rx_tracker->payload_requested += rx_tracker->total_payload;
		rx_tracker->sbuf_offset += rx_tracker->total_payload;
		rx_tracker->rbuf_offset += rx_tracker->total_payload;
	}
	return ret;
}

static int hfi1_dms_impl_inject_read_start(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker, u32 tid_set)
{
	u32 tid_info;
	union hfi1_dms_cmd_read_start cmd;
	u64 tid_set_nbytes;
	int ret;

	DMS_BUG_ON(rx_tracker->payload_requested > 0);

	if (rx_tracker->head_misalignment || rx_tracker->tail_misalignment) {
		// have to adjust _first_ otherwise our _tidset_enable() will fail if we are unaligned
		rx_tracker->sbuf_offset += rx_tracker->head_misalignment;
		rx_tracker->rbuf_offset += rx_tracker->head_misalignment;

		// must also correctly set the "payload requested" because, from tidset perspective,
		// we have requested these misaligned bytes by setting "include_fixup_data" in the packet
		rx_tracker->payload_requested = rx_tracker->head_misalignment + rx_tracker->tail_misalignment;

		_tidset_enable(dms, tid_set, rx_tracker, &tid_info, &tid_set_nbytes);

		cmd = hfi1_dms_cmd_read_start_make(dms, rx_tracker, tid_set, tid_set_nbytes);
		cmd.info.tid_info = tid_info;
		ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
		if (ret == 0) {
			rx_tracker->payload_requested += tid_set_nbytes;
			rx_tracker->sbuf_offset += tid_set_nbytes;
			rx_tracker->rbuf_offset += tid_set_nbytes;
		} else {
			rx_tracker->sbuf_offset -= rx_tracker->head_misalignment;
			rx_tracker->rbuf_offset -= rx_tracker->head_misalignment;
			rx_tracker->payload_requested = 0;
			_tidset_reset(dms, tid_set, HFI1_DMS_TIDSET_STATE_FREE);
		}
		return ret;
	}

	_tidset_enable(dms, tid_set, rx_tracker, &tid_info, &tid_set_nbytes);

	cmd = hfi1_dms_cmd_read_start_make(dms, rx_tracker, tid_set, tid_set_nbytes);
	cmd.info.tid_info = tid_info;
	ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
	if (ret == 0) {
		rx_tracker->payload_requested += tid_set_nbytes;
		rx_tracker->sbuf_offset += tid_set_nbytes;
		rx_tracker->rbuf_offset += tid_set_nbytes;
	} else {
		_tidset_reset(dms, tid_set, HFI1_DMS_TIDSET_STATE_FREE);
	}
	return ret;
}

static void _dms_tidset_waiter_add(struct hfi1_dms *dms, enum hfi1_dms_tidset_waiter_type type, struct hfi1_dms_rx_tracker *rx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(type >= HFI1_DMS_TIDSET_WAITER_TYPE_COUNT);
	DMS_BUG_ON(_rift_key_error(rx_tracker->hdr.local_rift_key));

	static u64 const mask = HFI1_DMS_ARRAY_SIZE(dms->tidset_waiters[type].ring) - 1;
	u64 const idx = dms->tidset_waiters[type].tail & mask;
	dms->tidset_waiters[type].ring[idx] = rx_tracker->hdr.local_rift_key;
	dms->tidset_waiters[type].tail += 1;
}

static struct hfi1_dms_rx_tracker * _dms_tidset_waiter_peek(struct hfi1_dms *dms, enum hfi1_dms_tidset_waiter_type type)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(type >= HFI1_DMS_TIDSET_WAITER_TYPE_COUNT);

	if (dms->tidset_waiters[type].tail == dms->tidset_waiters[type].head)
		return NULL;

	static u64 const mask = HFI1_DMS_ARRAY_SIZE(dms->tidset_waiters[type].ring) - 1;
	u64 const idx = dms->tidset_waiters[type].head & mask;
	return (struct hfi1_dms_rx_tracker *) _rift_lookup(&dms->rx_rift, dms->tidset_waiters[type].ring[idx]);
}

static struct hfi1_dms_rx_tracker * _dms_tidset_waiter_next(struct hfi1_dms *dms, enum hfi1_dms_tidset_waiter_type type)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(type >= HFI1_DMS_TIDSET_WAITER_TYPE_COUNT);
	DMS_BUG_ON(dms->tidset_waiters[type].head >= dms->tidset_waiters[type].tail);

	dms->tidset_waiters[type].head += 1;
	return _dms_tidset_waiter_peek(dms, type);
}

static struct hfi1_dms_rx_tracker * _dms_tidset_waiter_head(struct hfi1_dms *dms, enum hfi1_dms_tidset_waiter_type type)
{
	return _dms_tidset_waiter_peek(dms, type);
}

static struct hfi1_dms_rx_tracker * _dms_tidset_waiter_tail(struct hfi1_dms *dms, enum hfi1_dms_tidset_waiter_type type)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(type >= HFI1_DMS_TIDSET_WAITER_TYPE_COUNT);

	if (dms->tidset_waiters[type].tail == dms->tidset_waiters[type].head)
		return NULL;

	static u64 const mask = HFI1_DMS_ARRAY_SIZE(dms->tidset_waiters[type].ring) - 1;
	u64 const idx = (dms->tidset_waiters[type].tail - 1) & mask;
	return (struct hfi1_dms_rx_tracker *) _rift_lookup(&dms->rx_rift, dms->tidset_waiters[type].ring[idx]);
}

static void _dms_tidset_waiters_poll(struct hfi1_dms *dms)
{
	struct hfi1_dms_rx_tracker *rx_tracker;
	u32 tid_set;
	int ret;

	DMS_BUG_ON(!dms);

	//
	// POLICY DECISION: waitlist priority = HFI1_DMS_TIDSET_WAITER_TYPE_DATA
	//
	// Which tidset waitlist should be preferentially drained?
	//
	// - Prefer HFI1_DMS_TIDSET_WAITER_TYPE_DATA to complete large (>1 tidset)
	//   READ transfers, and any WRITE transfers, before starting new READ
	//   transfers; perhaps introducing network congestion between the two devices
	//
	// - Prefer HFI1_DMS_TIDSET_WAITER_TYPE_READ to start new READ transfers
	//   before completing large (>1 tidset) READ transfers and before
	//   completing any WRITE transfers
	//
	
	rx_tracker = _dms_tidset_waiter_peek(dms, HFI1_DMS_TIDSET_WAITER_TYPE_DATA);
	while (rx_tracker) {
		if (_tidset_idx_peek(dms, &tid_set) < 0) break;

		ret = hfi1_dms_impl_make_data_request(dms, rx_tracker, tid_set);
		if (ret != 0) break;

		_tidset_idx_reserve(dms, tid_set);

		if (rx_tracker->payload_requested == rx_tracker->total_payload) {
			rx_tracker = _dms_tidset_waiter_next(dms, HFI1_DMS_TIDSET_WAITER_TYPE_DATA);
		}
	}

	rx_tracker = _dms_tidset_waiter_peek(dms, HFI1_DMS_TIDSET_WAITER_TYPE_READ);
	while (rx_tracker) {
		if (_tidset_idx_peek(dms, &tid_set) < 0) break;

		_tracker_timestamp_first(dms, (union hfi1_dms_tracker *)rx_tracker);
		ret = hfi1_dms_impl_inject_read_start(dms, rx_tracker, tid_set);
		if (ret != 0) break;

		_tidset_idx_reserve(dms, tid_set);

		rx_tracker = _dms_tidset_waiter_next(dms, HFI1_DMS_TIDSET_WAITER_TYPE_READ);
	}
}

static void _tidset_free_then_poll_waiters(struct hfi1_dms *dms, u32 tid_set)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(tid_set >= HFI1_DMS_TID_SET_IDX_COUNT);

	// release the tidset index to the free stack
	_tidset_idx_release(dms, tid_set);

	// set the tidset state to 'free' - but do not clear the tid hardware
	dms->read_requests[tid_set].state = HFI1_DMS_TIDSET_STATE_FREE;

	// allow any tidset waiters to use this tidset
	_dms_tidset_waiters_poll(dms);

	if (dms->read_requests[tid_set].state == HFI1_DMS_TIDSET_STATE_FREE) {
		// no tidset waiter acquired this tidset; reset the tid hardware
		_tidset_reset(dms, tid_set, HFI1_DMS_TIDSET_STATE_FREE);
	}
}

static int _dms_rx_rift_continue_read_data(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);

	hfi1_dms_rift_key_t const local_rift_key = rx_tracker->hdr.local_rift_key;
	DMS_BUG_ON(_rift_key_error(local_rift_key));

	if (_rift_lookup(&dms->rx_rift, local_rift_key) == NULL) {
		dd_dev_warn(dms->dd, "(%d) Ignore invalid rx rift key 0x%04hx (%hu %hu)\n", __LINE__, local_rift_key.value, _rift_key_generation(local_rift_key), _rift_key_index(local_rift_key));
		return 0;
	}

	DMS_BUG_ON(_rift_lookup(&dms->rx_rift, local_rift_key) != (union hfi1_dms_tracker *)rx_tracker);

	if (rx_tracker->total_payload <= 16) {
		_tracker_timestamp_first(dms, (union hfi1_dms_tracker *)rx_tracker);
		return hfi1_dms_impl_inject_read_start_small(dms, rx_tracker);
	}

	_dms_tidset_waiter_add(dms, HFI1_DMS_TIDSET_WAITER_TYPE_READ, rx_tracker);
	_dms_tidset_waiters_poll(dms);

	return 0;
}

static int _dms_rx_rift_continue_write_start(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker)
{
	int ret;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);

	hfi1_dms_rift_key_t const local_rift_key = rx_tracker->hdr.local_rift_key;
	DMS_BUG_ON(_rift_key_error(local_rift_key));

	if (_rift_lookup(&dms->rx_rift, local_rift_key) == NULL) {
		dd_dev_warn(dms->dd, "(%d) Ignore invalid rx rift key 0x%04hx (%hu %hu)\n", __LINE__, local_rift_key.value, _rift_key_generation(local_rift_key), _rift_key_index(local_rift_key));
		return 0;
	}

	DMS_BUG_ON(_rift_lookup(&dms->rx_rift, local_rift_key) != (union hfi1_dms_tracker *)rx_tracker);
	DMS_BUG_ON(_rift_key_error(rx_tracker->hdr.remote_rift_key));

	_tracker_timestamp_first(dms, (union hfi1_dms_tracker *)rx_tracker);

	if (rx_tracker->total_payload <= 16) {
		return hfi1_dms_impl_inject_data_request_small(dms, rx_tracker);
	}

	if (rx_tracker->head_misalignment || rx_tracker->tail_misalignment) {
		dd_dev_dbg(dms->dd, "rx tracker has head misalignment %u and tail misalignment %u.\n", rx_tracker->head_misalignment, rx_tracker->tail_misalignment);
		ret = hfi1_dms_impl_inject_data_request_fixup(dms, rx_tracker);
		if (ret < 0) {
			dd_dev_err(dms->dd, "Failed to send or enqueue data request fixup\n");
			return ret;
		}
	}

	_dms_tidset_waiter_add(dms, HFI1_DMS_TIDSET_WAITER_TYPE_DATA, rx_tracker);
	_dms_tidset_waiters_poll(dms);

	return 0;
}


static int _dms_rx_rift_poll(struct hfi1_dms *dms, enum hfi1_dms_xfer_type const t)
{
	int ret;
	struct hfi1_dms_dlist_element *waiter;
	struct hfi1_dms_rx_tracker *rx_tracker;

	if (!_rift_available(&dms->rx_rift, t)) {
		return 0;
	}

	waiter = _rift_waitlist_peek(&dms->rx_rift, t);
	if (!waiter) {
		return -ENOENT;
	}

	rx_tracker = container_of(waiter, struct hfi1_dms_rx_tracker, hdr.dlist);

	ret = _rift_reserve(&dms->rx_rift, t, &rx_tracker->hdr.local_rift_key);
	DMS_BUG_ON(ret < 0);

	_rift_assign(&dms->rx_rift, (union hfi1_dms_tracker *)rx_tracker, rx_tracker->hdr.local_rift_key);

	if (rx_tracker->op == HFI1_DMS_RX_TRACKER_OP_RDMA_READ) {
		ret = _dms_rx_rift_continue_read_data(dms, rx_tracker);
		if (ret < 0) {
			goto err;
		}
	} else { // HFI1_DMS_RX_TRACKER_OP_RDMA_WRITE
		ret = _dms_rx_rift_continue_write_start(dms, rx_tracker);
		if (ret < 0) {
			goto err;
		}
	}

	_rift_waitlist_pop(&dms->rx_rift, t);
	return 0;

err:
	_rift_release(&dms->rx_rift, rx_tracker->hdr.local_rift_key);
	rx_tracker->hdr.local_rift_key = _rift_key_create_err(HFI1_DMS_RIFT_ERR_KEY_NOT_SET);
	return ret;
}


int hfi1_dms_read_data(struct hfi1_dms *dms, u32 src_lid, union hfi1_dms_key dms_key, u64 key_offset_or_vaddr, u32 size, struct hfi1_dms_mr *mr, u64 mr_offset, u16 flags, u64 imm_data, struct hfi1_dms_tracker_completion const completion)
{
	int ret;
	u64 start, end;
	u64 starting_rbuf_offset;
	struct hfi1_dms_rx_tracker *rx_tracker;

	dms_trace(dms_read_data, dms, src_lid, dms_key, key_offset_or_vaddr, size, mr, mr_offset);

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!mr);
	DMS_BUG_ON(src_lid == 0);

	start = dms_rdtsc();
	dms->counters.sending_first_rr = ktime_get();

	ret = calculate_mr_page_offset(dms, mr, mr_offset, size, &starting_rbuf_offset);
	if (ret < 0) {
		goto err;
	}

	rx_tracker = hfi1_dms_impl_rx_tracker_read_new(dms, size, key_offset_or_vaddr, dms_key, src_lid, mr, starting_rbuf_offset, flags, imm_data, &completion);
	if (rx_tracker == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	ret = _rift_reserve(&dms->rx_rift, HFI1_DMS_XFER_TYPE_INITIATOR, &rx_tracker->hdr.local_rift_key);
	if (ret < 0) {
		_rift_waitlist_add(&dms->rx_rift, HFI1_DMS_XFER_TYPE_INITIATOR, &rx_tracker->hdr.dlist);
	} else {
		_rift_assign(&dms->rx_rift, (union hfi1_dms_tracker *)rx_tracker, rx_tracker->hdr.local_rift_key);

		ret = _dms_rx_rift_continue_read_data(dms, rx_tracker);
		if (ret < 0) {
			goto err2;
		}
	}

	end = dms_rdtsc();
	dms->counters.rget += end - start;

	// Successfully started rdma read bulk transfer operation
	return 0;

err2:
	_rift_release(&dms->rx_rift, rx_tracker->hdr.local_rift_key);
	hfi1_dms_impl_rx_tracker_free(dms, rx_tracker);
err:
	// Unable to start rdma read bulk transfer operation
	return ret;
}

void hfi1_dms_impl_handle_read_response_small_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	union hfi1_dms_pkt_read_response_small *pkt = (union hfi1_dms_pkt_read_response_small *)hdr;
	struct hfi1_dms_rx_tracker *rx_tracker;

	hfi1_dms_rift_key_t const rx_rift_key = pkt->info.rx_rift_key;
	DMS_BUG_ON(_rift_key_error(rx_rift_key));

	rx_tracker = (struct hfi1_dms_rx_tracker *) _rift_lookup(&dms->rx_rift, rx_rift_key);
	if (!rx_tracker) {
		dd_dev_warn(dms->dd, "(%d) Ignore invalid rx rift key 0x%04hx (%hu %hu)\n", __LINE__, rx_rift_key.value, _rift_key_generation(rx_rift_key), _rift_key_index(rx_rift_key));
		return;
	}

	DMS_BUG_ON(rx_tracker->op != HFI1_DMS_RX_TRACKER_OP_RDMA_READ);

	_tracker_timestamp_update(dms, (union hfi1_dms_tracker *)rx_tracker);

	rx_tracker->hdr.remote_rift_key = pkt->info.tx_rift_key;

	if (rx_tracker->total_payload <= 8) {
		hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset, &pkt->info.data[0], rx_tracker->total_payload);
	} else {
		hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset, &pkt->info.data[0], sizeof(u64));
		hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset + sizeof(u64), &pkt->info.data[1], rx_tracker->total_payload - sizeof(u64));
	}
	
	rx_tracker->payload_remaining -= rx_tracker->total_payload;
	DMS_BUG_ON(rx_tracker->payload_remaining != 0);

	hfi1_dms_rx_tracker_handle_completion(dms, rx_tracker, 0, 1);
}

static void _tracker_rift_release(struct hfi1_dms *dms, union hfi1_dms_tracker *tracker, struct hfi1_dms_rift *rift)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tracker);
	DMS_BUG_ON(!rift);

	if (tracker->hdr.remote_status_pending) {
		dd_dev_dbg(dms->dd, "(%d) Completed tracker has a pending remote status response. Cancel local_rift_key %05hu\n", __LINE__, tracker->hdr.local_rift_key.value);
		_rift_cancel(rift, tracker->hdr.local_rift_key);
	} else {
		_rift_release(rift, tracker->hdr.local_rift_key);
	}
}

void hfi1_dms_rx_tracker_handle_completion(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker, int status, u32 do_ack)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(rx_tracker->payload_remaining != 0);
	DMS_BUG_ON(_rift_key_error(rx_tracker->hdr.local_rift_key));

	enum hfi1_dms_rx_tracker_op const op = rx_tracker->op;

	if (do_ack) {
		union hfi1_dms_proto_cmd_ack cmd;
		int ret;

		DMS_BUG_ON(_rift_key_error(rx_tracker->hdr.remote_rift_key));

		if (op == HFI1_DMS_RX_TRACKER_OP_RDMA_READ) {
			cmd = hfi1_dms_proto_cmd_ack_make(dms, rx_tracker, rx_tracker->hdr.remote_lid, rx_tracker->hdr.remote_rift_key, rx_tracker->read.flags, rx_tracker->read.imm_data);
		} else { // HFI1_DMS_RX_TRACKER_OP_RDMA_WRITE
			cmd = hfi1_dms_proto_cmd_ack_make(dms, rx_tracker, rx_tracker->hdr.remote_lid, rx_tracker->hdr.remote_rift_key, 0, 0);
		}

		ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
		if (ret < 0)
			dd_dev_err(dms->dd, "Failed to send or enqueue ACK packet\n");
	}

	if (op == HFI1_DMS_RX_TRACKER_OP_RDMA_READ) {
		rx_tracker->read.completion.fn(&rx_tracker->read.completion.cookie, status);
		_tracker_rift_release(dms, (union hfi1_dms_tracker *)rx_tracker, &dms->rx_rift);
		_dms_rx_rift_poll(dms, HFI1_DMS_XFER_TYPE_INITIATOR);
	} else { // HFI1_DMS_RX_TRACKER_OP_RDMA_WRITE
		access_xfer_end(dms, rx_tracker->write.access, rx_tracker->write.start.flags, rx_tracker->write.start.imm_data, 0);
		_tracker_rift_release(dms, (union hfi1_dms_tracker *)rx_tracker, &dms->rx_rift);
		_dms_rx_rift_poll(dms, HFI1_DMS_XFER_TYPE_TARGET);
	}

	hfi1_dms_impl_rx_tracker_free(dms, rx_tracker);
}

static void hfi1_dms_handle_data_start(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	union hfi1_dms_proto_pkt_data *data;
	struct hfi1_dms_read_request_state *read_request;
	struct hfi1_dms_rx_tracker *rx_tracker;
	u16 tid;
	u16 tid_set;
	u32 payload_qws;

	dms_trace(hfi1_dms_handle_data_start, dms, hdr);

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!hdr);

	tid = (hdr->kdeth[0] >> 16) & (BIT(10) - 1);
	tid_set = (tid / HFI1_DMS_TID_SET_SIZE);
	payload_qws = hfi1_dms_16b_data_payload_qws_get(hdr);

	read_request = &dms->read_requests[tid_set];
	if (read_request->state != HFI1_DMS_TIDSET_STATE_ENABLED) {
		dd_dev_dbg(dms->dd, "Stale data_start packet for not-enabled tid_set %u, dropping\n", tid_set);
		dms->read_requests[tid_set].disable_ts = dms->now; // reset disable timer?
		return;
	} else if (read_request->tid_set != tid_set) {
		dd_dev_warn(dms->dd, "Mismatched data_start packet for enabled tid_set %u, dropping\n", tid_set);
		return;
	}

	rx_tracker = read_request->rx_tracker;
	DMS_BUG_ON(!rx_tracker);

	_tracker_timestamp_update(dms, (union hfi1_dms_tracker *)rx_tracker);

	if (_rift_key_error(rx_tracker->hdr.remote_rift_key) == HFI1_DMS_RIFT_ERR_KEY_NOT_SET) {
		data = (union hfi1_dms_proto_pkt_data *)hdr;
		DMS_BUG_ON(_rift_key_error(data->info.tx_rift_key));

		rx_tracker->hdr.remote_rift_key = data->info.tx_rift_key;

		u64 const bytes_requested = rx_tracker->payload_requested;

		if (bytes_requested < rx_tracker->total_payload) {
			_dms_tidset_waiter_add(dms, HFI1_DMS_TIDSET_WAITER_TYPE_DATA, rx_tracker);
			_dms_tidset_waiters_poll(dms);
		}

		if ((rx_tracker->head_misalignment) || (rx_tracker->tail_misalignment)) {
			hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset, &data->info.head, sizeof(u64));
			rx_tracker->payload_remaining -= rx_tracker->head_misalignment;
			hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset + rx_tracker->total_payload - sizeof(u64), &data->info.tail, sizeof(u64));
			rx_tracker->payload_remaining -= rx_tracker->tail_misalignment;
		}
	}

	DMS_WARN_ON(read_request->remaining_qws < payload_qws);
	read_request->remaining_qws -= payload_qws;

	if (read_request->remaining_qws == 0) {
		rx_tracker->payload_remaining -= (read_request->total_requested_qws << 3);
		if (rx_tracker->payload_remaining == 0) {
			DMS_BUG_ON(_rift_key_error(rx_tracker->hdr.remote_rift_key));
			hfi1_dms_rx_tracker_handle_completion(dms, rx_tracker, 0, 1);
		}

		_tidset_free_then_poll_waiters(dms, read_request->tid_set);
	}
}

void hfi1_dms_handle_data(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	u64 start, end;
	struct hfi1_dms_read_request_state *read_request;
	struct hfi1_dms_rx_tracker *rx_tracker;
	u16 tid;
	u16 tid_set;
	u32 payload_qws;

	dms_trace(dms_handle_data, dms, hdr);

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!hdr);

	start = dms_rdtsc();

	tid = (hdr->kdeth[0] >> 16) & (BIT(10) - 1);
	tid_set = (tid / HFI1_DMS_TID_SET_SIZE);
	payload_qws = hfi1_dms_16b_data_payload_qws_get(hdr);

	read_request = &dms->read_requests[tid_set];
	if (read_request->state != HFI1_DMS_TIDSET_STATE_ENABLED) {
		dd_dev_dbg(dms->dd, "Stale data packet for not-enabled tid_set %u, dropping\n", tid_set);
		dms->read_requests[tid_set].disable_ts = dms->now; // reset disable timer?
		return;
	} else if (read_request->tid_set != tid_set) {
		dd_dev_err(dms->dd, "Mismatched data packet for enabled tid_set %u, dropping\n", tid_set);
		return;
	}

	rx_tracker = read_request->rx_tracker;
	DMS_BUG_ON(!rx_tracker);

	_tracker_timestamp_update(dms, (union hfi1_dms_tracker *)rx_tracker);

	DMS_WARN_ON(read_request->remaining_qws < payload_qws);
	read_request->remaining_qws -= payload_qws;

	if (read_request->remaining_qws == 0) {
		rx_tracker->payload_remaining -= (read_request->total_requested_qws << 3);
		if (rx_tracker->payload_remaining == 0) {
			DMS_BUG_ON(_rift_key_error(rx_tracker->hdr.remote_rift_key));
			hfi1_dms_rx_tracker_handle_completion(dms, rx_tracker, 0, 1);
		}
		_tidset_free_then_poll_waiters(dms, read_request->tid_set);
	}

	end = dms_rdtsc();
	dms->counters.handle_data += end - start;
}

void hfi1_dms_handle_data_fixup(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	union hfi1_dms_proto_pkt_data_fixup * fixup;
	struct hfi1_dms_rx_tracker *rx_tracker;
	u64 head;
	u64 tail;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(hdr == NULL);

	fixup = (union hfi1_dms_proto_pkt_data_fixup *)hdr;
	head = fixup->info.head;
	tail = fixup->info.tail;

	hfi1_dms_rift_key_t const rx_rift_key = fixup->info.rx_rift_key;
	DMS_BUG_ON(_rift_key_error(rx_rift_key));

	rx_tracker = (struct hfi1_dms_rx_tracker *) _rift_lookup(&dms->rx_rift, rx_rift_key);
	if (!rx_tracker) {
		dd_dev_warn(dms->dd, "(%d) Ignore invalid rx rift key 0x%04hx (%hu %hu)\n", __LINE__, rx_rift_key.value, _rift_key_generation(rx_rift_key), _rift_key_index(rx_rift_key));
		return;
	}

	DMS_BUG_ON(rx_tracker->total_payload <= 16);
	DMS_BUG_ON((rx_tracker->head_misalignment == 0) && (rx_tracker->tail_misalignment == 0));

	_tracker_timestamp_update(dms, (union hfi1_dms_tracker *)rx_tracker);

	hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset, &head, sizeof(head));
	hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset + rx_tracker->total_payload - sizeof(u64), &tail, sizeof(tail));

	rx_tracker->payload_remaining -= (rx_tracker->head_misalignment + rx_tracker->tail_misalignment);

	if (rx_tracker->payload_remaining == 0) {
		hfi1_dms_rx_tracker_handle_completion(dms, rx_tracker, 0, 1);
	}
}

void hfi1_dms_impl_handle_data_small_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	union hfi1_dms_proto_pkt_data_small * small;
	struct hfi1_dms_rx_tracker *rx_tracker;

	dms_trace(hfi1_dms_impl_handle_data_small_packet, dms, hdr);

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(hdr == NULL);

	small = (union hfi1_dms_proto_pkt_data_small *)hdr;

	hfi1_dms_rift_key_t const rx_rift_key = small->info.rx_rift_key;
	DMS_BUG_ON(_rift_key_error(rx_rift_key));

	rx_tracker = (struct hfi1_dms_rx_tracker *) _rift_lookup(&dms->rx_rift, rx_rift_key);
	if (!rx_tracker) {
		dd_dev_warn(dms->dd, "(%d) Ignore invalid rx rift key 0x%04hx (%hu %hu)\n", __LINE__, rx_rift_key.value, _rift_key_generation(rx_rift_key), _rift_key_index(rx_rift_key));
		return;
	}

	DMS_BUG_ON(rx_tracker->op != HFI1_DMS_RX_TRACKER_OP_RDMA_WRITE);

	_tracker_timestamp_update(dms, (union hfi1_dms_tracker *)rx_tracker);

	DMS_BUG_ON(rx_tracker->total_payload > 16);
	if (rx_tracker->total_payload <= 8) {
		hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset, &small->info.data[0], rx_tracker->total_payload);
	} else {
		hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset, &small->info.data[0], sizeof(u64));
		hfi1_dms_impl_slow_write_to_user(rx_tracker->rbuf, rx_tracker->rbuf_start_offset + sizeof(u64), &small->info.data[1], rx_tracker->total_payload - sizeof(u64));
	}
	rx_tracker->payload_remaining -= rx_tracker->total_payload;
	DMS_BUG_ON(rx_tracker->payload_remaining > 0);

	hfi1_dms_rx_tracker_handle_completion(dms, rx_tracker, 0, 1);
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

	rcd = packet->rcd;
	idx = packet->egr_index;
	offset = rhf_egr_buf_offset(packet->rhf);

	*update |= !(idx & (rcd->egrbufs.threshold - 1)) && !offset;
	ret = (void *)(((u64)(rcd->egrbufs.rcvtids[idx].addr)) +
			(offset * RCV_BUF_BLOCK_SIZE));
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
}

static inline int process_rcv_packet(struct hfi1_packet *packet)
{
	int ret = 0;

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

	return ret;
}

static inline void *hfi1_get_header(struct hfi1_ctxtdata *rcd,
					__le32 *rhf_addr)
{
	u64 offset;
	void *ret;

	offset = rhf_hdrq_offset(rhf_to_cpu(rhf_addr));

	ret = (void *)(rhf_addr - rcd->rhf_offset + offset);
	return ret;
}

static inline union hfi1_dms_16b_header
		*hfi1_get_16B_header(struct hfi1_ctxtdata *rcd,
					 __le32 *rhf_addr)
{
	union hfi1_dms_16b_header *ret;

	ret = (union hfi1_dms_16b_header *)hfi1_get_header(rcd, rhf_addr);
	return ret;
}

static inline enum hfi1_dms_msg_type hfi1_dms_impl_message_type_get(union hfi1_dms_16b_header *hdr)
{
	enum hfi1_dms_msg_type ret;

	ret = (enum hfi1_dms_msg_type) ((hdr->bth[0] & 0x00FF0000) >> 16); // Extract the message type from BTH
	return ret;
}

static void _handle_data_packet(struct hfi1_packet *packet)
{
	struct hfi1_bulksvc *svc;
	struct hfi1_dms *dms;
	union hfi1_dms_16b_header *hdr;
	enum hfi1_dms_msg_type msg_type;
	struct hfi1_ctxtdata *rcd;

	DMS_BUG_ON(packet == NULL);
	DMS_BUG_ON(packet->rcd == NULL);
	DMS_BUG_ON(packet->rcd->dd == NULL);
	DMS_BUG_ON(packet->rcd->dd->bulksvc == NULL);

	rcd = packet->rcd;
	svc = packet->rcd->dd->bulksvc;
	dms = &svc->dms;

	// We set hardware to drop 9B packets to our rcd
	if (DMS_WARN_ON(jkr_rhf_l2_type(packet->rhf) != HFI1_L2_TYPE_16B)) {
		return;
	}

	WARN_ON_ONCE(packet->ebuf != NULL);

	hdr = hfi1_get_16B_header(rcd, packet->rhf_addr);
	msg_type = hfi1_dms_impl_message_type_get(hdr);
	switch (msg_type) {
	case HFI1_DMS_MSG_TYPE_READ_RESPONSE_SMALL:
		hfi1_dms_impl_handle_read_response_small_packet(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_DATA_START:
		hfi1_dms_handle_data_start(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_DATA:
		hfi1_dms_handle_data(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_DATA_SMALL:
		hfi1_dms_impl_handle_data_small_packet(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_DATA_FIXUP: {
		hfi1_dms_handle_data_fixup(dms, hdr);
		break;
	}

	case HFI1_DMS_MSG_TYPE_READ_START:
	case HFI1_DMS_MSG_TYPE_DATA_REQUEST:
	case HFI1_DMS_MSG_TYPE_DATA_REQUEST_SMALL:
	case HFI1_DMS_MSG_TYPE_DATA_REQUEST_FIXUP:
	case HFI1_DMS_MSG_TYPE_WRITE_START:
	case HFI1_DMS_MSG_TYPE_ACK:
	case HFI1_DMS_MSG_TYPE_NACK:
	case HFI1_DMS_MSG_TYPE_STATUS:
		WARN_ON_ONCE(true);
		break;

	default:
		dd_dev_err(dms->dd, "Received unknown message type: %d\n", msg_type);
		break;
	}
}

static void _handle_ctrl_packet(struct hfi1_packet *packet)
{
	struct hfi1_bulksvc *svc;
	struct hfi1_dms *dms;
	union hfi1_dms_16b_header *hdr;
	enum hfi1_dms_msg_type msg_type;
	struct hfi1_ctxtdata *rcd;

	DMS_BUG_ON(packet == NULL);
	DMS_BUG_ON(packet->rcd == NULL);
	DMS_BUG_ON(packet->rcd->dd == NULL);
	DMS_BUG_ON(packet->rcd->dd->bulksvc == NULL);

	rcd = packet->rcd;
	svc = packet->rcd->dd->bulksvc;
	dms = &svc->dms;

	// We set hardware to drop 9B packets to our rcd
	if (DMS_WARN_ON(jkr_rhf_l2_type(packet->rhf) != HFI1_L2_TYPE_16B)) {
		return;
	}
	WARN_ON_ONCE(packet->ebuf != NULL);

	hdr = hfi1_get_16B_header(rcd, packet->rhf_addr);
	msg_type = hfi1_dms_impl_message_type_get(hdr);
	switch (msg_type) {
	
	case HFI1_DMS_MSG_TYPE_READ_START:
		hfi1_dms_impl_handle_read_start_packet(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_DATA_REQUEST:
		hfi1_dms_impl_handle_data_request_packet(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_DATA_REQUEST_SMALL:
		hfi1_dms_impl_handle_data_request_small_packet(dms, hdr);
		break;
	
	case HFI1_DMS_MSG_TYPE_DATA_REQUEST_FIXUP:
		hfi1_dms_impl_handle_data_request_fixup_packet(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_WRITE_START:
		hfi1_dms_impl_handle_write_start_packet(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_ACK:
		hfi1_dms_impl_handle_ack(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_NACK:
		hfi1_dms_impl_handle_nack_packet(dms, hdr);
		break;

	case HFI1_DMS_MSG_TYPE_STATUS:
		hfi1_dms_impl_handle_status_packet(dms, hdr);
		break;
	
	case HFI1_DMS_MSG_TYPE_READ_RESPONSE_SMALL:
	case HFI1_DMS_MSG_TYPE_DATA_START:
	case HFI1_DMS_MSG_TYPE_DATA:
	case HFI1_DMS_MSG_TYPE_DATA_SMALL:
	case HFI1_DMS_MSG_TYPE_DATA_FIXUP:
		WARN_ON_ONCE(true);
		break;

	default:
		dd_dev_err(dms->dd, "Received unknown message type: %d\n", msg_type);
		break;
	}
}

static void _noop_handle_packet(struct hfi1_packet *packet)
{
	(void) packet;
}


static void hfi1_dms_impl_reclaim_ahg(struct hfi1_dms *dms, struct sdma_engine *sde, struct hfi1_dms_sde_rsrc *sde_rsrc)
{
	u32 descq_head;
	u32 descq_tail;
	struct hfi1_dms_ahg_header_set *ahg_header_set;
	u32 ahg_desc;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(sde == NULL);
	DMS_WARN_ON(sde_rsrc == NULL);

	descq_head = sde->descq_head;
	descq_tail = sde->descq_tail;
	if (descq_head == descq_tail) {
		// reclaim all
		while (sde_rsrc->active_ahg_headers.head != NULL) {
			ahg_header_set = (struct hfi1_dms_ahg_header_set *) sde_rsrc->active_ahg_headers.head;
			ahg_desc = ahg_header_set->desc_idx;
			//pr_debug("Reclaiming AHG header used in engine %d at idx %u [head, tail): [%u, %u)\n", sde->this_idx, ahg_desc, descq_head, descq_tail);
			hfi1_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
			hfi1_dms_impl_dlist_append(&dms->ahg_headers.free, &ahg_header_set->dlist);
		}
	} else if (descq_head < descq_tail) {
		while (sde_rsrc->active_ahg_headers.head != NULL) {
			ahg_header_set = (struct hfi1_dms_ahg_header_set *) sde_rsrc->active_ahg_headers.head;
			ahg_desc = ahg_header_set->desc_idx;
			if (ahg_desc > descq_head && ahg_desc <= descq_tail) {
				// this is within our list and our headers
				// are in-order here so we can just stop
				break;
			}
			//pr_debug("Reclaiming AHG header used in engine %d at idx %u [head, tail): [%u, %u)\n", sde->this_idx, ahg_desc, descq_head, descq_tail);
			hfi1_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
			hfi1_dms_impl_dlist_append(&dms->ahg_headers.free, &ahg_header_set->dlist);
		}
	} else {
		while (sde_rsrc->active_ahg_headers.head != NULL) {
			ahg_header_set = (struct hfi1_dms_ahg_header_set *) sde_rsrc->active_ahg_headers.head;
			ahg_desc = ahg_header_set->desc_idx;
			if (ahg_desc <= descq_tail || ahg_desc > descq_head) {
				// tail has wrapped, so this is within our list
				// and we can stop searching
				break;
			}
			//pr_debug("Reclaiming AHG header used in engine %d at idx %u [head, tail): [%u, %u)\n", sde->this_idx, ahg_desc, descq_head, descq_tail);
			hfi1_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
			hfi1_dms_impl_dlist_append(&dms->ahg_headers.free, &ahg_header_set->dlist);
		}
	}
}

static u64 _tracker_age(union hfi1_dms_tracker const * const tracker, ktime_t const now)
{
	return ktime_to_ns(ktime_sub(now, tracker->hdr.last_activity));
}

static bool _tracker_is_stale(union hfi1_dms_tracker const * const tracker, ktime_t const now)
{
	return _tracker_age(tracker, now) > HFI1_DMS_STALE_THRESHOLD_TIME_NS;
}

static bool _tracker_is_dead(union hfi1_dms_tracker const * const tracker, ktime_t const now)
{
	return _tracker_age(tracker, now) > HFI1_DMS_DEAD_ELAPSED_NS;
}

static void hfi1_dms_poll_stale(struct hfi1_dms *dms, u64 const max_elapsed_ns)
{
	static int const err = -ETIMEDOUT;
	
	DMS_BUG_ON(!dms);

	ktime_t const now = dms->now;

	// remove any disabled tidsets
	u32 const sz = HFI1_DMS_ARRAY_SIZE(dms->read_requests);
	for (u32 tid_set = 0; tid_set < sz; ++tid_set) {
		struct hfi1_dms_read_request_state *read_request = &dms->read_requests[tid_set];
		enum hfi1_dms_tidset_state const state = read_request->state;

		if (state == HFI1_DMS_TIDSET_STATE_DISABLED) {
			if (ktime_to_ns(ktime_sub(now, read_request->disable_ts)) > HFI1_DMS_FABRIC_PACKET_MAX_LIFETIME_NS) {
				dd_dev_warn(dms->dd, "Removed disabled tidset read request\n");
				_tidset_free_then_poll_waiters(dms, tid_set);
			}
		}
	}

	// remove any stale active rx trackers
	for (u64 i = 0; i < HFI1_DMS_ARRAY_SIZE(dms->rx_rift.arr); ++i) {
		union hfi1_dms_tracker * tracker = dms->rx_rift.arr[i];

		if (!tracker) {
			continue;
		
		} else if (_tracker_is_dead(tracker, now)) {
			hfi1_dms_rx_tracker_cancel(dms, &tracker->rx, err);

		} else if (_tracker_is_stale(tracker, now)) {
			if (!tracker->hdr.remote_status_pending) {
				tracker->hdr.remote_status_pending = true;
				dd_dev_dbg(dms->dd, "(%d) Injected tx status request  (l:%05hu r:%05hu); rx_tracker age = %llu\n", __LINE__, tracker->hdr.local_rift_key.value, tracker->hdr.remote_rift_key.value, _tracker_age(tracker, now));
				hfi1_dms_impl_inject_status(dms, tracker->hdr.remote_lid, tracker->hdr.local_rift_key,
					tracker->hdr.remote_rift_key, HFI1_DMS_STATUS_TYPE_TX_REQUEST, 0);
			}
		}
	}

	// remove any stale active tx trackers
	for (u64 i = 0; i < HFI1_DMS_ARRAY_SIZE(dms->tx_rift.arr); ++i) {
		union hfi1_dms_tracker * tracker = dms->tx_rift.arr[i];

		if (!tracker) {
			continue;
		
		} else if (_tracker_is_dead(tracker, now)) {
			hfi1_dms_tx_tracker_cancel(dms, &tracker->tx, err);

		} else if (_tracker_is_stale(tracker, now)) {
			if (!tracker->hdr.remote_status_pending) {
				tracker->hdr.remote_status_pending = true;
				dd_dev_dbg(dms->dd, "(%d) Injected rx status request  (l:%05hu r:%05hu); tx_tracker age = %llu\n", __LINE__, tracker->hdr.local_rift_key.value, tracker->hdr.remote_rift_key.value, _tracker_age(tracker, now));
				hfi1_dms_impl_inject_status(dms, tracker->hdr.remote_lid, tracker->hdr.remote_rift_key,
					tracker->hdr.local_rift_key, HFI1_DMS_STATUS_TYPE_RX_REQUEST, 0);
			}
		}
	}
}

// TODO: we should have different polling functionality/logic
// for the different types (protocl vs data) of receive contexts
// we have since they're set up differently.
static int _dms_poll_rcd(struct hfi1_dms *dms, struct hfi1_ctxtdata *rcd, bool can_stall)
{
	u64 const MAX_PACKETS_PER_POLL = rcd->rcvhdrq_cnt;
	struct hfi1_packet packet = {0};
	u64 actual_packet_start;
	u64 actual_packet_end;
	int last = RCV_PKT_OK;

	init_packet(rcd, &packet);
	if (last_rcv_seq(rcd, packet.rcv_seq)) {
		goto bail;
	}

	actual_packet_start = dms_rdtsc();
	while (last == RCV_PKT_OK) {
		last = process_rcv_packet(&packet);
		if (hfi1_seq_incr(rcd, packet.rcv_seq)) {
			last = RCV_PKT_DONE;
		}
		process_rcv_update(last, &packet);
		if (packet.numpkt > MAX_PACKETS_PER_POLL) {
			break;
		}
		if (can_stall && (dms->access_stall.op != HFI1_DMS_OP_NONE)) {
			break;
		}
	}
	hfi1_set_rcd_head(rcd, packet.rhqoff);
	actual_packet_end = dms_rdtsc();
	dms->counters.hdrq_drain_packet += actual_packet_end - actual_packet_start;

bail:
	finish_packet(&packet);
	return packet.numpkt;
}

static void _dms_drain_workqueue(struct hfi1_dms *dms)
{
	ktime_t now = dms->now;

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
}

int hfi1_dms_poll(struct hfi1_dms *dms, ktime_t const now)
{
	int numpkt = 0;
	u64 start;
	u64 end;
	int i;

	dms->now = now;
	start = dms_rdtsc();
	dms_trace(dms_poll, dms);

	for (i = 0; i < dms->num_engines; ++i) {
		sdma_gethead_dma(dms->sdma_engines[i]);
		hfi1_dms_impl_reclaim_ahg(dms, dms->sdma_engines[i], &dms->sde_rsrcs[i]);
	}

	_dms_drain_workqueue(dms);

	if (ktime_to_ns(ktime_sub(now, dms->last_stale_check)) > HFI1_DMS_STALE_POLL_TIME_NS) {
		dms->last_stale_check = now;
		hfi1_dms_poll_stale(dms, HFI1_DMS_STALE_THRESHOLD_TIME_NS);
	}

	// always drain/process data context even if protocol is stalled
	numpkt += _dms_poll_rcd(dms, dms->rcd_data, false);

	// stalls only happen on the protocol contexts
	if (dms->access_stall.op == HFI1_DMS_OP_NONE) {
		numpkt += _dms_poll_rcd(dms, dms->rcd_ctrl, true);
	} else {
		bool const access_lookup_is_error = (dms->access_stall.retries > HFI1_DMS_ACCESS_STALL_MAX_RETRIES);
		int ret = dms->access_stall.op == HFI1_DMS_OP_RDMA_READ ?
			hfi1_dms_impl_handle_read_start(dms, dms->access_stall.read, access_lookup_is_error) :
			hfi1_dms_impl_handle_write_start(dms, dms->access_stall.write, access_lookup_is_error);
		if (ret == 0) {
			dms->access_stall.retries = 0;
			dms->access_stall.op = HFI1_DMS_OP_NONE;
			numpkt += _dms_poll_rcd(dms, dms->rcd_ctrl, true);
		} else {
			dms->access_stall.retries += 1;
		}
	}

	end = dms_rdtsc();
	dms->counters.hdrq_drain += end - start;

	return numpkt;
}

static void hfi1_dms_handle_tx_tracker_completion(struct hfi1_dms *dms, hfi1_dms_rift_key_t tx_rift_key, u16 flags, u64 imm_data)
{
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(_rift_key_error(tx_rift_key));

	struct hfi1_dms_tx_tracker *tx_tracker = (struct hfi1_dms_tx_tracker *) _rift_lookup(&dms->tx_rift, tx_rift_key);
	if (!tx_tracker) {
		dd_dev_warn(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", tx_rift_key.value, _rift_key_generation(tx_rift_key), _rift_key_index(tx_rift_key));
		return;
	}

	_tracker_timestamp_update(dms, (union hfi1_dms_tracker *)tx_tracker);

	// invoke callback for the completed tx tracker
	if (tx_tracker->op == HFI1_DMS_TX_TRACKER_OP_RDMA_READ) {
		access_xfer_end(dms, tx_tracker->read.access, flags, imm_data, 0);
		_tracker_rift_release(dms, (union hfi1_dms_tracker *)tx_tracker, &dms->tx_rift);
		_dms_tx_rift_poll(dms, HFI1_DMS_XFER_TYPE_TARGET);

	} else if (tx_tracker->op == HFI1_DMS_TX_TRACKER_OP_RDMA_WRITE) {
		tx_tracker->write.completion.fn(&tx_tracker->write.completion.cookie, 0);
		_tracker_rift_release(dms, (union hfi1_dms_tracker *)tx_tracker, &dms->tx_rift);
		_dms_tx_rift_poll(dms, HFI1_DMS_XFER_TYPE_INITIATOR);
	}

	_sdma_waitlist_poll(dms);
	hfi1_dms_impl_tx_tracker_free(dms, tx_tracker);
}

/**
 * These functions exist in some form in hfi1.h but they don't exist in the way
 * we really want them here. Convenience functions for our pre-defined
 * templates
 */
static u64 hfi1_dms_impl_pbc_template_create_16Bc(u8 port_idx, u32 dw_len, u16 sctxt)
{
	u64 ret;

	ret = (u64) sctxt << PBC_SEND_CTXT_SHIFT |
		(u64) PBC_L2_16B << PBC_L2_TYPE_SHIFT |
		(u64) port_idx << PBC_PORT_IDX_SHIFT |
		(u64) (dw_len & PBC_LENGTH_DWS_MASK) << PBC_LENGTH_DWS_SHIFT |
		(u64) PBC_IHCRC_LKDETH << PBC_INSERT_HCRC_SHIFT |
		(u64) 1 << 19 | // 16B Compressed
		(u64) PBC_INSERT_BYPASS_ICRC; // InsertNon9BIcrc
	return ret;
}

static int hfi1_dms_impl_proto_command_template_make(struct hfi1_dms *dms, union hfi1_dms_proto_cmd *cmd, enum hfi1_dms_msg_type msg_type, u32 pkt_len_qws, u16 jkey)
{
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(cmd == NULL);
	// Even though the PBC gets stripped, a 16b compressed header will expand by 1 QW as it goes
	// out on the wire, so actually the pktlen_dw in the pbc should be the same as pktlen_qw in the lrh
	cmd->pbc = hfi1_dms_impl_pbc_template_create_16Bc(dms->dd->pport[HFI1_DMS_PORT].hw_pidx, pkt_len_qws << 1, dms->rcd_ctrl->sc->hw_context);
	hfi1_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc, pkt_len_qws);
	cmd->bth[0] = HFI1_DMS_BTH_OPCODE | ((u32) msg_type << 16);
	cmd->bth[1] = (u32) RVT_KDETH_QP_PREFIX << 8;
	cmd->kdeth[0] = 1 << 30; // set KVER
	cmd->kdeth[1] = jkey;

	return 0;
}

void hfi1_dms_impl_fill_proto_templates(struct hfi1_dms *dms)
{
	union hfi1_dms_proto_cmd *cmd;

	DMS_BUG_ON(dms == NULL);

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_START];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_READ_START, sizeof(union hfi1_dms_pkt_read_start)/sizeof(u64), HFI1_DMS_CTRL_JKEY);

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_READ_RESPONSE_SMALL];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_READ_RESPONSE_SMALL, sizeof(union hfi1_dms_pkt_read_response_small)/sizeof(u64), HFI1_DMS_DATA_JKEY);

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_REQUEST];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_DATA_REQUEST, sizeof(union hfi1_dms_pkt_data_request)/sizeof(u64), HFI1_DMS_CTRL_JKEY);

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_REQUEST_FIXUP];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_DATA_REQUEST_FIXUP, sizeof(union hfi1_dms_proto_pkt_data_request_fixup)/sizeof(u64), HFI1_DMS_CTRL_JKEY);

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_REQUEST_SMALL];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_DATA_REQUEST_SMALL, sizeof(union hfi1_dms_proto_pkt_data_request_small)/sizeof(u64), HFI1_DMS_CTRL_JKEY);

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_START];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_DATA_START, 8, HFI1_DMS_DATA_JKEY); // <-- 'pkt_len_qws' determined at runtime

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_DATA, 8, HFI1_DMS_DATA_JKEY); // <-- 'pkt_len_qws' determined at runtime

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_FIXUP];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_DATA_FIXUP, sizeof(union hfi1_dms_proto_pkt_data_fixup)/sizeof(u64), HFI1_DMS_DATA_JKEY);

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_SMALL];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_DATA_SMALL, sizeof(union hfi1_dms_proto_pkt_data_small)/sizeof(u64), HFI1_DMS_DATA_JKEY);

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_WRITE_START];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_WRITE_START, sizeof(union hfi1_dms_proto_pkt_write_start)/sizeof(u64), HFI1_DMS_CTRL_JKEY);

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_ACK];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_ACK, sizeof(union hfi1_dms_proto_pkt_ack)/sizeof(u64), HFI1_DMS_CTRL_JKEY);

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_NACK];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_NACK, sizeof(union hfi1_dms_pkt_nack)/sizeof(u64), HFI1_DMS_CTRL_JKEY);

	cmd = (union hfi1_dms_proto_cmd *) &dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_STATUS];
	hfi1_dms_impl_proto_command_template_make(dms, cmd, HFI1_DMS_MSG_TYPE_STATUS, sizeof(union hfi1_dms_pkt_status)/sizeof(u64), HFI1_DMS_CTRL_JKEY);
}

int hfi1_dms_impl_16bc_state_set(struct hfi1_dms *dms)
{
	struct hfi1_devdata *dd;
	u64 slid_reg;
	u64 mask;
	u64 lid;

	DMS_BUG_ON(dms == NULL);
	dd = dms->dd;
	mask = ~((1U << dd->pport[HFI1_DMS_PORT].lmc) - 1);
	lid = dd->pport[HFI1_DMS_PORT].lid;

	// TODO: I actually think all the things we need
	// to set are done so by default for us
	// but if not they are SendCtxtCheckSLID and
	// SendCtxtCheckCspecAge
	hfi1_set_ctxt_pkey(dd, dms->rcd_ctrl, HFI1_DMS_PKEY);
	hfi1_set_ctxt_pkey(dd, dms->rcd_data, HFI1_DMS_PKEY);
	slid_reg = BIT_ULL(63)
					| (mask & JKR_SEND_CTXT_CHECK_SLID_MASK_MASK) << JKR_SEND_CTXT_CHECK_SLID_MASK_SHIFT 
					| (lid & JKR_SEND_CTXT_CHECK_SLID_VALUE_MASK) << JKR_SEND_CTXT_CHECK_SLID_VALUE_SHIFT;
	write_epsc_csr(dd, dd->pport[HFI1_DMS_PORT].hw_pidx, dms->sctxt->hw_context,
			       dd->params->send_ctxt_check_slid_reg, slid_reg);
	// this one is _probably_ unnecessary for now because we're just going to use the rcd_ctrl
	// send_context, however that may change in the future for helping to resolve incast issues
	write_epsc_csr(dd, dd->pport[HFI1_DMS_PORT].hw_pidx, dms->rcd_data->sc->hw_context,
			       dd->params->send_ctxt_check_slid_reg, slid_reg);

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
	ret = (type == PT_EAGER ? 0 : BIT(JKR_RCV_ARRAY_EGR_TID_SELECT_SHIFT))
	       | (ctxt << JKR_RCV_ARRAY_RCV_CTXT_IDX_SHIFT)
	       | (index << JKR_RCV_ARRAY_CSR_INDEX_SHIFT);
	return ret;
}

static int hfi1_dms_impl_map_tid_entries(struct hfi1_dms *dms, struct hfi1_dms_mr * mr, u64 start_page_index, u64 npages, u32 tid_set)
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

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(mr == NULL);
	DMS_BUG_ON(tid_set >= HFI1_DMS_TID_SET_IDX_COUNT);
	DMS_BUG_ON(npages == 0);
	DMS_BUG_ON(npages > (HFI1_DMS_TID_SET_SIZE*2));
	start = dms_rdtsc();

	tid_start = tid_set * HFI1_DMS_TID_SET_SIZE;
	tid_entry_start = tid_start * 2;

	npages_twos = (npages + 1) & ~1ull;

	for (i = 0; i < npages; ++i) {
		next_phys_addr = mr->dma_list[start_page_index + i];
		tid_entries[i] = (u64) (next_phys_addr >> 12) | (1ull << 46) | BIT(63);
	}
	if (npages & 1) {
		tid_entries[npages] = (u64) (dms->zero_page.phys_addr >> 12) | (1ull << 46) | BIT(63);
	}

	csr_offset = rcvarray_offset(dms->rcd_data->ctxt, tid_entry_start, PT_EXPECTED);
	for (i = 0; i < npages_twos; ++i) {
		writeq(tid_entries[i], dms->dd->bar_maps[ctxt_bar_idx(dms->rcd_data->ctxt)].rcvarray_wc + csr_offset + (i * sizeof(u64)));
	}
	flush_wc();
	end = dms_rdtsc();
	dms->counters.map_tids += end - start;
	return 0;
}

union hfi1_dms_proto_cmd_data_request_fixup hfi1_dms_proto_cmd_data_request_fixup_make(struct hfi1_dms *dms,
		struct hfi1_dms_rx_tracker const * const rx_tracker, u32 dlid, hfi1_dms_rift_key_t tx_rift_key, hfi1_dms_rift_key_t rx_rift_key)
{
	union hfi1_dms_proto_cmd_data_request_fixup * tmpl;
	union hfi1_dms_proto_cmd_data_request_fixup cmd;
	int i;

	DMS_BUG_ON(dms == NULL);

	tmpl = (union hfi1_dms_proto_cmd_data_request_fixup *)
		&dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_REQUEST_FIXUP];

	int cmd_len_qws = sizeof(cmd) / sizeof(u64);
	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}
	_dms_return_rx_set(&cmd.info.bth[0], dms->rcd_data->ctxt);

	DMS_BUG_ON((rx_tracker->total_payload & 0xffffffff00000000ull) != 0);	// TODO - handle fixups of read requests larger than 2^32 size

	cmd.info.size = (u32) rx_tracker->total_payload;
	cmd.info.tx_rift_key = tx_rift_key;
	cmd.info.rx_rift_key = rx_rift_key;
	cmd.tail_flit = 0;
	// remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi1_dms_impl_pbc_dlid_set(&cmd.pbc, dlid);
	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);

	return cmd;
}

void _tidset_reset(struct hfi1_dms *dms, u32 tid_set, enum hfi1_dms_tidset_state new_state)
{
	u64 const npages = HFI1_DMS_TID_SET_SIZE*2;
	u64 const npages_twos = (npages + 1) & ~1ull;
	u64 const tid_start = tid_set * HFI1_DMS_TID_SET_SIZE;
	u64 const tid_entry_start = tid_start * 2;

	u64 csr_offset;
	u64 tid_entries[HFI1_DMS_TID_SET_SIZE * 2] = {0};

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(tid_set >= HFI1_DMS_TID_SET_IDX_COUNT);

	dms->read_requests[tid_set].disable_ts = dms->now;
	dms->read_requests[tid_set].state = new_state;
	dms->read_requests[tid_set].total_requested_qws = (u64)(-1);
	dms->read_requests[tid_set].remaining_qws = (u64)(-1);
	dms->read_requests[tid_set].rx_tracker = &dms->disabled_rx_tracker;

	for (u64 i = 0; i < npages; ++i) {
		tid_entries[i] = (u64) (dms->zero_page.phys_addr >> 12) | (1ull << 46) | BIT(63);
	}

	csr_offset = rcvarray_offset(dms->rcd_data->ctxt, tid_entry_start, PT_EXPECTED);
	for (u64 i = 0; i < npages_twos; ++i) {
		writeq(tid_entries[i], dms->dd->bar_maps[ctxt_bar_idx(dms->rcd_data->ctxt)].rcvarray_wc + csr_offset + (i * sizeof(u64)));
	}
}

void _tidset_disable(struct hfi1_dms *dms, u32 tid_set)
{
	_tidset_reset(dms, tid_set, HFI1_DMS_TIDSET_STATE_DISABLED);
}

// pre: pages must be pinned and mapped
void _tidset_enable(struct hfi1_dms *dms, u32 tid_set, struct hfi1_dms_rx_tracker *rx_tracker, u32 *tid_info, u64 *tidset_nbytes)
{
	u64 payload_start;
	u64 recv_offset_bytes;
	u64 recv_offset_dws;
	u64 start_page_index;
	u64 bytes_to_be_requested;
	u64 extent_remaining;
	u64 npages_remaining;
	u64 npages_to_request;
	u64 nbytes_to_request;
	int ret;
	struct hfi1_dms_read_request_state *read_req_state;
	u32 read_size_qw;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(tid_set >= HFI1_DMS_TID_SET_IDX_COUNT);
	DMS_BUG_ON(dms->read_requests[tid_set].tid_set != tid_set);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(!tid_info);
	DMS_BUG_ON(!tidset_nbytes);
	DMS_BUG_ON(rx_tracker->total_payload == 0);
	DMS_BUG_ON(rx_tracker->total_payload == rx_tracker->payload_requested);

	payload_start = rx_tracker->rbuf->extended_vaddr.addr + rx_tracker->rbuf_offset;
	DMS_BUG_ON(payload_start & 0x7); // Ensure payload_start is QW aligned

	// calculate byte offset into first page to receive data position
	// on first read request this might be non-zero but it should be zero
	// on most read requests
	recv_offset_bytes = (payload_start & (PAGE_SIZE - 1));
	recv_offset_dws = recv_offset_bytes >> 2;

	// determine which os page contains the first byte to request
	// rbuf_offset contains recv_offset_bytes already
	start_page_index = rx_tracker->rbuf_offset / PAGE_SIZE;

	// determine the number of pages to map into the tidset; also the number of bytes to request from the remote
	bytes_to_be_requested =  rx_tracker->total_payload - rx_tracker->payload_requested;
	extent_remaining = recv_offset_bytes + bytes_to_be_requested;
	npages_remaining = (extent_remaining + (PAGE_SIZE - 1)) / PAGE_SIZE;
	npages_to_request = min(npages_remaining, (u64) HFI1_DMS_TID_SET_PAGES_MAX);
	nbytes_to_request = min(extent_remaining, (npages_to_request * PAGE_SIZE)) - recv_offset_bytes;

	ret = rx_tracker->rbuf->pinned_check_fn(rx_tracker->rbuf, start_page_index, npages_to_request);
	DMS_BUG_ON(ret < 0); // pre: pages must be pinned and mapped

	hfi1_dms_impl_map_tid_entries(dms, rx_tracker->rbuf, start_page_index, npages_to_request, tid_set);

	read_size_qw = nbytes_to_request >> 3;

	read_req_state = &dms->read_requests[tid_set];
	*read_req_state = (struct hfi1_dms_read_request_state){
		.total_requested_qws = read_size_qw,
		.remaining_qws = read_size_qw,
		.rx_tracker = rx_tracker,
		.tid_set = tid_set,
		.state = HFI1_DMS_TIDSET_STATE_ENABLED,
	};

	*tid_info = hfi1_dms_tid_info_make(tid_set * HFI1_DMS_TID_SET_SIZE, recv_offset_dws);

	*tidset_nbytes = nbytes_to_request;
}

static union hfi1_dms_cmd_data_request hfi1_dms_cmd_data_request_make(struct hfi1_dms *dms, u32 tid_info, u32 sbuf_offset,
		hfi1_dms_rift_key_t tx_rift_key, u32 src_lid, u32 read_size_qw)
{
	union hfi1_dms_cmd_data_request cmd =
		*((union hfi1_dms_cmd_data_request *)&dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_REQUEST]);

	cmd.info.tid_info = tid_info;
	cmd.info.offset = sbuf_offset;
	cmd.info.tx_rift_key = tx_rift_key;

	hfi1_dms_impl_pbc_dlid_set(&cmd.pbc, src_lid);
	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, src_lid);
	_dms_return_rx_set(&cmd.info.bth[0], dms->rcd_data->ctxt);
	cmd.info.bth[2] = (read_size_qw << 16) | (cmd.info.bth[2] & 0xffff);

	return cmd;
}

int hfi1_dms_impl_make_data_request(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker, u32 tid_set)
{
	u64 start;
	u64 nbytes_to_request;
	u32 tid_info;
	u32 read_size_qw;
	union hfi1_dms_cmd_data_request cmd;
	int ret;
	u64 end;

	dms_trace(dms_make_data_request, dms, rx_tracker, tid_set);

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(rx_tracker == NULL);

	start = dms_rdtsc();

	_tidset_enable(dms, tid_set, rx_tracker, &tid_info, &nbytes_to_request);
	read_size_qw = nbytes_to_request >> 3;

	cmd = hfi1_dms_cmd_data_request_make(dms, tid_info, rx_tracker->sbuf_offset, rx_tracker->hdr.remote_rift_key, rx_tracker->hdr.remote_lid, read_size_qw);
	ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
	if (ret < 0) {
		dd_dev_dbg(dms->dd, "Unable to send data request.\n");
		_tidset_reset(dms, tid_set, HFI1_DMS_TIDSET_STATE_FREE);
		return ret;
	}

	rx_tracker->payload_requested += nbytes_to_request;
	rx_tracker->sbuf_offset += nbytes_to_request;
	rx_tracker->rbuf_offset += nbytes_to_request;

	end = dms_rdtsc();
	dms->counters.make_data_request += end - start;

	return 0;
}

int hfi1_dms_impl_make_data_requests(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker)
{
	u32 tid_set;
	int rc = 0;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(_rift_key_error(rx_tracker->hdr.remote_rift_key));

	rc = _tidset_idx_peek(dms, &tid_set);

	while (rc == 0 && (rx_tracker->payload_requested < rx_tracker->total_payload)) {
		rc = hfi1_dms_impl_make_data_request(dms, rx_tracker, tid_set);
		if (rc == 0) {
			_tidset_idx_reserve(dms, tid_set);
			rc = _tidset_idx_peek(dms, &tid_set);
		}
	}

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

int calculate_access_mr_page_offset(struct hfi1_dms *dms, struct hfi1_dms_access * access, u64 offset, u32 size, u64 *page_offset)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!access);
	DMS_BUG_ON(!page_offset);

	if (access->mr->mode == HFI1_DMS_MR_MODE_VADDR) {
		// offset is interpreted as a user virtual address
		if (offset < access->mr->user.addr) {
			dd_dev_info(dms->dd, "Invalid virtual address offset.\n");
			return -EINVAL;
		}
		*page_offset = access->mr->region_offset + offset - access->mr->user.addr;
	} else {
		*page_offset = access->mr->region_offset + access->offset + offset;
	}

	if ((*page_offset + size) > access->mr->extended_vaddr.len) {
		dd_dev_info(dms->dd, "Invalid length from offset.\n");
		return -EINVAL;
	}

	return 0;
}

int calculate_mr_page_offset(struct hfi1_dms *dms, struct hfi1_dms_mr * mr, u64 offset, u32 size, u64 *page_offset)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!mr);
	DMS_BUG_ON(!page_offset);

	if (mr->mode == HFI1_DMS_MR_MODE_VADDR) {
		// offset is interpreted as a user virtual address
		if (offset < mr->user.addr) {
			dd_dev_info(dms->dd, "Invalid virtual address offset.\n");
			return -EINVAL;
		}
		*page_offset = mr->region_offset + offset - mr->user.addr;
	} else {
		*page_offset = mr->region_offset + offset;
	}

	if ((*page_offset + size) > mr->extended_vaddr.len) {
		dd_dev_info(dms->dd, "Invalid length from offset.\n");
		return -EINVAL;
	}

	return 0;
}

int hfi1_dms_impl_handle_read_start(struct hfi1_dms *dms, struct hfi1_dms_read_start_parameters const parameters, bool const access_lookup_is_error)
{
	u64 start;
	struct hfi1_dms_client_state * client = NULL;
	struct hfi1_dms_access *access;
	struct hfi1_dms_tx_tracker *tx_tracker;
	int ret = 0;
	u64 end;
	u64 page_offset = 0;
	enum hfi1_dms_err_type reason = HFI1_DMS_ERR_TYPE_NONE;

	DMS_BUG_ON(dms == NULL);

	start = dms_rdtsc();

	access = hfi1_dms_access_lookup(dms, parameters.dms_key, &client);
	if (!client) {
		dd_dev_info(dms->dd, "(%d) Client not found for dms_key %llu.\n", __LINE__, parameters.dms_key.value);
		reason = HFI1_DMS_ERR_TYPE_CLIENT_NOT_FOUND;
		goto nack;
	}

	if (!access) {
		if (access_lookup_is_error) {
			dd_dev_info(dms->dd, "Access not found for dms_key %llu.\n", parameters.dms_key.value);
			reason = HFI1_DMS_ERR_TYPE_ACCESS_NOT_FOUND;
			goto nack;
		}
		return -EAGAIN;
	}

	ret = calculate_access_mr_page_offset(dms, access, parameters.offset, parameters.tbytes, &page_offset);
	if (ret < 0) {
		reason = HFI1_DMS_ERR_TYPE_ACCESS_RANGE_VIOLATION;
		goto nack;
	}

	ret = access_xfer_begin(dms, access);
	if (ret < 0) {
		// Unable to begin transfer on ephemeral access because another transfer is already active.
		reason = HFI1_DMS_ERR_TYPE_ACCESS_BUSY;
		goto nack;
		return 0;
	}

	union hfi1_dms_tracker *tracker = hfi1_dms_impl_tracker_new(dms);
	if (!tracker) {
		access_xfer_end(dms, access, parameters.flags, parameters.imm_data, -ENOMEM);
		reason = HFI1_DMS_ERR_TYPE_NO_MEMORY;
		goto nack;
	}
	tx_tracker = &tracker->tx;
	tx_tracker->op = HFI1_DMS_TX_TRACKER_OP_RDMA_READ;
	tx_tracker->read.access = access;
	tx_tracker->read.start = parameters;	

	tx_tracker->hdr.remote_lid = parameters.slid;
	tx_tracker->hdr.remote_rift_key = parameters.rx_rift_key;
	tx_tracker->hdr.local_rift_key = _rift_key_create_err(HFI1_DMS_RIFT_ERR_KEY_NOT_SET);

	tx_tracker->total_payload = parameters.tbytes;
	tx_tracker->payload_remaining = parameters.tbytes;
	tx_tracker->xfer_start_byte_offset = page_offset;

	ret = _rift_reserve(&dms->tx_rift, HFI1_DMS_XFER_TYPE_TARGET, &tx_tracker->hdr.local_rift_key);
	if (ret < 0) {
		_rift_waitlist_add(&dms->tx_rift, HFI1_DMS_XFER_TYPE_TARGET, &tx_tracker->hdr.dlist);
		return 0;
	}
	_rift_assign(&dms->tx_rift, (union hfi1_dms_tracker *)tx_tracker, tx_tracker->hdr.local_rift_key);

	ret = _dms_tx_rift_continue_read_start(dms, tx_tracker);
	if (ret < 0) {
		_rift_release(&dms->tx_rift, tx_tracker->hdr.local_rift_key);
		access_xfer_end(dms, access, parameters.flags, parameters.imm_data, -ENOMEM);
		hfi1_dms_impl_tx_tracker_free(dms, tx_tracker);
		reason = HFI1_DMS_ERR_TYPE_NO_MEMORY;
		goto nack;
	}

	end = dms_rdtsc();
	dms->counters.handle_data_request += end - start;

	return 0;

nack:
	_inject_nack(dms, HFI1_DMS_MSG_TYPE_READ_START, reason, parameters.slid, parameters.rx_rift_key);
	return 0;
}

void hfi1_dms_impl_handle_read_start_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!hdr);

	union hfi1_dms_pkt_read_start *pkt = (union hfi1_dms_pkt_read_start *)hdr;
	struct hfi1_dms_read_start_parameters const parameters = {
		.dms_key = pkt->info.dms_key,
		.offset = pkt->info.key_offset_or_vaddr,
		.imm_data = pkt->info.imm_data,
		.tbytes = pkt->info.size,
		.tid_info = pkt->info.tid_info,
		.slid = hfi1_dms_lrh16B_slid_get((u32 *) &hdr->lrh[0]),
		.flags = pkt->info.flags,
		.rx_rift_key = {.value = (u16) ((hdr->bth[2] >> 16) & 0xFFFF)},
		.size_qw = (u16) ((hdr->bth[2]) & 0xFFFF),
		.rx_id = _dms_return_rx_get(&hdr->bth[0]),
		.include_fixup_data = pkt->info.include_fixup_data,
		.head_misalignment = pkt->info.head_misalignment,
	};

	int ret = hfi1_dms_impl_handle_read_start(dms, parameters, false);
	if (ret < 0) {
		dms->access_stall.retries = 0;
		dms->access_stall.op = HFI1_DMS_OP_RDMA_READ;
		dms->access_stall.read = parameters;
	}
}

static int hfi1_dms_impl_handle_data_request(struct hfi1_dms *dms, struct dms_handle_data_request_parameters const *parameters)
{
	u64 start, end;
	struct hfi1_dms_tx_tracker *tx_tracker;
	int ret = 0;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(parameters == NULL);

	start = dms_rdtsc();

	hfi1_dms_rift_key_t const tx_rift_key = parameters->tx_rift_key;
	DMS_BUG_ON(_rift_key_error(tx_rift_key));

	tx_tracker = (struct hfi1_dms_tx_tracker *) _rift_lookup(&dms->tx_rift, tx_rift_key);
	if (!tx_tracker) {
		dd_dev_warn(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", tx_rift_key.value, _rift_key_generation(tx_rift_key), _rift_key_index(tx_rift_key));
		return 0;
	}

	_tracker_timestamp_update(dms, (union hfi1_dms_tracker *)tx_tracker);

	DMS_BUG_ON(tx_tracker == NULL);
	DMS_BUG_ON((tx_tracker->op != HFI1_DMS_TX_TRACKER_OP_RDMA_READ) && (tx_tracker->op != HFI1_DMS_TX_TRACKER_OP_RDMA_WRITE));

	struct hfi1_dms_sdma_parameters const sdma_parameters = {
		.tx_tracker = tx_tracker,
		.mr = (tx_tracker->op == HFI1_DMS_TX_TRACKER_OP_RDMA_WRITE) ? tx_tracker->write.mr : tx_tracker->read.access->mr,
		.page_offset = tx_tracker->xfer_start_byte_offset + parameters->sbuf_offset,
		.nbytes = parameters->size_qw << 3,
		.tid_info = parameters->tid_info,
		.sdma_type = HFI1_DMS_SDMA_TYPE_DATA,
		.rx_id = parameters->rx_id,
		.include_fixup_data = 0,
	};

	if (_sdma_waitlist_peek(dms)) {
		ret = _sdma_waitlist_add(dms, &sdma_parameters);
		_sdma_waitlist_poll(dms);
	} else if (hfi1_dms_sdma_send(dms, &sdma_parameters) < 0) {
		ret = _sdma_waitlist_add(dms, &sdma_parameters);
	}

	end = dms_rdtsc();
	dms->counters.handle_data_request += end - start;

	return ret;
}

int hfi1_dms_impl_handle_data_request_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	union hfi1_dms_pkt_data_request *pkt = (union hfi1_dms_pkt_data_request *)hdr;

	struct dms_handle_data_request_parameters const parameters = {
		.size_qw = hfi1_dms_impl_data_request_size_qw_get(hdr),
		.tid_info = pkt->info.tid_info,
		.sbuf_offset = pkt->info.offset,
		.tx_rift_key = pkt->info.tx_rift_key,
		.rx_id = _dms_return_rx_get(&hdr->bth[0]),
	};
	hfi1_dms_impl_handle_data_request(dms, &parameters);

	return 0;
}

union hfi1_dms_proto_cmd_data_small hfi1_dms_proto_cmd_data_small_make(struct hfi1_dms *dms, u32 dlid, u16 rx_id, hfi1_dms_rift_key_t tx_rift_key, hfi1_dms_rift_key_t rx_rift_key, u64 data0, u64 data1)
{
	union hfi1_dms_proto_cmd_data_small * tmpl;
	union hfi1_dms_proto_cmd_data_small cmd;
	int i;
	int cmd_len_qws;

	tmpl = (union hfi1_dms_proto_cmd_data_small *)&dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_SMALL];
	cmd_len_qws = sizeof(cmd) / sizeof(u64);
	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}
	_dms_destqp_rx_set(&cmd.info.bth[0], rx_id);
	cmd.info.rx_rift_key = rx_rift_key;
	cmd.info.tx_rift_key = tx_rift_key;
	cmd.info.data[0] = data0;
	cmd.info.data[1] = data1;

	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);

	return cmd;
}

static int hfi1_dms_impl_handle_data_request_small(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	enum hfi1_dms_msg_type msg_type;
	u16 size;
	hfi1_dms_rift_key_t rx_rift_key;
	int ret;
	u64 data[2] = {0, 0};
	u32 dlid;
	u64 nbytes;
	union hfi1_dms_proto_cmd_data_small cmd;
	union hfi1_dms_proto_pkt_data_request_small * drs;
	struct hfi1_dms_tx_tracker *tx_tracker;
	struct hfi1_dms_mr * mr;
	u64 page_offset;

	dms_trace(dms_handle_data_request_small, dms, hdr);

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(hdr == NULL);

	msg_type = hfi1_dms_impl_message_type_get(hdr);
	DMS_BUG_ON(msg_type != HFI1_DMS_MSG_TYPE_DATA_REQUEST_SMALL);

	drs = (union hfi1_dms_proto_pkt_data_request_small *)hdr;
	size = drs->info.size;
	rx_rift_key = drs->info.rx_rift_key;

	hfi1_dms_rift_key_t const tx_rift_key = drs->info.tx_rift_key;
	DMS_BUG_ON(_rift_key_error(tx_rift_key));

	tx_tracker = (struct hfi1_dms_tx_tracker *) _rift_lookup(&dms->tx_rift, tx_rift_key);
	if (!tx_tracker) {
		dd_dev_warn(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", tx_rift_key.value, _rift_key_generation(tx_rift_key), _rift_key_index(tx_rift_key));
		return 0;
	}

	DMS_BUG_ON(tx_tracker->op != HFI1_DMS_TX_TRACKER_OP_RDMA_WRITE);

	_tracker_timestamp_update(dms, (union hfi1_dms_tracker *)tx_tracker);

	mr = tx_tracker->write.mr;
	page_offset = tx_tracker->xfer_start_byte_offset;
	nbytes = min((u16)sizeof(u64),size);
	data[0] = hfi1_dms_impl_slow_read_from_user(mr, page_offset, nbytes);
	if (size > sizeof(u64)) {
		page_offset += sizeof(u64);
		nbytes = size - sizeof(u64);
		data[1] = hfi1_dms_impl_slow_read_from_user(mr, page_offset, nbytes);
	} else {
		data[1] = 0;
	}

	dlid = hfi1_dms_lrh16B_slid_get((u32 *) &hdr->lrh[0]);
	cmd = hfi1_dms_proto_cmd_data_small_make(dms, dlid, _dms_return_rx_get(&drs->info.bth[0]), tx_tracker->hdr.local_rift_key, rx_rift_key, data[0], data[1]);
	ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
	if (ret < 0) {
		dd_dev_err(dms->dd, "Failed to pio send small data request response.\n");
		return ret; // FIXME - blocksome 
	}

	return 0; // Success
}

static int hfi1_dms_impl_handle_data_request_small_work(struct hfi1_dms *dms, struct hfi1_dms_work_item *item)
{
	static_assert(sizeof(union hfi1_dms_16b_header) <= sizeof(item->data));
	union hfi1_dms_16b_header *hdr = (union hfi1_dms_16b_header *)item->data;
	int ret = hfi1_dms_impl_handle_data_request_small(dms, hdr);

	if (ret == -ENOMSG)
		ret = -EAGAIN;

	return ret;
}

int hfi1_dms_impl_handle_data_request_small_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	int ret;

	ret = hfi1_dms_impl_handle_data_request_small(dms, hdr);
	if (ret < 0) {
		return hfi1_dms_impl_queue_work_item(dms, (void*)hdr, sizeof(*hdr), hfi1_dms_impl_handle_data_request_small_work);
	}

	return 0;
}

struct hfi1_dms_handle_data_request_fixup_parameters {
	u32 size;
	u16 rx_id;
	hfi1_dms_rift_key_t tx_rift_key;
	hfi1_dms_rift_key_t rx_rift_key;
	u16 unused;
};

union hfi1_dms_proto_cmd_data_fixup hfi1_dms_proto_cmd_data_fixup_make(struct hfi1_dms *dms, u32 dlid, u16 rx_id, hfi1_dms_rift_key_t tx_rift_key, hfi1_dms_rift_key_t rx_rift_key, u64 head, u64 tail)
{
	union hfi1_dms_proto_cmd_data_fixup * tmpl;
	union hfi1_dms_proto_cmd_data_fixup cmd;
	int i;
	int cmd_len_qws;

	tmpl = (union hfi1_dms_proto_cmd_data_fixup *)&dms->protocol_cmd_templates[HFI1_DMS_MSG_TYPE_DATA_FIXUP];

	cmd_len_qws = sizeof(cmd) / sizeof(u64);
	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}

	_dms_destqp_rx_set(&cmd.info.bth[0], rx_id);

	cmd.info.tx_rift_key = tx_rift_key;
	cmd.info.rx_rift_key = rx_rift_key;
	cmd.info.head = head;
	cmd.info.tail = tail;

	hfi1_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);
	return cmd;
}

static void hfi1_dms_impl_handle_data_request_fixup(struct hfi1_dms *dms, struct hfi1_dms_handle_data_request_fixup_parameters const *parameters)
{
	struct hfi1_dms_tx_tracker *tx_tracker;
	int ret;
	u64 head, tail;
	union hfi1_dms_proto_cmd_data_fixup cmd;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!parameters);
	DMS_BUG_ON(parameters->size <= 16); // must use "small" instead

	hfi1_dms_rift_key_t const tx_rift_key = parameters->tx_rift_key;
	DMS_BUG_ON(_rift_key_error(tx_rift_key));

	tx_tracker = (struct hfi1_dms_tx_tracker *) _rift_lookup(&dms->tx_rift, tx_rift_key);
	if (!tx_tracker) {
		dd_dev_warn(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", tx_rift_key.value, _rift_key_generation(tx_rift_key), _rift_key_index(tx_rift_key));
		return;
	}

	DMS_BUG_ON(tx_tracker->op != HFI1_DMS_TX_TRACKER_OP_RDMA_WRITE);

	_tracker_timestamp_update(dms, (union hfi1_dms_tracker *)tx_tracker);

	head = hfi1_dms_impl_slow_read_from_user(tx_tracker->write.mr, tx_tracker->xfer_start_byte_offset, sizeof(u64));
	tail = hfi1_dms_impl_slow_read_from_user(tx_tracker->write.mr, tx_tracker->xfer_start_byte_offset + parameters->size - sizeof(u64), sizeof(u64));

	cmd = hfi1_dms_proto_cmd_data_fixup_make(dms, tx_tracker->hdr.remote_lid, parameters->rx_id, parameters->tx_rift_key, parameters->rx_rift_key, head, tail);
	ret = hfi1_dms_impl_pio_send_or_enqueue_work(dms, (union hfi1_dms_proto_cmd *)&cmd);
	if (ret < 0) {
		dd_dev_err(dms->dd, "Failed to pio send data fixup.\n");
	}
}

int hfi1_dms_impl_handle_data_request_fixup_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	union hfi1_dms_proto_pkt_data_request_fixup * fixup = (union hfi1_dms_proto_pkt_data_request_fixup *)hdr;

	struct hfi1_dms_handle_data_request_fixup_parameters const parameters = {
		.size = fixup->info.size,
		.rx_id = _dms_return_rx_get(&hdr->bth[0]),
		.tx_rift_key = fixup->info.tx_rift_key,
		.rx_rift_key = fixup->info.rx_rift_key,
	};

	hfi1_dms_impl_handle_data_request_fixup(dms, &parameters);

	return 0;
}

void hfi1_dms_impl_handle_ack(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	union hfi1_dms_proto_pkt_ack * ack;
	struct hfi1_dms_tx_tracker *tx_tracker;

	DMS_WARN_ON(dms == NULL);
	DMS_WARN_ON(hdr == NULL);
	DMS_WARN_ON(hfi1_dms_impl_message_type_get(hdr) != HFI1_DMS_MSG_TYPE_ACK);

	ack = (union hfi1_dms_proto_pkt_ack *)hdr;

	hfi1_dms_rift_key_t const tx_rift_key = ack->info.tx_rift_key;
	DMS_BUG_ON(_rift_key_error(tx_rift_key));

	tx_tracker = (struct hfi1_dms_tx_tracker *) _rift_lookup(&dms->tx_rift, tx_rift_key);
	if (!tx_tracker) {
		dd_dev_warn(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", tx_rift_key.value, _rift_key_generation(tx_rift_key), _rift_key_index(tx_rift_key));
		return;
	}

	hfi1_dms_handle_tx_tracker_completion(dms, ack->info.tx_rift_key, ack->info.flags, ack->info.imm_data);
}

int hfi1_dms_impl_handle_write_start(struct hfi1_dms *dms, struct hfi1_dms_write_start_parameters const parameters, bool const access_lookup_is_error)
{
	int ret;
	struct hfi1_dms_access * access;
	struct hfi1_dms_client_state *client;
	u64 byte_offset_from_first_mr_page;
	struct hfi1_dms_rx_tracker *rx_tracker;

	dms_trace(dms_handle_write_start, dms, info);

	DMS_BUG_ON(dms == NULL);
	enum hfi1_dms_err_type reason = HFI1_DMS_ERR_TYPE_NONE;

	access = hfi1_dms_access_lookup(dms, parameters.dms_key, &client);
	if (!client) {
		dd_dev_info(dms->dd, "(%d) Client not found for dms_key %llu.\n", __LINE__, parameters.dms_key.value);
		reason = HFI1_DMS_ERR_TYPE_CLIENT_NOT_FOUND;
		goto nack;
	}

	if (!access) {
		if (access_lookup_is_error) {
			dd_dev_info(dms->dd, "Access not found for dms_key %llu.\n", parameters.dms_key.value);
			reason = HFI1_DMS_ERR_TYPE_ACCESS_NOT_FOUND;
			goto nack;
		}
		return -EAGAIN;
	}

	union hfi1_dms_tracker *tracker = hfi1_dms_impl_tracker_new(dms);
	if (!tracker) {
		reason = HFI1_DMS_ERR_TYPE_NO_MEMORY;
		goto nack;
	}
	rx_tracker = &tracker->rx;
	rx_tracker->op = HFI1_DMS_RX_TRACKER_OP_RDMA_WRITE;
	rx_tracker->write.start = parameters;	

	rx_tracker->hdr.remote_lid = parameters.slid;
	rx_tracker->hdr.remote_rift_key = parameters.tx_rift_key;
	rx_tracker->hdr.local_rift_key = _rift_key_create_err(HFI1_DMS_RIFT_ERR_KEY_NOT_SET);
	rx_tracker->hdr.remote_rift_key = parameters.tx_rift_key;

	rx_tracker->total_payload = parameters.size;
	rx_tracker->payload_requested = 0;
	rx_tracker->payload_remaining = parameters.size;
	rx_tracker->sbuf_offset = 0;
	rx_tracker->sbuf_start_offset = 0;

	ret = calculate_access_mr_page_offset(dms, access, parameters.offset, parameters.size, &byte_offset_from_first_mr_page);
	if (ret < 0) {
		hfi1_dms_impl_rx_tracker_free(dms, rx_tracker);
		reason = HFI1_DMS_ERR_TYPE_ACCESS_RANGE_VIOLATION;
		goto nack;
	}

	rx_tracker->rbuf_offset = byte_offset_from_first_mr_page;
	rx_tracker->rbuf_start_offset = byte_offset_from_first_mr_page;
	rx_tracker->rbuf = access->mr;

	u64 rbuf_addr = rx_tracker->rbuf->extended_vaddr.addr + rx_tracker->rbuf_start_offset;
	rx_tracker->head_misalignment = (8 - (rbuf_addr & 0x7)) & 0x7;
	rx_tracker->tail_misalignment = (rbuf_addr + parameters.size) & 0x7;

	rx_tracker->write.access = access;

	ret = access_xfer_begin(dms, access);
	if (ret < 0) {
		hfi1_dms_impl_rx_tracker_free(dms, rx_tracker);
		reason = HFI1_DMS_ERR_TYPE_ACCESS_BUSY;
		goto nack;
	}

	ret = _rift_reserve(&dms->rx_rift, HFI1_DMS_XFER_TYPE_TARGET, &rx_tracker->hdr.local_rift_key);
	if (ret < 0) {
		_rift_waitlist_add(&dms->rx_rift, HFI1_DMS_XFER_TYPE_TARGET, &rx_tracker->hdr.dlist);
		return 0;
	}
	_rift_assign(&dms->rx_rift, (union hfi1_dms_tracker *)rx_tracker, rx_tracker->hdr.local_rift_key);

	ret = _dms_rx_rift_continue_write_start(dms, rx_tracker);
	if (ret < 0) {
		_rift_release(&dms->rx_rift, rx_tracker->hdr.local_rift_key);
		access_xfer_end(dms, access, parameters.flags, parameters.imm_data, -ENOMEM);
		hfi1_dms_impl_rx_tracker_free(dms, rx_tracker);
		reason = HFI1_DMS_ERR_TYPE_NO_MEMORY;
		goto nack;
	}

	return 0;

nack:
	dd_dev_dbg(dms->dd, "(%d) Send nack packet\n", __LINE__);
	_inject_nack(dms, HFI1_DMS_MSG_TYPE_WRITE_START, reason, parameters.slid, parameters.tx_rift_key);
	return 0;
}

void hfi1_dms_impl_handle_write_start_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!hdr);

	union hfi1_dms_proto_pkt_write_start *wr = (union hfi1_dms_proto_pkt_write_start *)hdr;
	struct hfi1_dms_write_start_parameters const parameters = {
		.dms_key = wr->info.dms_key,
		.offset = wr->info.key_offset_or_vaddr,
		.imm_data = wr->info.imm_data,
		.slid = hfi1_dms_lrh16B_slid_get((u32 *) &hdr->lrh[0]),
		.size = wr->info.size,
		.tx_rift_key = {.value = (u16) ((hdr->bth[2] >> 16) & 0xFFFF)},
		.flags = (u16) ((hdr->bth[2]) & 0xFFFF),
	};

	int ret = hfi1_dms_impl_handle_write_start(dms, parameters, false);
	if (ret < 0) {
		dms->access_stall.retries = 0;
		dms->access_stall.op = HFI1_DMS_OP_RDMA_WRITE;
		dms->access_stall.write = parameters;
	}
}

void hfi1_dms_tx_tracker_cancel(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker *tx_tracker, int err)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tx_tracker);

	hfi1_dms_rift_key_t const key = tx_tracker->hdr.local_rift_key;
	enum hfi1_dms_rift_err const status = _rift_key_error(key);

	DMS_BUG_ON(status == HFI1_DMS_RIFT_ERR_KEY_DISABLED);

	if (status != HFI1_DMS_RIFT_ERR_KEY_NOT_SET) {
		// must check the "sdma waiter" list; potentially multiple
		struct hfi1_dms_sdma_tracker *sdma_waiter = (struct hfi1_dms_sdma_tracker *) dms->sdma_waiters.waitlist.head;
		while (sdma_waiter) {
			struct hfi1_dms_sdma_tracker *next = (struct hfi1_dms_sdma_tracker *) sdma_waiter->hdr.dlist.next;
			if (sdma_waiter->parameters.tx_tracker == tx_tracker) {
				hfi1_dms_impl_dlist_remove(&dms->sdma_waiters.waitlist, (struct hfi1_dms_dlist_element *)sdma_waiter);
				hfi1_dms_impl_dlist_push(&dms->trackers.free, (struct hfi1_dms_dlist_element *)sdma_waiter);
			}
			sdma_waiter = next;
		}
		_rift_release(&dms->tx_rift, key);

	} else {
		// must only be in a "tx rift waiter" list; and, therefore, NOT in the "sdma waiter" list
		if (tx_tracker->op == HFI1_DMS_TX_TRACKER_OP_RDMA_WRITE) {
			hfi1_dms_impl_dlist_remove(&dms->tx_rift.type[HFI1_DMS_XFER_TYPE_INITIATOR].waitlist, (struct hfi1_dms_dlist_element *)tx_tracker);
		} else {
			hfi1_dms_impl_dlist_remove(&dms->tx_rift.type[HFI1_DMS_XFER_TYPE_TARGET].waitlist, (struct hfi1_dms_dlist_element *)tx_tracker);
		}
	}

	// FIXME FIXME FIXME - this is not correct because there could be sdma descriptors in the ring
	// but not yet processed by the sdma engine. We can't complete the xfer until we know that
	// no sdma descriptors reference the memory associated with this xfer
	if (tx_tracker->op == HFI1_DMS_TX_TRACKER_OP_RDMA_READ) {
		access_xfer_end(dms, tx_tracker->read.access, tx_tracker->read.start.flags, tx_tracker->read.start.imm_data, err);
		hfi1_dms_impl_tx_tracker_free(dms, tx_tracker);
		_dms_tx_rift_poll(dms, HFI1_DMS_XFER_TYPE_TARGET);

	} else if (tx_tracker->op == HFI1_DMS_TX_TRACKER_OP_RDMA_WRITE) {
		tx_tracker->write.completion.fn(&tx_tracker->write.completion.cookie, err);
		hfi1_dms_impl_tx_tracker_free(dms, tx_tracker);
		_dms_tx_rift_poll(dms, HFI1_DMS_XFER_TYPE_INITIATOR);
	}
	_sdma_waitlist_poll(dms);
}

void hfi1_dms_rx_tracker_cancel(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *rx_tracker, int err)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);

	hfi1_dms_rift_key_t const key = rx_tracker->hdr.local_rift_key;
	enum hfi1_dms_rift_err const status = _rift_key_error(key);

	DMS_BUG_ON(status == HFI1_DMS_RIFT_ERR_KEY_DISABLED);

	if (status != HFI1_DMS_RIFT_ERR_KEY_NOT_SET) {

		// remove from tidset waiter rings
		for (enum hfi1_dms_tidset_waiter_type type = HFI1_DMS_TIDSET_WAITER_TYPE_READ; type < HFI1_DMS_TIDSET_WAITER_TYPE_COUNT; ++type) {
			DMS_BUG_ON(dms->tidset_waiters[type].head > dms->tidset_waiters[type].tail);

			u64 cancel = 0;
			u64 const head =  dms->tidset_waiters[type].head;
			u64 const tail =  dms->tidset_waiters[type].tail;
			u64 const count = tail - head;
			u64 const mask = HFI1_DMS_ARRAY_SIZE(dms->tidset_waiters[type].ring) - 1;

			if (count == 0)
				continue;
			
			if (_dms_tidset_waiter_head(dms, type) == rx_tracker) {
				// special case: remove from head;
				dms->tidset_waiters[type].head += 1;
				break;
			} else if (_dms_tidset_waiter_tail(dms, type) == rx_tracker) {
				// special case: remove from tail;
				dms->tidset_waiters[type].tail -= 1;
				break;
			} else {
				// general case: remove from middle; must iterate entire ring in order to "compact" the ring after
				// potentially removing a middle entry.

				for (u64 i = 0; i < count; ++i) {
					u64 const idx = (head + i) & mask;
					union hfi1_dms_tracker * tracker = _rift_lookup(&dms->rx_rift, dms->tidset_waiters[type].ring[idx]);
					if ((struct hfi1_dms_rx_tracker *)tracker == rx_tracker) {
						cancel += 1;
					} else {
						u64 const new_idx = (head + i - cancel) & mask;
						dms->tidset_waiters[type].ring[new_idx] = dms->tidset_waiters[type].ring[idx];
					}
				}
				if (cancel) {
					u64 const new_tail = head + count - cancel;
					dms->tidset_waiters[type].tail = new_tail;
					break;
				}
			}
		}

		// even with/without tidset waiter(s) there might be one or more active tidsets that must be disabled.
		u32 const sz = HFI1_DMS_ARRAY_SIZE(dms->read_requests);
		for (u32 tid_set = 0; tid_set < sz; ++tid_set) {
			union hfi1_dms_tracker * tracker = (union hfi1_dms_tracker *) dms->read_requests[tid_set].rx_tracker;
			if (((struct hfi1_dms_rx_tracker *)tracker == rx_tracker) && (dms->read_requests[tid_set].state == HFI1_DMS_TIDSET_STATE_ENABLED)) {
				_tidset_disable(dms, tid_set);
			}
		}

		// last, cancel the rx rift entry
		_rift_cancel(&dms->rx_rift, key);

	} else {
		// must only be in a "rx rift waiter" list; and, therefore, NOT in "tidset waiter"
		if (rx_tracker->op == HFI1_DMS_RX_TRACKER_OP_RDMA_READ) {
			hfi1_dms_impl_dlist_remove(&dms->rx_rift.type[HFI1_DMS_XFER_TYPE_INITIATOR].waitlist, (struct hfi1_dms_dlist_element *)rx_tracker);
		} else {
			hfi1_dms_impl_dlist_remove(&dms->rx_rift.type[HFI1_DMS_XFER_TYPE_TARGET].waitlist, (struct hfi1_dms_dlist_element *)rx_tracker);
		}
	}

	if (rx_tracker->op == HFI1_DMS_RX_TRACKER_OP_RDMA_READ) {
		rx_tracker->read.completion.fn(&rx_tracker->read.completion.cookie, err);
		hfi1_dms_impl_rx_tracker_free(dms, rx_tracker);
		_dms_rx_rift_poll(dms, HFI1_DMS_XFER_TYPE_INITIATOR);

	} else { // HFI1_DMS_RX_TRACKER_OP_RDMA_WRITE
		access_xfer_end(dms, rx_tracker->write.access, rx_tracker->write.start.flags, rx_tracker->write.start.imm_data, err);
		hfi1_dms_impl_rx_tracker_free(dms, rx_tracker);
		_dms_rx_rift_poll(dms, HFI1_DMS_XFER_TYPE_TARGET);
	}

	_dms_tidset_waiters_poll(dms);
}

void hfi1_dms_impl_handle_nack_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	union hfi1_dms_pkt_nack *nack;
	struct hfi1_dms_tx_tracker *tx_tracker;
	struct hfi1_dms_rx_tracker *rx_tracker;

	DMS_WARN_ON(!dms);
	DMS_WARN_ON(!hdr);
	DMS_WARN_ON(hfi1_dms_impl_message_type_get(hdr) != HFI1_DMS_MSG_TYPE_NACK);

	nack = (union hfi1_dms_pkt_nack *)hdr;
	DMS_WARN_ON(nack->info.err_type == HFI1_DMS_ERR_TYPE_NONE);

	hfi1_dms_rift_key_t const nack_rift_key = nack->info.rift_key;
	DMS_BUG_ON(_rift_key_error(nack_rift_key));

	int err = 0;
	switch (nack->info.err_type) {
		case HFI1_DMS_ERR_TYPE_CLIENT_NOT_FOUND:
			err = -EINVAL;
			break;
		case HFI1_DMS_ERR_TYPE_ACCESS_NOT_FOUND:
			err = -EINVAL;
			break;
		case HFI1_DMS_ERR_TYPE_ACCESS_RANGE_VIOLATION:
			err = -EACCES;
			break;
		case HFI1_DMS_ERR_TYPE_NO_MEMORY:
			err = -ENOMEM;
			break;
		case HFI1_DMS_ERR_TYPE_ACCESS_BUSY:
			err = -EBUSY;
			break;
		default:
			err = -EPROTO;
			break;
	}

	switch (nack->info.msg_type) {
		case HFI1_DMS_MSG_TYPE_WRITE_START:
			tx_tracker = (struct hfi1_dms_tx_tracker *) _rift_lookup(&dms->tx_rift, nack_rift_key);
			if (!tx_tracker) {
				dd_dev_dbg(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", nack_rift_key.value, _rift_key_generation(nack_rift_key), _rift_key_index(nack_rift_key));
				return;
			}
			hfi1_dms_tx_tracker_cancel(dms, tx_tracker, err);
			break;

		case HFI1_DMS_MSG_TYPE_READ_START:
			rx_tracker = (struct hfi1_dms_rx_tracker *) _rift_lookup(&dms->rx_rift, nack_rift_key);
			if (!rx_tracker) {
				dd_dev_dbg(dms->dd, "Ignore invalid rx rift key 0x%04hx (%hu %hu)\n", nack_rift_key.value, _rift_key_generation(nack_rift_key), _rift_key_index(nack_rift_key));
				return;
			}
			hfi1_dms_rx_tracker_cancel(dms, rx_tracker, err);
			break;

		default:
			dd_dev_dbg(dms->dd, "Received NACK for unknown message type %u with rift index: %hu, error type: %u\n", nack->info.msg_type, nack->info.rift_key.value, nack->info.err_type);
			break;
	}
}

static union hfi1_dms_tracker * _locate_tracker(struct hfi1_dms *dms, struct hfi1_dms_rift *rift, hfi1_dms_rift_key_t const local_rift_key, hfi1_dms_rift_key_t const remote_rift_key)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(_rift_key_error(remote_rift_key) != HFI1_DMS_RIFT_ERR_NONE);

	enum hfi1_dms_rift_err const err = _rift_key_error(local_rift_key);
	union hfi1_dms_tracker *tracker;

	if (err == HFI1_DMS_RIFT_ERR_NONE) {
		return _rift_lookup(rift, local_rift_key);

	} else if (err == HFI1_DMS_RIFT_ERR_KEY_NOT_SET) {

		dd_dev_dbg(dms->dd, "(%d)   Searching rift->arr[] for tracker with remote_rift_key %05hu\n", __LINE__, remote_rift_key.value);
		tracker = _rift_search(rift, remote_rift_key);
		if (tracker) {
			return tracker;

		} else {
			struct hfi1_dms_dlist_element *waiter;
			enum hfi1_dms_xfer_type const local_type = _rift_key_opposite_type(remote_rift_key);
			dd_dev_dbg(dms->dd, "(%d)   Searching rift->type[%u].waitlist for tracker with remote_rift_key %05hu\n", __LINE__, local_type, remote_rift_key.value);
			waiter = rift->type[local_type].waitlist.head;
			while (waiter) {
				tracker = container_of(waiter, union hfi1_dms_tracker, hdr.dlist);
				if (tracker->hdr.remote_rift_key.value == remote_rift_key.value) {
					return tracker;
				}
				waiter = waiter->next;
			}
		}
	}

	return NULL;
}

void hfi1_dms_impl_handle_status_packet(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr)
{
	union hfi1_dms_tracker * tracker = NULL;
	union hfi1_dms_pkt_status *pkt = (union hfi1_dms_pkt_status *)hdr;
	u32 const remote_lid = hfi1_dms_lrh16B_slid_get((u32 *) &hdr->lrh[0]);
	hfi1_dms_rift_key_t const rx_rift_key = pkt->info.rx_rift_key;
	hfi1_dms_rift_key_t const tx_rift_key = pkt->info.tx_rift_key;

	DMS_BUG_ON(!dms);

	switch (pkt->info.type) {
		case HFI1_DMS_STATUS_TYPE_RX_REQUEST:
			{
				dd_dev_dbg(dms->dd, "(%d) Received rx status request  (l:%05hu r:%05hu)\n", __LINE__, rx_rift_key.value, tx_rift_key.value);
				if (_locate_tracker(dms, &dms->rx_rift, rx_rift_key, tx_rift_key)) {
					hfi1_dms_impl_inject_status(dms, remote_lid, rx_rift_key, tx_rift_key, HFI1_DMS_STATUS_TYPE_RX_RESPONSE_OK, 0);
				} else {
					hfi1_dms_impl_inject_status(dms, remote_lid, rx_rift_key, tx_rift_key, HFI1_DMS_STATUS_TYPE_RX_RESPONSE_NOT_FOUND, 0);
				}
			}
			break;
		case HFI1_DMS_STATUS_TYPE_RX_RESPONSE_OK:
			{
				dd_dev_dbg(dms->dd, "(%d) Received rx status response (l:%05hu r:%05hu) .. OK\n", __LINE__, tx_rift_key.value, rx_rift_key.value);
				DMS_BUG_ON(_rift_key_error(tx_rift_key));
				tracker = _rift_lookup(&dms->tx_rift, tx_rift_key);
				if (tracker) {
					tracker->hdr.remote_status_pending = false;
					_tracker_timestamp_update(dms, tracker);
				}
			}
			break;
		case HFI1_DMS_STATUS_TYPE_RX_RESPONSE_NOT_FOUND:
			{
				dd_dev_dbg(dms->dd, "(%d) Received rx status response (l:%05hu r:%05hu) .. NOT FOUND\n", __LINE__, tx_rift_key.value, rx_rift_key.value);
				DMS_BUG_ON(_rift_key_error(tx_rift_key));
				tracker = _rift_lookup(&dms->tx_rift, tx_rift_key);
				if (tracker) {
					dd_dev_dbg(dms->dd, "(%d)   Cancel tracker with tx_rift_key %05hu\n", __LINE__, tx_rift_key.value);
					hfi1_dms_tx_tracker_cancel(dms, &tracker->tx, -ENOMSG);
				} else {
					dd_dev_dbg(dms->dd, "(%d)   Did not find tracker with tx_rift_key %05hu; perhaps it was already successfully completed?\n", __LINE__, tx_rift_key.value);
				}
			}
			break;
		case HFI1_DMS_STATUS_TYPE_TX_REQUEST:
			{
				dd_dev_dbg(dms->dd, "(%d) Received tx status request  (l:%05hu r:%05hu)\n", __LINE__, tx_rift_key.value, rx_rift_key.value);
				DMS_BUG_ON(_rift_key_error(rx_rift_key));
				if (_locate_tracker(dms, &dms->tx_rift, tx_rift_key, rx_rift_key)) {
					hfi1_dms_impl_inject_status(dms, remote_lid, rx_rift_key, tx_rift_key, HFI1_DMS_STATUS_TYPE_TX_RESPONSE_OK, 0);
				} else {
					hfi1_dms_impl_inject_status(dms, remote_lid, rx_rift_key, tx_rift_key, HFI1_DMS_STATUS_TYPE_TX_RESPONSE_NOT_FOUND, 0);
				}
			}
			break;
		case HFI1_DMS_STATUS_TYPE_TX_RESPONSE_OK:
			{
				dd_dev_dbg(dms->dd, "(%d) Received tx status response (l:%05hu r:%05hu) .. OK\n", __LINE__, rx_rift_key.value, tx_rift_key.value);
				DMS_BUG_ON(_rift_key_error(rx_rift_key));
				tracker = _rift_lookup(&dms->rx_rift, rx_rift_key);
				if (tracker) {
					tracker->hdr.remote_status_pending = false;
					_tracker_timestamp_update(dms, tracker);
				}
			}
			break;
		case HFI1_DMS_STATUS_TYPE_TX_RESPONSE_NOT_FOUND:
			{
				dd_dev_dbg(dms->dd, "(%d) Received tx status response (l:%05hu r:%05hu) .. NOT FOUND\n", __LINE__, rx_rift_key.value, tx_rift_key.value);
				DMS_BUG_ON(_rift_key_error(rx_rift_key));
				tracker = _rift_lookup(&dms->rx_rift, rx_rift_key);
				if (tracker) {
					dd_dev_dbg(dms->dd, "(%d)   Cancel tracker with rx_rift_key %05hu\n", __LINE__, rx_rift_key.value);
					hfi1_dms_rx_tracker_cancel(dms, &tracker->rx, -ENOMSG);
				} else {
					dd_dev_dbg(dms->dd, "(%d)   Did not find tracker with rx_rift_key %05hu; perhaps it was already successfully completed?\n", __LINE__, rx_rift_key.value);
				}
			}
			break;
		default:
			dd_dev_warn(dms->dd, "Received status packet with unknown type: %u\n", pkt->info.type);
			break;
	}
}

u32 hfi1_dms_impl_data_request_size_qw_get(union hfi1_dms_16b_header *hdr)
{
	u32 ret;

	DMS_BUG_ON(hdr == NULL);
	ret = (u32) ((hdr->bth[2] >> 16) & 0xFFFF);
	return ret;
}

void hfi1_dms_impl_lrh16bc_dlid_set(u64 *lrh16bc, u32 dlid)
{
	u64 newlrh;

	DMS_BUG_ON(lrh16bc == NULL);
	newlrh = (*lrh16bc & ~0xFFFFFFull) | (dlid & 0xFFFFFF);

	*lrh16bc = newlrh;
}

void hfi1_dms_impl_lrh16bc_len_qws_set(u64 *lrh16bc, u32 len_qws)
{
	DMS_BUG_ON(lrh16bc == NULL);

	// Set the length in QWs in the LRH16BC
	*lrh16bc = (*lrh16bc & ~(HFI1_DMS_LRH16BC_LEN_QW_MASK << HFI1_DMS_LRH16BC_LEN_QW_SHIFT)) | (
		((u64) (len_qws & HFI1_DMS_LRH16BC_LEN_QW_MASK) << HFI1_DMS_LRH16BC_LEN_QW_SHIFT));
}

void hfi1_dms_impl_pbc_dlid_set(u64 *pbc, u32 dlid)
{
	DMS_BUG_ON(pbc == NULL);

	// Set the DLID in the PBC
	*pbc = (*pbc & ~(((u64) PBC_DLID_MASK << PBC_DLID_SHIFT))) |
	       ((u64) (dlid & PBC_DLID_MASK) << PBC_DLID_SHIFT);
}

static void hfi1_dms_impl_pbc_length_dws_set(u64 *pbc, u32 length_dws)
{
	DMS_BUG_ON(pbc == NULL);

	// Set the length in DWords in the PBC
	*pbc = (*pbc & ~(((u64) PBC_LENGTH_DWS_MASK << PBC_LENGTH_DWS_SHIFT))) |
	       ((u64) (length_dws & PBC_LENGTH_DWS_MASK) << PBC_LENGTH_DWS_SHIFT);
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

	// 64 byte 16B compressed header (with PBC) + payload + 2 dws for 16B tail flit
	ret = 16 + payload_dws + 2;
	return ret;
}

static void hfi1_dms_impl_data_packet_header_make(struct hfi1_dms *dms, union hfi1_dms_proto_cmd_data *cmd, u32 nbytes, u32 dlid, u8 rx, u32 tid_info, hfi1_dms_rift_key_t tx_rift_key,
		u64 head, u64 tail, enum hfi1_dms_sdma_type sdma_type)
{
	u32 payload_dws;
	u32 pbc_pktlen_dws;
	u32 pktlen_qws;
	union hfi1_dms_proto_cmd_data *data_template;
	u64 cmd_data_qw_size;
	u64 i;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(cmd == NULL);

	payload_dws = (nbytes + 3) >> 2;
	pbc_pktlen_dws = hfi1_dms_impl_data_pktlen_dws_from_payload_dws(payload_dws);
	pktlen_qws = pbc_pktlen_dws >> 1;

	enum hfi1_dms_msg_type const msg_type =
		sdma_type == HFI1_DMS_SDMA_TYPE_DATA ?
			HFI1_DMS_MSG_TYPE_DATA :
			HFI1_DMS_MSG_TYPE_DATA_START;
	data_template = (union hfi1_dms_proto_cmd_data *) &dms->protocol_cmd_templates[msg_type];
	cmd_data_qw_size = sizeof(union hfi1_dms_proto_cmd_data) >> 3;
	for (i = 0; i < cmd_data_qw_size; ++i) {
		cmd->qws[i] = data_template->qws[i];
	}
	hfi1_dms_impl_lrh16bc_dlid_set(&cmd->lrh16bc, dlid);
	hfi1_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc, pktlen_qws);

	cmd->info.kdeth[0] = tid_info;
	cmd->info.tx_rift_key = tx_rift_key;
	cmd->info.head = head;
	cmd->info.tail = tail;

	_dms_destqp_rx_set(&cmd->info.bth[0], rx);
	hfi1_dms_impl_pbc_dlid_set(&cmd->pbc, dlid);
	hfi1_dms_impl_pbc_length_dws_set(&cmd->pbc, pbc_pktlen_dws);
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
static struct hfi1_dms_impl_fill_state hfi1_dms_impl_fill_payload(struct sdma_desc *start_desc, u64 nbytes, u64 sbuf_page_offset, dma_addr_t *phys_addrs)
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

	DMS_BUG_ON(start_desc == NULL);
	DMS_BUG_ON(phys_addrs == NULL);
	DMS_BUG_ON((PHYS_PAGE_SIZE & (PHYS_PAGE_SIZE - 1)) != 0);
	DMS_BUG_ON(nbytes > HFI1_DMS_MAX_PAYLOAD_SIZE);

	offset = sbuf_page_offset;
	desc = start_desc;

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
static struct hfi1_dms_impl_fill_state hfi1_dms_impl_fill_first_packet_descriptors(struct hfi1_dms *dms, struct hfi1_dms_impl_fill_state initial_fill_state, hfi1_dms_rift_key_t tx_rift_key, u32 nbytes, u32 dlid, u8 rx, u32 tid_info, u8 ahg_idx, struct hfi1_dms_mem_coh *ahg_header,
		u64 head_qw, u64 tail_qw, enum hfi1_dms_sdma_type sdma_type)
{
	u64 start;
	struct sdma_desc *desc;
	struct hfi1_dms_impl_fill_state fill_state;
	union hfi1_dms_proto_cmd_data *data_header;
	u64 HEADER_SIZE = 64;
	phys_addr_t phys_addr;
	u64 end;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(initial_fill_state.cur_desc == NULL);
	DMS_BUG_ON(initial_fill_state.phys_addrs == NULL);
	DMS_BUG_ON(nbytes == 0);
	DMS_BUG_ON((nbytes & 0x7) != 0);
	DMS_BUG_ON(dlid == 0);
	DMS_BUG_ON(ahg_header == NULL);
	start = dms_rdtsc();

	// Fill the first packet descriptor
	desc = initial_fill_state.cur_desc;
	fill_state = initial_fill_state;

	data_header = (union hfi1_dms_proto_cmd_data *) ahg_header->kvaddr;
	hfi1_dms_impl_data_packet_header_make(dms, data_header, nbytes, dlid, rx, tid_info, tx_rift_key, head_qw, tail_qw, sdma_type);

	*desc = (struct sdma_desc){0};
	phys_addr = ahg_header->phys_addr;
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
	end = dms_rdtsc();
	dms->counters.first_packet_send += end - start;

	return fill_state; // Success
}

int hfi1_dms_impl_sdma_send(struct hfi1_dms *dms, struct hfi1_dms_mr * mr, u64 page_offset, u32 nbytes, u32 dlid, u8 rx_id, u32 tid_info, hfi1_dms_rift_key_t tx_rift_key,
		u64 head_qw, u64 tail_qw, enum hfi1_dms_sdma_type sdma_type)
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
	struct hfi1_dms_ahg_header_set *ahg_set;
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

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(mr == NULL);

	dms_trace(dms_sdma_send, dms, mr);

	start = dms_rdtsc();
	// sdma still performs send context checks on egress
	if (!(dms->sctxt->flags & SCF_ENABLED))
		return -ECOMM;
	
	ahg_set = hfi1_dms_impl_ahg_header_set_get(dms);
	if (DMS_WARN_ON(ahg_set == NULL)) {
		return -ENOMEM;
	}

	tid_offset = (tid_info & 0x7fff) << 2;
	tid = (tid_info >> 16) & 0x3ff;

	bytes_first_packet = min(nbytes, (u32) HFI1_DMS_MAX_PAYLOAD_SIZE - tid_offset);
	num_full_mtu_packets = (nbytes - bytes_first_packet) / HFI1_DMS_MAX_PAYLOAD_SIZE;
	bytes_last_packet = nbytes - (num_full_mtu_packets * HFI1_DMS_MAX_PAYLOAD_SIZE) - bytes_first_packet;

	cur_desc = &dms->desc_stack[0];

	current_fill_state = (struct hfi1_dms_impl_fill_state){
		.cur_desc = cur_desc,
		.phys_addrs = mr->dma_list,
		.page_offset = page_offset,
	};

	current_fill_state = hfi1_dms_impl_fill_first_packet_descriptors(dms, current_fill_state, tx_rift_key, bytes_first_packet, dlid, rx_id, tid_info, ahg_idx, &ahg_set->headers[nahg_mem], head_qw, tail_qw, sdma_type);
	tid += 1;
	nahg_mem += 1;
	tid_info = hfi1_dms_tid_info_update_tid(tid_info, tid);
	// clear tid_offset for the rest of the packets
	tid_info &= ~0x7fff;

	for (i = 0; i < num_full_mtu_packets; ++i) {
		// Fill the next MTU packet
		u64 bytes_to_fill = HFI1_DMS_MAX_PAYLOAD_SIZE;
		current_fill_state = hfi1_dms_impl_fill_first_packet_descriptors(dms, current_fill_state, tx_rift_key, bytes_to_fill, dlid, rx_id, tid_info, ahg_idx, &ahg_set->headers[nahg_mem], head_qw, tail_qw, sdma_type);
		nahg_mem += 1;
		tid += 1;
		tid_info = hfi1_dms_tid_info_update_tid(tid_info, tid);
	}

	if (bytes_last_packet > 0) {
		current_fill_state = hfi1_dms_impl_fill_first_packet_descriptors(dms, current_fill_state, tx_rift_key, bytes_last_packet, dlid, rx_id, tid_info, ahg_idx, &ahg_set->headers[nahg_mem], head_qw, tail_qw, sdma_type);
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
	DMS_BUG_ON(!sdma);

	while ((--sdma_engine_count >= 0) && (!__sdma_running(sdma) || (sdma_descq_freecnt(sdma) < ndesc_total))) {
		cur_sdma_engine = (cur_sdma_engine + 1) % num_sdma_engines;
		sdma = dms->sdma_engines[cur_sdma_engine];
	}
	dms->cur_sdma_engine = cur_sdma_engine;
	if (sdma_engine_count < 0) {
		// check once more now that we have read all the head values
		sdma_engine_count = num_sdma_engines;
		while ((--sdma_engine_count >= 0)) {
			sdma_gethead_dma(sdma);
			if (__sdma_running(sdma) && sdma_descq_freecnt(sdma) >= ndesc_total) {
				break;
			}
			cur_sdma_engine = (cur_sdma_engine + 1) % num_sdma_engines;
			sdma = dms->sdma_engines[cur_sdma_engine];
		}
		dms->cur_sdma_engine = cur_sdma_engine;	
	}
	if (sdma_engine_count < 0) {
		dd_dev_dbg(dms->dd, "dms: No sdma engine available. Tracker will be put back on the todo list\n");
		hfi1_dms_impl_dlist_append(&dms->ahg_headers.free, &ahg_set->dlist);
		return -EAGAIN; // TODO: this should not be an error but we don't have a "todo" list
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
	ahg_set->desc_idx = desc_tail;
	hfi1_dms_impl_dlist_append(&sdma_rsrc->active_ahg_headers, &ahg_set->dlist);

	dms->cur_sdma_engine = (dms->cur_sdma_engine + 1) % dms->num_engines;

	end = dms_rdtsc();
	dms->counters.tid_send += end - start;

	return 0;
}

int hfi1_dms_sdma_send(struct hfi1_dms *dms, struct hfi1_dms_sdma_parameters const * parameters)
{
	u64 head, tail;

	struct hfi1_dms_tx_tracker *tx_tracker = parameters->tx_tracker;

	if (parameters->include_fixup_data) {
		u64 xfer_start_byte_offset = tx_tracker->xfer_start_byte_offset;
		u64 total_payload = tx_tracker->total_payload;
		head = hfi1_dms_impl_slow_read_from_user(parameters->mr, xfer_start_byte_offset, sizeof(u64));
		tail = hfi1_dms_impl_slow_read_from_user(parameters->mr, xfer_start_byte_offset + total_payload - sizeof(u64), sizeof(u64));
	} else {
		head = 0;
		tail = 0;
	}
	
	return hfi1_dms_impl_sdma_send(dms, parameters->mr, parameters->page_offset, parameters->nbytes, tx_tracker->hdr.remote_lid, parameters->rx_id, parameters->tid_info, tx_tracker->hdr.local_rift_key,
		head, tail, parameters->sdma_type);
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

int hfi1_dms_impl_tracker_block_alloc(struct hfi1_dms *dms)
{
	static size_t const sz = sizeof(struct hfi1_dms_dlist_element) + 100 * sizeof(union hfi1_dms_tracker);
	struct hfi1_dms_dlist_element * block;
	struct hfi1_dms_dlist_element * tracker;
	size_t i;

	block = (struct hfi1_dms_dlist_element *) kzalloc(sz, GFP_KERNEL);
	if (block == NULL) {
		return -ENOMEM;
	}

	hfi1_dms_impl_dlist_push(&dms->trackers.blocklist, block);

	tracker = block + 1;
	for (i = 0; i < 100; ++i) {
		hfi1_dms_impl_dlist_push(&dms->trackers.free, tracker);
		tracker = (struct hfi1_dms_dlist_element *)((u64) tracker + sizeof(union hfi1_dms_tracker));
	}

	return 0;
}

int hfi1_dms_impl_ahg_header_block_alloc(struct hfi1_dms *dms)
{
	u64 const AHG_BACKING_ALLOC_SIZE = HFI1_DMS_AHG_HEADER_BLOCK_SIZE * HFI1_DMS_TID_SET_SIZE * sizeof(union hfi1_dms_proto_cmd_data);
	u64 const SDMA_HEADER_SIZE = sizeof(union hfi1_dms_proto_cmd_data);
	struct hfi1_dms_dlist_element *block;
	struct hfi1_dms_ahg_header_block *ahg_block;
	u64 i, j;
	struct hfi1_dms_mem_coh ahg_memory;
	struct hfi1_dms_ahg_header_set *header_set;

	block = (struct hfi1_dms_dlist_element *) kzalloc(sizeof(struct hfi1_dms_ahg_header_block), GFP_KERNEL);
	if (block == NULL) {
		return -ENOMEM;
	}
	ahg_block = (struct hfi1_dms_ahg_header_block *) block;
	ahg_block->backing_mem.kvaddr = dma_alloc_coherent(&dms->dd->pcidev->dev, AHG_BACKING_ALLOC_SIZE, &ahg_block->backing_mem.phys_addr, GFP_DMA);
	ahg_block->backing_mem.len = AHG_BACKING_ALLOC_SIZE;
	if (!ahg_block->backing_mem.kvaddr) {
		kfree(block);
		return -ENOMEM;
	}
	hfi1_dms_impl_dlist_push(&dms->ahg_headers.blocklist, block);

	for (i = 0; i < HFI1_DMS_AHG_HEADER_BLOCK_SIZE; ++i) {
		header_set = &ahg_block->header_sets[i];
		for (j = 0; j < HFI1_DMS_TID_SET_SIZE; ++j) {
			ahg_memory = (struct hfi1_dms_mem_coh){
				.kvaddr = ahg_block->backing_mem.kvaddr + ((i * HFI1_DMS_TID_SET_SIZE + j) * SDMA_HEADER_SIZE),
				.phys_addr = ahg_block->backing_mem.phys_addr + ((i * HFI1_DMS_TID_SET_SIZE + j) * SDMA_HEADER_SIZE),
				.len = SDMA_HEADER_SIZE,
			};
			header_set->headers[j] = ahg_memory;
		}
		hfi1_dms_impl_dlist_push(&dms->ahg_headers.free, &header_set->dlist);
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

void hfi1_dms_impl_tracker_block_free(struct hfi1_dms *dms)
{
	struct hfi1_dms_dlist_element * block;

	DMS_BUG_ON(dms == NULL);

	block = hfi1_dms_impl_dlist_pop(&dms->trackers.blocklist);
	while (block) {
		kfree(block);
		block = hfi1_dms_impl_dlist_pop(&dms->trackers.blocklist);
	}

	DMS_BUG_ON(dms->trackers.blocklist.head != NULL);
	DMS_BUG_ON(dms->trackers.blocklist.tail != NULL);

	dms->trackers.free.head = NULL;
	dms->trackers.free.tail = NULL;
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

union hfi1_dms_tracker * hfi1_dms_impl_tracker_new(struct hfi1_dms *dms)
{
	int ret;
	struct hfi1_dms_dlist_element * dlist_element;
	union hfi1_dms_tracker * tracker;

	DMS_BUG_ON(!dms);

	dlist_element = hfi1_dms_impl_dlist_pop(&dms->trackers.free);
	if (dlist_element == NULL) {
		ret = hfi1_dms_impl_tracker_block_alloc(dms);
		if (ret < 0) {
			return NULL;
		}
		dlist_element = hfi1_dms_impl_dlist_pop(&dms->trackers.free);
		DMS_BUG_ON(!dlist_element);
	}
	tracker = container_of(dlist_element, union hfi1_dms_tracker, hdr.dlist);

	_tracker_timestamp_init(dms, tracker);

	return tracker;
}

static struct hfi1_dms_tx_tracker *hfi1_dms_impl_tx_tracker_new(struct hfi1_dms *dms, u32 size,
		u64 byte_offset_from_first_page, u32 remote_lid, hfi1_dms_rift_key_t remote_rift_key)
{
	struct hfi1_dms_tx_tracker * tx_tracker;

	DMS_BUG_ON(!dms);

	tx_tracker = (struct hfi1_dms_tx_tracker *) hfi1_dms_impl_tracker_new(dms);
	if (!tx_tracker) {
		return NULL;
	}

	tx_tracker->hdr.local_rift_key = _rift_key_create_err(HFI1_DMS_RIFT_ERR_KEY_NOT_SET);
	tx_tracker->total_payload = size;
	tx_tracker->payload_remaining = size;
	tx_tracker->xfer_start_byte_offset = byte_offset_from_first_page;
	tx_tracker->hdr.remote_lid = remote_lid;
	tx_tracker->hdr.remote_rift_key = remote_rift_key;

	return tx_tracker;
}

struct hfi1_dms_tx_tracker *hfi1_dms_impl_tx_tracker_write_new(struct hfi1_dms *dms, u32 size,
		u64 byte_offset_from_first_page, u32 remote_lid, struct hfi1_dms_mr *mr, u64 mr_offset,
		u16 flags, u64 imm_data, struct hfi1_dms_tracker_completion const *completion, union hfi1_dms_key rx_dms_key,
		u64 rx_offset)
{
	struct hfi1_dms_tx_tracker * tx_tracker;

	DMS_BUG_ON(!dms);

	tx_tracker = hfi1_dms_impl_tx_tracker_new(dms, size, byte_offset_from_first_page, remote_lid, _rift_key_create_err(HFI1_DMS_RIFT_ERR_KEY_NOT_SET));
	if (tx_tracker) {
		tx_tracker->op = HFI1_DMS_TX_TRACKER_OP_RDMA_WRITE;
		tx_tracker->write.mr = mr;
		tx_tracker->write.completion = *completion;
		tx_tracker->write.dms_key = rx_dms_key;
		tx_tracker->write.rx_offset = rx_offset;
		tx_tracker->write.flags = flags;
		tx_tracker->write.imm_data = imm_data;
	}

	return tx_tracker;
}

static struct hfi1_dms_rx_tracker *hfi1_dms_impl_rx_tracker_new(struct hfi1_dms *dms,
							   u32 size,
							   u32 remote_lid, struct hfi1_dms_mr *rbuf, u64 rbuf_offset)
{
	struct hfi1_dms_rx_tracker * rx_tracker;

	DMS_BUG_ON(!dms);

	rx_tracker = (struct hfi1_dms_rx_tracker *) hfi1_dms_impl_tracker_new(dms);
	if (!rx_tracker) {
		return NULL;
	}

	// initialize tracker state
	rx_tracker->total_payload = size;
	rx_tracker->payload_requested = 0;
	rx_tracker->payload_remaining = size;
	rx_tracker->sbuf_offset = 0;
	rx_tracker->rbuf_offset = rbuf_offset;
	rx_tracker->rbuf_start_offset = rbuf_offset;
	rx_tracker->hdr.remote_lid = remote_lid;
	rx_tracker->hdr.local_rift_key = _rift_key_create_err(HFI1_DMS_RIFT_ERR_KEY_NOT_SET);
	rx_tracker->hdr.remote_rift_key = _rift_key_create_err(HFI1_DMS_RIFT_ERR_KEY_NOT_SET);
	rx_tracker->sbuf_start_offset = 0;

	rx_tracker->rbuf = rbuf;

	u64 rbuf_addr = rx_tracker->rbuf->extended_vaddr.addr + rx_tracker->rbuf_start_offset;
	rx_tracker->head_misalignment = (8 - (rbuf_addr & 0x7)) & 0x7;
	rx_tracker->tail_misalignment = (rbuf_addr + size) & 0x7;

	return rx_tracker;
}

struct hfi1_dms_rx_tracker *hfi1_dms_impl_rx_tracker_read_new(struct hfi1_dms *dms,
							   u32 size,
							   u64 starting_sbuf_offset, union hfi1_dms_key dms_key,
							   u32 remote_lid, struct hfi1_dms_mr *rbuf, u64 rbuf_offset,
								 u16 flags, u64 imm_data,
								 struct hfi1_dms_tracker_completion const *completion)
{
	struct hfi1_dms_rx_tracker * rx_tracker;

	DMS_BUG_ON(dms == NULL);

	rx_tracker = hfi1_dms_impl_rx_tracker_new(dms, size, remote_lid, rbuf, rbuf_offset);
	rx_tracker->sbuf_start_offset = starting_sbuf_offset;

	rx_tracker->op = HFI1_DMS_RX_TRACKER_OP_RDMA_READ;
	rx_tracker->read.dms_key = dms_key;
	rx_tracker->read.flags = flags;
	rx_tracker->read.imm_data = imm_data;
	if (!completion || !completion->fn) {
		rx_tracker->read.completion.fn = hfi1_dms_tracker_completion_fn_noop;
	} else {
		rx_tracker->read.completion = *completion;
	}

	return rx_tracker;
}

struct hfi1_dms_ahg_header_set *hfi1_dms_impl_ahg_header_set_get(struct hfi1_dms *dms)
{
	struct hfi1_dms_dlist_element * header;
	struct hfi1_dms_ahg_header_set *ret;

	DMS_BUG_ON(dms == NULL);

	header = hfi1_dms_impl_dlist_pop(&dms->ahg_headers.free);
	if (header == NULL) {
		dd_dev_dbg(dms->dd, "dms: No free AHG header available, allocating a new block.\n");
		hfi1_dms_impl_ahg_header_block_alloc(dms);
		header = hfi1_dms_impl_dlist_pop(&dms->ahg_headers.free);
		DMS_WARN_ON(header == NULL);
	}

	ret = (struct hfi1_dms_ahg_header_set *) header;
	return ret;
}

void hfi1_dms_impl_rx_tracker_free(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker * rx_tracker)
{
	DMS_BUG_ON(rx_tracker->hdr.dlist.prev != NULL);
	DMS_BUG_ON(rx_tracker->hdr.dlist.next != NULL);
	hfi1_dms_impl_dlist_push(&dms->trackers.free, (struct hfi1_dms_dlist_element *)rx_tracker);
}
void hfi1_dms_impl_tx_tracker_free(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker * tx_tracker)
{
	DMS_BUG_ON(tx_tracker->hdr.dlist.prev != NULL);
	DMS_BUG_ON(tx_tracker->hdr.dlist.next != NULL);
	hfi1_dms_impl_dlist_push(&dms->trackers.free, (struct hfi1_dms_dlist_element *)tx_tracker);
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

int _tidset_idx_peek(struct hfi1_dms *dms, u32 *tid_set)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tid_set);

	if (dms->free_tid_sets_stack_top == 0) {
		return -1; // No free TID sets available
	}

	*tid_set = dms->free_tid_sets_stack[dms->free_tid_sets_stack_top - 1];
	return 0;
}

void _tidset_idx_reserve(struct hfi1_dms *dms, u32 tid_set)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(tid_set >= HFI1_DMS_TID_SET_IDX_COUNT);
	DMS_BUG_ON(dms->read_requests[tid_set].state != HFI1_DMS_TIDSET_STATE_ENABLED);
	DMS_BUG_ON(dms->free_tid_sets_stack_top == 0);
	DMS_BUG_ON(dms->free_tid_sets_stack[dms->free_tid_sets_stack_top - 1] != tid_set);

	--dms->free_tid_sets_stack_top;
}

void _tidset_idx_release(struct hfi1_dms *dms, u32 tid_set)
{
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(tid_set >= HFI1_DMS_TID_SET_IDX_COUNT);
	DMS_BUG_ON(dms->free_tid_sets_stack_top >= HFI1_DMS_TID_SET_IDX_COUNT);

	dms->free_tid_sets_stack[dms->free_tid_sets_stack_top++] = tid_set;
}

void _configure_ctrl_rcd(struct hfi1_dms *dms, u8 pidx, struct hfi1_ctxtdata *rcd)
{
	hfi1_dms_impl_rcv_context_disable9B(dms, pidx, rcd);
	_set_ctrl_split_point(dms, pidx, rcd);
	rcd->rhf_rcv_function_map = _dms_rhf_rcv_functions_ctrl;
}
void _configure_data_rcd(struct hfi1_dms *dms, u8 pidx, struct hfi1_ctxtdata *rcd)
{
	hfi1_dms_impl_rcv_context_disable9B(dms, pidx, rcd);
	rcd->rhf_rcv_function_map = _dms_rhf_rcv_functions_data;
}

void hfi1_dms_impl_rcv_context_disable9B(struct hfi1_dms *dms, u8 pidx, struct hfi1_ctxtdata *rcd)
{
	u64 reg;

	dd_dev_dbg(dms->dd, "Disabling 9B context for pidx %u, ctxt %u\n", pidx, rcd->ctxt);

	reg = read_iprc_csr(dms->dd, pidx, rcd->ctxt, JKR_RCV_PKT_CTRL);
	dd_dev_info(dms->dd, "Current JKR_RCV_PKT_CTRL: 0x%016llx\n", reg);
	reg &= ~JKR_RCV_PKT_CTRL_L2_TYPE_ENABLE_MASK_SMASK;
	reg |= 0x4ull << JKR_RCV_PKT_CTRL_L2_TYPE_ENABLE_MASK_SHIFT;
	dd_dev_info(dms->dd, "Setting JKR_RCV_PKT_CTRL to 0x%016llx\n", reg);
	write_iprc_csr(dms->dd, pidx, rcd->ctxt, JKR_RCV_PKT_CTRL, reg);
}

void _set_ctrl_split_point(struct hfi1_dms *dms, u8 pidx, struct hfi1_ctxtdata *rcd)
{
	u64 reg;
	dd_dev_dbg(dms->dd, "Setting split point for rctxt %u to fill entire rcvhdrqentsize\n", rcd->ctxt);

	reg = read_iprc_csr(dms->dd, pidx, rcd->ctxt, JKR_RCV_PKT_CTRL);
	reg &= ~JKR_RCV_PKT_CTRL_HDR_SIZE_SMASK;
	reg |= HFI1_DMS_CTRL_HDR_SIZE << JKR_RCV_PKT_CTRL_HDR_SIZE_SHIFT;
	write_iprc_csr(dms->dd, pidx, rcd->ctxt, JKR_RCV_PKT_CTRL, reg);

}

void hfi1_dms_impl_slow_write_to_user(struct hfi1_dms_mr *mr, u64 offset, const void *data, u64 size)
{
	DMS_BUG_ON(mr == NULL);

	if (size > sizeof(u64)) {
		return;
	}

	if (offset > mr->extended_vaddr.len - size) {
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
u64 hfi1_dms_impl_slow_read_from_user(struct hfi1_dms_mr *mr, u64 offset, u64 size)
{
	DMS_BUG_ON(mr == NULL);

	u64 value = 0;

	if (size > sizeof(u64)) {
		pr_warn("DMS: tried to copy out more than a u64 from user buffer. Not currently supported - size: %llu\n", size);
		return value;
	}

	if (offset > mr->extended_vaddr.len - size) {
		pr_warn("DMS: Attempted to read beyond the end of the memory region. Offset: %llu, Size: %llu, Region Length: %lu\n", offset, size, mr->extended_vaddr.len);
		return value;
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
		memcpy(&value, kaddr_first + offset_in_page, size_first_page);
		memcpy(((char *)&value) + size_first_page, kaddr_second, size_second_page);
		kunmap_atomic(kaddr_second);
		kunmap_atomic(kaddr_first);
	} else {
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
	if (!(sc->flags & SCF_ENABLED))
		return -ECOMM;

	u64 total_size_qw = size_qw + 1; // +1 for pbc

	u32 blocks = QWORD2BLOCK_ROUND_UP(total_size_qw); // include pbc
	u32 pad_qws = ((PIO_BLOCK_SIZE - ((total_size_qw << 3) & (PIO_BLOCK_SIZE - 1))) >> 3) & 0x7;
	u32 avail = (u32) sc->credits - (sc->fill - sc->alloc_free);
	// only retry once because we've got our work queue anyway
	if (blocks > avail) {
		dd_dev_dbg(dms->dd, "PIO Not enough space, trying again");
		u64 hw_free = le64_to_cpu(*sc->hw_free);
		sc->free = hw_free & CR_COUNTER_SMASK;
		sc->alloc_free = sc->free;
		avail = (u32) sc->credits - (sc->fill - sc->alloc_free);
		if (blocks > avail) {
			return -ENOMEM;
		}
	}

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


int hfi1_dms_cmd_pio_send(struct hfi1_dms *dms, union hfi1_dms_proto_cmd * cmd)
{
	// -1 here because the pbc is included in the pbc dw length
	u64 size_qw = (hfi1_dms_impl_pbc_length_dws_get(cmd->pbc) >> 1) - 1;
	return hfi1_dms_impl_pio_send(dms, cmd->pbc, &cmd->qws[1], size_qw);
}

static int hfi1_dms_impl_pio_send_work(struct hfi1_dms *dms, struct hfi1_dms_work_item *item)
{
	union hfi1_dms_proto_cmd * cmd = (union hfi1_dms_proto_cmd *)item->data;
	int rc = hfi1_dms_cmd_pio_send(dms, cmd);
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

	ret = hfi1_dms_cmd_pio_send(dms, cmd);
	if (ret < 0) {
		//dd_dev_dbg(dms->dd, "%s:%d:%s() pio send failed, queueing work. ret=%d\n", __FILENAME__, __LINE__, __func__, ret);
		hfi1_dms_impl_queue_work_item(dms, (void*)cmd, sizeof(*cmd), hfi1_dms_impl_pio_send_work);
	}

	return 0;
}
