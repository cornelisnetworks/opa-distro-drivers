/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2025 Cornelis Networks.
 *
 */
#ifndef _HFI1_DMS_H
#define _HFI1_DMS_H

#include "mem_region.h"
#include <linux/types.h>
#include <linux/xarray.h>
#include <linux/rbtree.h>

#define HFI1_DMS_CTRL_JKEY (0xACDC)
#define HFI1_DMS_DATA_JKEY (0xACDD)
#define HFI1_DMS_MAX_TID_VALUE (1024)
#define HFI1_DMS_TID_SET_SIZE (16)
#define HFI1_DMS_TID_SET_IDX_COUNT (HFI1_DMS_MAX_TID_VALUE / HFI1_DMS_TID_SET_SIZE)
// (32 ahg indices per engine * 16 engines * 2)
#define HFI1_DMS_AHG_HEADER_BLOCK_SIZE (1024)

#define HFI1_DMS_MAX_ACCESS_FAST (1024)

#define HFI1_DMS_RIFT_IDX_BITS (10)
#define HFI1_DMS_RIFT_IDX_SIZE (1ull << HFI1_DMS_RIFT_IDX_BITS)
#define HFI1_DMS_RIFT_IDX_MASK (HFI1_DMS_RIFT_IDX_SIZE - 1)

#define HFI1_DMS_RIFT_KEY_TYPE_MASK (0x01)

#define HFI1_DMS_RIFT_GEN_BITS (5)
#define HFI1_DMS_RIFT_GEN_SIZE (1ull << HFI1_DMS_RIFT_GEN_BITS)
#define HFI1_DMS_RIFT_GEN_MASK ((HFI1_DMS_RIFT_GEN_SIZE - 1) << HFI1_DMS_RIFT_IDX_BITS)

#define HFI1_DMS_RIFT_ERR_BITS (1)
#define HFI1_DMS_RIFT_ERR_MASK (1ull << (16 - HFI1_DMS_RIFT_ERR_BITS))

#define HFI1_DMS_RIFT_KEY_TYPE_RX_COUNT (HFI1_DMS_TID_SET_IDX_COUNT * 2)

typedef struct {u16 value;} hfi1_dms_rift_key_t;

enum hfi1_dms_rift_err {
	HFI1_DMS_RIFT_ERR_NONE = 0,
	HFI1_DMS_RIFT_ERR_KEY_NOT_SET,
	HFI1_DMS_RIFT_ERR_KEY_DISABLED,
};

struct sdma_engine;

struct hfi1_dms_dlist_element {
	struct hfi1_dms_dlist_element * prev;
	struct hfi1_dms_dlist_element * next;
};

struct hfi1_dms_dlist {
	struct hfi1_dms_dlist_element * head;
	struct hfi1_dms_dlist_element * tail;
};

union hfi1_dms_proto_cmd {
	u64 qws[16];
	struct {
		u64 pbc;
		u64 lrh16bc;
		u32 bth[3];
		u32 kdeth[2];
		u32 user_kdeth[5];
		u64 tail_flit; // this is the tail flit if message is only 1 SCB in size
		u64 additional_data[8]; // else the last u64 of this array is the tail flit
	};
} __attribute__((packed, aligned(4)));

union hfi1_dms_completion_cookie {
	u8 byte[64];
	u32 dw[16];
	u64 qw[8];
};

typedef void (*hfi1_dms_completion_fn)(union hfi1_dms_completion_cookie *, int);

struct hfi1_dms_tracker_completion {
	hfi1_dms_completion_fn fn;
	union hfi1_dms_completion_cookie cookie;
};

enum hfi1_dms_mr_mode {
	HFI1_DMS_MR_MODE_OFFSET = 0,
	HFI1_DMS_MR_MODE_VADDR = 1,
};

struct hfi1_dms_mr {
	struct {
		unsigned long addr;
		unsigned long len;
	} extended_vaddr;
	
	dma_addr_t *dma_list;
	unsigned int npages_total;

	struct {
		unsigned long addr;	// user unaligned vaddr of start of buffer
		unsigned long len;  // number of bytes in the user buffer
	} user;
	u64 region_offset; // offset into the mr (from the first page address) where the user buffer starts
	enum hfi1_dms_mr_mode mode;
	u32 active_count;

	int (*pinned_check_fn)(struct hfi1_dms_mr *mr, unsigned int start_page_index, unsigned int npages_to_request);
	int (*dms_mr_memcpy_fn)(struct hfi1_dms_mr *mr, u64 offset, u64 size, void *data, const bool is_read);
};

enum hfi1_dms_access_type {
	HFI1_DMS_ACCESS_TYPE_PERSISTENT = 0,
	HFI1_DMS_ACCESS_TYPE_EPHEMERAL = 1,
};

typedef void (*hfi1_dms_access_completion_fn)(union hfi1_dms_completion_cookie *, u16, u64, int);

struct hfi1_dms_access_completion {
	hfi1_dms_access_completion_fn fn;
	union hfi1_dms_completion_cookie cookie;
};

union hfi1_dms_key {
	u64 value;
	struct {
		u32 access;
		u32 client;
	};
};

struct hfi1_dms_access {
	struct rb_node node;
	struct hfi1_dms_dlist_element element;
	union hfi1_dms_key dms_key;
	enum hfi1_dms_access_type type;
	struct hfi1_dms_access_completion completion;
	struct hfi1_dms_mr *mr; // memory region this access is for
	u64 offset; // offset into the memory region
	u64 size; // size of the access in bytes
	u32 active_count; // number of transfers currently using this access
};

struct hfi1_dms_read_start_parameters {
	union hfi1_dms_key dms_key;
	u64 offset; // offset into access buffer; interpreted on the target as either a byte offset or a virtual address
	u64 imm_data;
	u32 tbytes;
	u32 tid_info;
	u32 slid;
	u16 flags;
	hfi1_dms_rift_key_t rx_rift_key;
	u16 size_qw;
	u8 rx_id;
	u8 tail_misalignment;
	u8 head_misalignment;
	bool ordered;
	u64 order_key;
};

struct hfi1_dms_write_start_parameters {
	union hfi1_dms_key dms_key;
	u64 offset; // offset into access buffer; interpreted on the target as either a byte offset or a virtual address
	u64 imm_data;
	u32 slid;
	u32 size;
	hfi1_dms_rift_key_t tx_rift_key;
	u16 flags;
	bool ordered;
	u64 order_key;
};

struct hfi1_dms_order_domain;

enum hfi1_dms_xfer_type {
	HFI1_DMS_XFER_TYPE_TARGET = 0,
	HFI1_DMS_XFER_TYPE_INITIATOR,
	HFI1_DMS_XFER_TYPE_COUNT,
	HFI1_DMS_XFER_TYPE_NONE,
};

enum hfi1_dms_xfer_side {
	HFI1_DMS_XFER_SIDE_RX = 0,
	HFI1_DMS_XFER_SIDE_TX,
	HFI1_DMS_XFER_SIDE_COUNT,
	HFI1_DMS_XFER_SIDE_NONE,
};

enum hfi1_dms_xfer_op {
	HFI1_DMS_XFER_OP_WRITE = 0,
	HFI1_DMS_XFER_OP_READ,
	HFI1_DMS_XFER_OP_COUNT,
	HFI1_DMS_XFER_OP_NONE,
};

struct hfi1_dms_ring {
	u64 head;
	u64 tail;
	u64 mask;
	u32 size;
	u32 max_size;
};

struct hfi1_dms_tracker_perf {
	ktime_t lifetime[2];
	ktime_t rift_wait[2];
};

struct hfi1_dms_tracker_hdr {
	struct hfi1_dms_dlist_element dlist;

	ktime_t init_activity;
	ktime_t first_activity;
	ktime_t last_activity;
	bool remote_status_pending;

	hfi1_dms_rift_key_t local_rift_key;
	hfi1_dms_rift_key_t remote_rift_key;
	u32 remote_lid;
	bool ordered;
	u64 order_key;
	struct hfi1_dms_order_domain *order_domain;

	u32 status_req_count;
	u32 status_rsp_count;

	struct {
		u64 rx;	// tid + eager
		u64 tx; // sdma + eager
		u64 eager;
	} fence;

	u64 order_domain_message_id;

	enum hfi1_dms_xfer_type type;
	enum hfi1_dms_xfer_side side;
	enum hfi1_dms_xfer_op op;

	struct hfi1_dms_tracker_perf perf;
};

struct hfi1_dms_sdma_waiters {
	struct hfi1_dms_dlist waitlist;
};

enum hfi1_dms_tx_tracker_op {
	HFI1_DMS_TX_TRACKER_OP_RDMA_WRITE = 0,
	HFI1_DMS_TX_TRACKER_OP_RDMA_READ,

	HFI1_DMS_TX_TRACKER_OP_COUNT,
};

struct hfi1_dms_tx_tracker {
	struct hfi1_dms_tracker_hdr hdr;

	u32 total_payload;
	u32 payload_remaining;

	u32 xfer_start_byte_offset; // byte offset from start of first mr page to the start of the xfer buffer
	bool first_data_request_received;

	struct hfi1_dms_sdma_waiters sdma_waiters;

	enum hfi1_dms_tx_tracker_op op;
	union {
		struct {
			struct hfi1_dms_mr *mr;
			struct hfi1_dms_tracker_completion completion;
			union hfi1_dms_key dms_key;
			u64 rx_offset;
			u64 imm_data;
			u16 flags;
		} write;
		struct {
			struct hfi1_dms_access * access;
			struct hfi1_dms_read_start_parameters start;
			u64 imm_data;
			u16 flags;
			u64 head;
			u64 tail;
		} read;
	};
};

enum hfi1_dms_sdma_type {
	HFI1_DMS_SDMA_TYPE_START = 0,
	HFI1_DMS_SDMA_TYPE_DATA,

	HFI1_DMS_SDMA_TYPE_COUNT
};

enum hfi1_dms_sdma_engine_idx {
	HFI1_DMS_SDMA_ENGINE_IDX_0 = 0,
	HFI1_DMS_SDMA_ENGINE_IDX_1,
	HFI1_DMS_SDMA_ENGINE_IDX_2,
	HFI1_DMS_SDMA_ENGINE_IDX_3,
	HFI1_DMS_SDMA_ENGINE_IDX_4,
	HFI1_DMS_SDMA_ENGINE_IDX_5,
	HFI1_DMS_SDMA_ENGINE_IDX_6,
	HFI1_DMS_SDMA_ENGINE_IDX_7,
	HFI1_DMS_SDMA_ENGINE_IDX_8,
	HFI1_DMS_SDMA_ENGINE_IDX_9,
	HFI1_DMS_SDMA_ENGINE_IDX_10,
	HFI1_DMS_SDMA_ENGINE_IDX_11,
	HFI1_DMS_SDMA_ENGINE_IDX_12,
	HFI1_DMS_SDMA_ENGINE_IDX_13,
	HFI1_DMS_SDMA_ENGINE_IDX_14,
	HFI1_DMS_SDMA_ENGINE_IDX_15,
	HFI1_DMS_SDMA_ENGINE_IDX_ANY,

	HFI1_DMS_SDMA_ENGINE_IDX_COUNT,
};

struct hfi1_dms_sdma_parameters {
	u32 tid_info;
	enum hfi1_dms_sdma_type sdma_type;
	u8 rx_id;
	u8 head_misalignment;
	u8 tail_misalignment;
};

struct hfi1_dms_sdma_info {
	hfi1_dms_rift_key_t local_rift_key;
	struct hfi1_dms_mr *mr;
	u64 page_offset;
	u32 nbytes;
	union {
		struct hfi1_dms_sdma_parameters parameters;
		union hfi1_dms_proto_cmd cmd;
	};
};

struct hfi1_dms;
typedef int (*hfi1_dms_sdma_inject_fn)(struct hfi1_dms *, enum hfi1_dms_sdma_engine_idx const, struct hfi1_dms_sdma_info const *);

struct hfi1_dms_sdma_tracker {
	struct hfi1_dms_tracker_hdr hdr;
	struct hfi1_dms_sdma_info info;
	hfi1_dms_sdma_inject_fn inject;
	u64 xfer_bytes;
};

enum hfi1_dms_rx_tracker_op {
	HFI1_DMS_RX_TRACKER_OP_RDMA_WRITE = 0,
	HFI1_DMS_RX_TRACKER_OP_RDMA_READ,

	HFI1_DMS_RX_TRACKER_OP_COUNT,
 };

struct hfi1_dms_rx_tracker {
	struct hfi1_dms_tracker_hdr hdr;

	u32 payload_requested;
	u32 payload_remaining;
	u32 total_payload;

	u32 sbuf_offset; // Current offset into the _user region_ of the sbuf on the other side
	u64 rbuf_offset; // Current absolute offset into rbuf
	u64 rbuf_start_offset; // Offset into the rbuf where the data starts
	u64 sbuf_start_offset; // Offset into the sbuf where the data starts; interpreted on the remote as either a byte offset or a virtual address

	// receiving buffer
	struct hfi1_dms_mr *rbuf;
	u8 head_misalignment;
	u8 tail_misalignment;
	bool fixup_request_needed;
	bool fixup_request_pending;
	bool fixup_response_received;


	enum hfi1_dms_rx_tracker_op op;
	union {
		struct {
			struct hfi1_dms_access * access;
			struct hfi1_dms_write_start_parameters start;
		} write;

		struct {
			union hfi1_dms_key dms_key;
			struct hfi1_dms_tracker_completion completion;
			u16 flags;
			u16 unused[3];
			u64 imm_data;
			u64 head;
			u64 tail;
			struct {
				u32 id;
				u32 tid_info;
				u64 read_size_qw;
			} tidset;
		} read;

	};
};

enum hfi1_dms_tidset_state {
	HFI1_DMS_TIDSET_STATE_FREE = 0,
	HFI1_DMS_TIDSET_STATE_ENABLED,
	HFI1_DMS_TIDSET_STATE_DISABLED
};

struct hfi1_dms_read_request_state {
	u64 remaining_qws;
	u64 total_requested_qws;
	struct hfi1_dms_rx_tracker *rx_tracker;
	u32 tid_set;
	enum hfi1_dms_tidset_state state;
	ktime_t disable_ts;
	struct {
		ktime_t begin;
		ktime_t tidset_enabled;
		ktime_t first_data;
		ktime_t end;
	} perf;
};

struct hfi1_dms_tracker_mgr {
	struct hfi1_dms_dlist free;
	struct hfi1_dms_dlist blocklist;
};

struct hfi1_dms;
struct hfi1_dms_work_item;
typedef int (*hfi1_dms_work_fn)(struct hfi1_dms *dms, struct hfi1_dms_work_item *item);

struct hfi1_dms_work_item {
	struct hfi1_dms_dlist_element dlist;
	hfi1_dms_work_fn work_fn;
	ktime_t enqueue_time;
	u8 data[96];
};

struct hfi1_dms_work_item_block {
	struct hfi1_dms_dlist_element dlist;
	struct hfi1_dms_work_item items[100];
};

struct hfi1_dms_work_item_mgr {
	struct hfi1_dms_dlist active;
	struct hfi1_dms_dlist free;
	struct hfi1_dms_dlist blocklist;
};

struct hfi1_dms_mem_coh {
	void *kvaddr; // kernel virtual address
	dma_addr_t phys_addr; // physical address
	u64 len; // length of the memory region in bytes
};

struct hfi1_dms_ahg_header_set {
	struct hfi1_dms_dlist_element dlist;

	u32 desc_idx; // descriptor index for these headers
	struct hfi1_dms_mem_coh headers[HFI1_DMS_TID_SET_SIZE];
};

struct hfi1_dms_ahg_header_block {
	struct hfi1_dms_dlist_element dlist;

	struct hfi1_dms_mem_coh backing_mem;
	struct hfi1_dms_ahg_header_set header_sets[HFI1_DMS_AHG_HEADER_BLOCK_SIZE];
};

// no active list, active headers managed elsewhere
struct hfi1_dms_ahg_header_mgr {
	struct hfi1_dms_dlist free;
	struct hfi1_dms_dlist blocklist;
};

struct hfi1_dms_sde_rsrc {
	struct hfi1_dms_dlist active_ahg_headers;
};

struct dms_perf_counters {
	u64 transfers;
	u64 bytes;
	ktime_t total_time;
	ktime_t rift_wait_time;
};

struct dms_perf_tidset {
	ktime_t enable;
	ktime_t rtt;
	ktime_t total;
	ktime_t data;
	u32 bytes;
	hfi1_dms_rift_key_t local;
	hfi1_dms_rift_key_t remote;
	u64 order_key;
	u32 tbytes;
};

struct dms_counters
{
	u64 send_total;
	u64 rget;
	u64 make_data_request;
	u64 map_tids;
	u64 handle_data_request;
	u64 tid_send;
	u64 first_packet_send;
	u64 next_packet_send;
	u64 hdrq_drain;
	u64 hdrq_drain_packet;
	u64 handle_data;
	u64 read_request_done;
	ktime_t sending_first_rr;
	ktime_t rcv_first_data;
	ktime_t rcv_first_rr;
	ktime_t last_sdma_sent;

	struct dms_perf_counters perf[HFI1_DMS_XFER_TYPE_COUNT][HFI1_DMS_XFER_OP_COUNT];

	struct {
		struct hfi1_dms_ring ring;
		struct dms_perf_tidset arr[1024];
	} tidset;
};

struct hfi1_dms_client_state {
	struct rb_node node;
	u32 key;
	struct {
 		struct hfi1_dms_access * arr[HFI1_DMS_MAX_ACCESS_FAST];
		struct rb_root rbt;
	} access;
};

union hfi1_dms_tracker {
	struct hfi1_dms_tracker_hdr hdr;
	struct hfi1_dms_rx_tracker rx;
	struct hfi1_dms_tx_tracker tx;
	struct hfi1_dms_sdma_tracker sdma;
};

struct hfi1_dms_rift {
	struct {
		struct hfi1_dms_dlist waitlist;
		struct {
			u16 stack_top;
			u16 stack_size;
			hfi1_dms_rift_key_t stack[HFI1_DMS_RIFT_IDX_SIZE/HFI1_DMS_XFER_TYPE_COUNT];
		} side[HFI1_DMS_XFER_SIDE_COUNT];
	} type[HFI1_DMS_XFER_TYPE_COUNT];
	union hfi1_dms_tracker *arr[HFI1_DMS_RIFT_IDX_SIZE];
};

enum hfi1_dms_tidset_waiter_type {
	HFI1_DMS_TIDSET_WAITER_TYPE_READ = 0,
	HFI1_DMS_TIDSET_WAITER_TYPE_DATA,

	HFI1_DMS_TIDSET_WAITER_TYPE_COUNT
};


struct hfi1_dms_rift_keyring {
	struct hfi1_dms_ring ring;
	hfi1_dms_rift_key_t arr[HFI1_DMS_RIFT_IDX_SIZE*2];
};

struct hfi1_dms_stack_u8 {
	u32 top;
	u32 size;
	u8 arr[256];
};

struct hfi1_dms_order_domain {
	struct rb_node node;
	struct hfi1_dms_dlist_element dlist;

	u64 key;

	struct {
		struct {
			u64 rx_total;	// tid + eager
			u64 tx_total; // sdma + eager
			u64 rx_received;
			u64 tx_injected;

			u64 eager_tx_requested;
			u64 eager_tx_acked;
		} nbytes;
		struct {
			u64 started;
			u64 completed;
		} xfers;
	} stats;

	struct {
		enum hfi1_dms_sdma_engine_idx engine_idx;
		struct hfi1_dms_rift_keyring wait;
	} sdma;

	struct {
		u32 active_count;
		struct hfi1_dms_stack_u8 free;
		struct hfi1_dms_rift_keyring wait;
	} tidsets;
};

enum hfi1_dms_op {
	HFI1_DMS_OP_NONE = 0,
	HFI1_DMS_OP_RDMA_WRITE,
	HFI1_DMS_OP_RDMA_READ,
};

struct hfi1_dms {
	struct hfi1_devdata *dd; /* provided by bulksvc */
	struct sdma_engine **sdma_engines; /* Array of SDMA engines */
	s32 num_engines;                  /* Number of SDMA engines */
	s32 cur_sdma_engine;

	struct hfi1_ctxtdata *rcd_ctrl; // used for protocol and small PIO messages
	struct hfi1_ctxtdata *rcd_data; // used for expected receive data (TODO: eager data?)
	struct send_context *sctxt;

	struct hfi1_dms_stack_u8 free_tidsets;

	// these are implicitly indexed by the associated TID set index
	struct hfi1_dms_read_request_state read_requests[HFI1_DMS_TID_SET_IDX_COUNT];

	struct hfi1_dms_rift_keyring tidset_waiters[HFI1_DMS_TIDSET_WAITER_TYPE_COUNT];
	struct hfi1_dms_sdma_waiters sdma_waiters[HFI1_DMS_SDMA_ENGINE_IDX_COUNT];
	s32 sdma_waiter_count;

	/* Internal pointers for protocol/registered buffers */
	union hfi1_dms_proto_cmd *protocol_cmd_templates; /* Array of protocol command templates */

	struct hfi1_dms_tracker_mgr trackers;

	struct hfi1_dms_sde_rsrc *sde_rsrcs; /* per SDMA engine resources */

	struct hfi1_dms_ahg_header_mgr ahg_headers;
	struct hfi1_dms_mem_coh zero_page; // for tail flit and scratch space
	
	struct sdma_desc *desc_stack;
	s32 num_descs;

	struct rb_root client_rbtree;
	struct {
		struct hfi1_dms_dlist freelist;
	} access;

	struct hfi1_dms_rift rift;

	struct hfi1_dms_work_item_mgr work_items;

	struct hfi1_dms_rx_tracker disabled_rx_tracker;

	ktime_t now;
	ktime_t last_stale_check;

	struct {
		int retries;
		enum hfi1_dms_op op;
		union {
			struct hfi1_dms_read_start_parameters read;
			struct hfi1_dms_write_start_parameters write;
		};
	} access_stall;

	struct {
		struct hfi1_dms_dlist waitlist;
		struct hfi1_dms_dlist freelist;
	} pio;

	struct {
		struct rb_root rb;
		struct hfi1_dms_dlist freelist;
		u32 sdma_engine_ctr;
	} order;

	struct dms_counters counters;
};

int hfi1_dms_init(struct hfi1_dms *dms, struct hfi1_devdata *dd, struct hfi1_ctxtdata **rcds, int num_rcds, struct sdma_engine **sdma_engines, int num_engines);
void hfi1_dms_uninit(struct hfi1_dms *dms);

// struct hfi1_dms_mr * hfi1_dms_mr_new(struct mmu_rb_handler *handler, uintptr_t vaddr, u64 len);
// int hfi1_dms_mr_free(struct hfi1_dms_mr *mr);

int hfi1_dms_register_access(struct hfi1_dms *dms, struct hfi1_dms_mr *mr, u64 offset, u32 size, union hfi1_dms_key dms_key, struct hfi1_dms_access_completion const completion,
		enum hfi1_dms_access_type access_type, struct hfi1_dms_access **out);
	
int hfi1_dms_unregister_access(struct hfi1_dms *dms, union hfi1_dms_key dms_key);

int hfi1_dms_read_data(struct hfi1_dms *dms, u32 src_lid, union hfi1_dms_key dms_key, u64 key_offset_or_vaddr, u32 size,
			struct hfi1_dms_mr *mr, u64 mr_offset, u16 flags, u64 imm_data, struct hfi1_dms_tracker_completion const completion,
			bool ordered, u64 order_key);

int hfi1_dms_write_data(struct hfi1_dms *dms, u32 dest_lid, union hfi1_dms_key dms_key, u64 remote_offset,
			u32 size, struct hfi1_dms_mr *mr, u64 mr_offset, u16 flags, u64 imm_data,
			struct hfi1_dms_tracker_completion const completion, bool ordered, u64 order_key);

// This is only here for now to debug, this will be removed
/* in the future when we have interrupts linked up */
int hfi1_dms_poll(struct hfi1_dms *dms, ktime_t const now);

void hfi1_dms_access_completion_fn_noop(union hfi1_dms_completion_cookie * cookie, u16 flags, u64 imm_data, int status);
void hfi1_dms_tracker_completion_fn_noop(union hfi1_dms_completion_cookie * cookie, int status);

/* called when user info is being freed */
void hfi1_dms_release_client_key(struct hfi1_dms *dms, u32 client_key);

int hfi1_dms_create_client_key(struct hfi1_dms *dms, u32 client_key);

hfi1_dms_rift_key_t _rift_key_create(u16 const generation, u16 const index);
bool _rift_key_side_rx(hfi1_dms_rift_key_t const key);
bool _rift_key_side_tx(hfi1_dms_rift_key_t const key);

u32 _ring_size(struct hfi1_dms_ring *ring);
u32 _ring_consume(struct hfi1_dms_ring *ring);

#endif /* _HFI1_DMS_H */
