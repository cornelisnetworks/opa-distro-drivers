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

#define HFI1_DMS_JKEY (0xACDC)
#define HFI1_DMS_MAX_TID_VALUE (1024)
#define HFI1_DMS_TID_SET_SIZE (16)
#define HFI1_DMS_TID_SET_IDX_MIN (0)
#define HFI1_DMS_TID_SET_IDX_MAX (HFI1_DMS_MAX_TID_VALUE / HFI1_DMS_TID_SET_SIZE)
// 32 ahg indices per engine * 16 engines * 2
#define HFI1_DMS_AHG_HEADER_BLOCK_SIZE (1024)

#define HFI1_DMS_MAX_ACCESS_FAST (1024)
#define HFI1_DMS_RIFT_SIZE (1024 * 8)

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
	
	struct page** pages;
	dma_addr_t *dma_list;
	unsigned int npages_total;
	unsigned int npages_pinned;

	struct {
		unsigned long addr;	// user unaligned vaddr of start of buffer
		unsigned long len;  // number of bytes in the user buffer
	} user;
	u64 region_offset; // offset into the mr (from the first page address) where the user buffer starts
	enum hfi1_dms_mr_mode mode;
	u32 active_count;

	int (*pinned_check_fn)(struct hfi1_dms_mr *mr, unsigned int start_page_index, unsigned int npages_to_request);
};

enum hfi1_dms_access_type {
	HFI1_DMS_ACCESS_TYPE_PERSISTENT = 0,
	HFI1_DMS_ACCESS_TYPE_EPHEMERAL = 1,
};

typedef void (*hfi1_dms_access_completion_fn)(union hfi1_dms_completion_cookie *, u16, u64);

struct hfi1_dms_access_completion {
	hfi1_dms_access_completion_fn fn;
	union hfi1_dms_completion_cookie cookie;
};

struct hfi1_dms_access {
	struct rb_node node;
	struct hfi1_dms_dlist_element element;
	u64 dms_key;
	u32 access_key;
	enum hfi1_dms_access_type type;
	struct hfi1_dms_access_completion completion;
	struct hfi1_dms_mr *mr; // memory region this access is for
	u64 offset; // offset into the memory region
	u64 size; // size of the access in bytes
	u32 active_count; // number of transfers currently using this access
};

 enum hfi1_dms_tx_tracker_op {
	HFI1_DMS_TX_TRACKER_OP_RDMA_WRITE = 0,
	HFI1_DMS_TX_TRACKER_OP_RDMA_READ = 1,
 };

struct hfi1_dms_tx_tracker {
	struct hfi1_dms_dlist_element dlist;
	u16 rift_index;
	u32 total_payload;
	u32 payload_remaining;

	u32 xfer_start_byte_offset; // byte offset from start of first mr page to the start of the xfer buffer
	u32 remote_lid;
	u16 remote_rift_index;

	enum hfi1_dms_tx_tracker_op op;
	union {
		struct {
			struct hfi1_dms_mr *mr;
			struct hfi1_dms_tracker_completion completion;
		} write;
		struct {
			struct hfi1_dms_access * access;
		} read;
	};

	//u64 start_offset; // offset from start of mr (page-aligned) to start of xfer buffer
};


 enum hfi1_dms_rx_tracker_op {
	HFI1_DMS_RX_TRACKER_OP_RDMA_WRITE = 0,
	HFI1_DMS_RX_TRACKER_OP_RDMA_READ = 1,
 };


#define HFI1_DMS_RIFT_INDEX_NOT_SET (-1)

struct hfi1_dms_rx_tracker {
	struct hfi1_dms_dlist_element dlist;

	u16 rift_index;
	u32 payload_requested;
	u32 payload_remaining;
	u32 total_payload;

	u32 sbuf_offset; // Current offset into the _user region_ of the sbuf on the other side
	u64 rbuf_offset; // Current absolute offset into rbuf
	u64 rbuf_start_offset; // Offset into the rbuf where the data starts
	u64 sbuf_start_offset; // Offset into the sbuf where the data starts; interpreted on the remote as either a byte offset or a virtual address

	u32 remote_lid;
	int tx_rift_index;

	// receiving buffer
	struct hfi1_dms_mr *rbuf;
	u8 head_misalignment;
	u8 tail_misalignment;


	enum hfi1_dms_rx_tracker_op op;
	union {
		struct {
			struct hfi1_dms_access * access;
			u16 flags;
			u16 unused[3];
			u64 imm_data;
		} write;

		struct {
			u64 dms_key;
			struct hfi1_dms_tracker_completion completion;
			u16 flags;
			u16 unused[3];
			u64 imm_data;
		} read;

	};

};

struct hfi1_dms_read_request_state {
	u64 remaining_qws;
	u64 total_requested_qws;
	struct hfi1_dms_rx_tracker *rx_tracker;
	s32 tid_set;
};

struct hfi1_dms_rx_tracker_block {
	struct hfi1_dms_dlist_element dlist;

	struct hfi1_dms_rx_tracker tracker[100];
};

struct hfi1_dms_tx_tracker_block {
	struct hfi1_dms_dlist_element dlist;

	struct hfi1_dms_tx_tracker tracker[100];
};

struct hfi1_dms_tracker_mgr {
	struct hfi1_dms_dlist active;    // i.e., hfi1_dms_rx_tracker or hfi1_dms_tx_tracker
	struct hfi1_dms_dlist free;      // i.e., hfi1_dms_rx_tracker or hfi1_dms_tx_tracker
	struct hfi1_dms_dlist blocklist; // i.e., hfi1_dms_rx_tracker_block or hfi1_dms_tx_tracker_block
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

struct hfi1_dms_ahg_header {
	struct hfi1_dms_dlist_element dlist;

	u32 desc_idx; // descriptor index for this header
	struct hfi1_dms_mem_coh mem_coh;
};

struct hfi1_dms_ahg_header_block {
	struct hfi1_dms_dlist_element dlist;

	struct hfi1_dms_mem_coh backing_mem;
	struct hfi1_dms_ahg_header headers[HFI1_DMS_AHG_HEADER_BLOCK_SIZE];
};

// no active list, active headers managed elsewhere
struct hfi1_dms_ahg_header_mgr {
	struct hfi1_dms_dlist free;
	struct hfi1_dms_dlist blocklist;
};

struct hfi1_dms_sde_rsrc {
	struct hfi1_dms_dlist active_ahg_headers;
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
	struct hfi1_dms_rx_tracker rx;
	struct hfi1_dms_tx_tracker tx;
};

struct hfi1_dms_rift {
	struct hfi1_dms_dlist waitlist;
	u16 stack_top;
	u16 stack[HFI1_DMS_RIFT_SIZE];
	union hfi1_dms_tracker *arr[HFI1_DMS_RIFT_SIZE];
};

enum hfi1_dms_tidset_waiter_type {
	HFI1_DMS_TIDSET_WAITER_TYPE_READ = 0,
	HFI1_DMS_TIDSET_WAITER_TYPE_DATA,

	HFI1_DMS_TIDSET_WAITER_TYPE_COUNT
};

struct hfi1_dms_tidset_waiters {
	u64 head;
	u64 tail;
	u16 ring[HFI1_DMS_RIFT_SIZE*2];
};

struct hfi1_dms {
	struct hfi1_devdata *dd; /* provided by bulksvc */
	struct sdma_engine **sdma_engines; /* Array of SDMA engines */
	s32 num_engines;                  /* Number of SDMA engines */
	s32 cur_sdma_engine;

	struct hfi1_ctxtdata *rctxt;
	struct send_context *sctxt;
	/* Read Request State - shared across messages */
	// free list of TID sets available
	// 1:1 with active read requests in-flight
	s32 free_tid_sets_stack[HFI1_DMS_TID_SET_IDX_MAX]; /* Stack of free TID sets */
	s32 free_tid_sets_stack_top;

	// these are implicitly indexed by the associated TID set index
	struct hfi1_dms_read_request_state read_requests[HFI1_DMS_TID_SET_IDX_MAX];

	struct hfi1_dms_tidset_waiters tidset_waiters[HFI1_DMS_TIDSET_WAITER_TYPE_COUNT];

	/* Internal pointers for protocol/registered buffers */
	union hfi1_dms_proto_cmd *protocol_cmd_templates; /* Array of protocol command templates */

	struct hfi1_dms_tracker_mgr rx_trackers;
	struct hfi1_dms_tracker_mgr tx_trackers;

	struct hfi1_dms_sde_rsrc *sde_rsrcs; /* per SDMA engine resources */

	struct hfi1_dms_ahg_header_mgr ahg_headers;
	struct hfi1_dms_mem_coh zero_page; // for tail flit and scratch space
	
	struct sdma_desc *desc_stack;
	s32 num_descs;
	struct hfi1_dms_ahg_header **ahg_header_stack;
	s32 num_ahgs;

	struct rb_root client_rbtree;
	struct {
		struct hfi1_dms_dlist freelist;
	} access;

	struct hfi1_dms_rift rx_rift;
	struct hfi1_dms_rift tx_rift;

	struct hfi1_dms_work_item_mgr work_items;

	struct dms_counters counters;
};

int hfi1_dms_init(struct hfi1_dms *dms, struct hfi1_devdata *dd, struct hfi1_ctxtdata **rcds, int num_rcds, struct sdma_engine **sdma_engines, int num_engines);
void hfi1_dms_uninit(struct hfi1_dms *dms);

// struct hfi1_dms_mr * hfi1_dms_mr_new(struct mmu_rb_handler *handler, uintptr_t vaddr, u64 len);
// int hfi1_dms_mr_free(struct hfi1_dms_mr *mr);

int hfi1_dms_register_access(struct hfi1_dms *dms, struct hfi1_dms_mr *mr, u64 offset, u32 size, u64 dms_key, struct hfi1_dms_access_completion const completion,
		enum hfi1_dms_access_type access_type, struct hfi1_dms_access **out);
	
// This probably isn't a real function or won't be like this
// but it's useful for now on the testing side
int hfi1_dms_unregister_access(struct hfi1_dms *dms, u64 dms_key);
int hfi1_dms_read_data(struct hfi1_dms *dms, u32 src_lid, u64 dms_key, u64 key_offset_or_vaddr, u32 size, struct hfi1_dms_mr *mr, u64 mr_offset, u16 flags, u64 imm_data, struct hfi1_dms_tracker_completion const completion);

int hfi1_dms_dma_access_once(struct hfi1_dms *dms, u32 client_key, struct hfi1_dms_mr *mr, u32 access_key,
			       u64 offset, u32 len,
			       struct hfi1_dms_access_completion const notification);
int hfi1_dms_dma_access_enable(struct hfi1_dms *dms, u32 client_key, struct hfi1_dms_mr *mr, u32 access_key,
			       u64 offset_into_buffer, u32 len,
			       struct hfi1_dms_access_completion const notification);
int hfi1_dms_dma_access_disable(struct hfi1_dms *dms, u32 client_key, u32 access_key);

int hfi1_dms_write_data(struct hfi1_dms *dms, u32 dest_lid, u64 dms_key, u64 remote_offset,
			u32 size, struct hfi1_dms_mr *mr, u64 mr_offset, u16 flags, u64 imm_data,
			struct hfi1_dms_tracker_completion const completion);

// This is only here for now to debug, this will be removed
/* in the future when we have interrupts linked up */
int hfi1_dms_poll(struct hfi1_dms *dms);

void hfi1_dms_access_completion_fn_noop(union hfi1_dms_completion_cookie * cookie, u16 flags, u64 imm_data);
void hfi1_dms_tracker_completion_fn_noop(union hfi1_dms_completion_cookie * cookie, int status);

/* called when user info is being freed */
void hfi1_dms_release_client_key(struct hfi1_dms *dms, u32 client_key);

int hfi1_dms_create_client_key(struct hfi1_dms *dms, u32 client_key);

#endif /* _HFI1_DMS_H */
