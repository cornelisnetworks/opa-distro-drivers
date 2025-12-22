#ifndef DEF_HFI1_BULKSVC_USER_H
#define DEF_HFI1_BULKSVC_USER_H

#include <linux/iosys-map.h>
#include <linux/types.h>
#include <linux/kref.h>
#include <linux/mutex.h>

#include <uapi/rdma/hfi/hfi1_user.h>
#ifdef CONFIG_HFI1_NVIDIA_P2P_MEMCPY
#include <nvidia/nv-p2p.h>
#endif

#include "dms.h"

struct hfi1_bulksvc_user_info;

struct hfi1_bulksvc_queue_record {
	bool active;
	struct hfi1_bulksvc_queue_info queue_info;
	struct hfi1_bulksvc_queue_ctrl *ctrl;
	atomic64_t *head;
	atomic64_t *tail;
	u32 idx_mask;
	u8 *queue_buf;
	u8 *queue_buf_magic;
};

#define BULKSVC_USER_MAX_NUM_CMPLQS 16
#define BULKSVC_USER_MAX_NUM_CMDQS 16

enum hfi1_bulksvc_mr_type {
	HFI1_BULKSVC_MR_TYPE_HOST,
	HFI1_BULKSVC_MR_TYPE_DMABUF,
};

enum hfi1_bulksvc_fixup_cpu_mapping_type {
	HFI1_BULKSVC_FIXUP_CPU_MAPPING_NONE,
	HFI1_BULKSVC_FIXUP_CPU_MAPPING_VMAP,
	HFI1_BULKSVC_FIXUP_CPU_MAPPING_NVPT,
};

struct hfi1_bulksvc_nv_pt_info {
	struct nvidia_p2p_page_table *nv_pt;
	u64 nv_start;
	u64 nv_end;
};

struct hfi1_bulksvc_user_mr_record {
	struct list_head list_entry;
	struct kref refcount; // Can have multiple outstanding transactions
	u32 user_handle;

	enum hfi1_bulksvc_mr_type mr_type;
	union {
		struct {
			struct hfi1_mem_region *hfi1_mr;
		};
		struct {
			struct dma_buf *dma_buf;
			struct dma_buf_attachment *dma_buf_attachment;
			struct sg_table *sg_table;
			enum hfi1_bulksvc_fixup_cpu_mapping_type fixup_mapping_type;

			union {
				struct iosys_map vmap;
				struct hfi1_bulksvc_nv_pt_info *nv_pt_info;

			} fixup_mapping;
		};
	} mem_region;

	struct hfi1_dms_mr dms_mr;
};

struct hfi1_bulksvc_user_mr_access_record {
	struct list_head list_entry;
	u64 app_context;
	u32 access_key;
	u32 cmplq_id;
	struct hfi1_bulksvc_user_mr_record *mr_record;
	struct hfi1_bulksvc_user_info *user_info;
	u32 client_key;
	bool released_by_user;
};

union hfi1_bulksvc_userctxt_cmd_data {
	u64 raw;
	struct {
		struct dma_buf *dmabuf;
		struct hfi1_bulksvc_nv_pt_info *nv_pt_info;
	} dmabuf_open;
};

struct hfi1_bulksvc_userctxt_cmd_entry {
	struct list_head node;
	union hfi1_bulksvc_userctxt_cmd_data data;
	struct hfi1_bulksvc_cmd cmd; // variably-sized
};

struct hfi1_bulksvc_user_info {
	// Held by the user file handle, as well as active dms ops
	struct kref refcount;

	struct list_head list_entry;
	struct hfi1_bulksvc *svc;
	u32 client_key;

	struct mutex queue_records_lock;
	struct hfi1_bulksvc_queue_record
		cmplq_records[BULKSVC_USER_MAX_NUM_CMPLQS];
	u8 num_cmplqs; /* number of cmplq records in use */
	struct hfi1_bulksvc_queue_record
		cmdq_records[BULKSVC_USER_MAX_NUM_CMDQS];
	u8 num_cmdqs; /* number of cmdq records in use */

	struct list_head userctxt_cmdq; // hfi1_bulksvc_userctxt_cmd_entry
	struct mutex userctxt_cmdq_lock;

	union hfi1_bulksvc_upd *completion_overflows; /* shared overflow queue for all completions */
	struct hfi1_bulksvc_queue_record **completion_overflow_records; /* the completion queue record associated with a particular completion */
	u32 completion_overflows_size; /* size of the array above */
	u32 num_completion_overflows; /* number of entries in the array */

	u32 num_inflight;
	u32 max_inflight;

	u32 next_user_mr_handle;
	struct list_head user_mr_list;
	struct list_head active_access_list;

	struct mmu_rb_handler *mmu;

	struct mm_struct *user_mm;
};

// Must be called from a user context
struct hfi1_bulksvc_user_info* hfi1_bulksvc_user_info_create(struct hfi1_filedata *fdata);

void hfi1_bulksvc_user_info_get(struct hfi1_bulksvc_user_info* info);
void hfi1_bulksvc_user_info_put(struct hfi1_bulksvc_user_info* info);

struct hfi1_bulksvc;
int hfi1_bulksvc_poll_user_cmds(struct hfi1_bulksvc * const svc);
void bulksvc_user_info_destroy(struct hfi1_bulksvc_user_info* info);

void bulksvc_user_info_destroy(struct hfi1_bulksvc_user_info* info);

#endif /* DEF_HFI1_BULKSVC_USER_H */
