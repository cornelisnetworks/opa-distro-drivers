#include "bulksvc_user.h"
#include "bulksvc_verbs.h" // to call post_send handler
#include "bulksvc.h"
#include "dms.h"

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

static void user_mr_record_put(struct hfi1_bulksvc_user_mr_record *mr_record);
void user_mr_access_record_destroy_and_remove(struct hfi1_bulksvc_user_mr_access_record *access_record);

extern uint bulksvc_user_queue_size_pages_log2;
struct hfi1_bulksvc_user_info* hfi1_bulksvc_user_info_create(struct hfi1_filedata *fd)
{
	pr_debug("hfi1: bulksvc enabled, creating user info\n");

	struct hfi1_bulksvc_user_info *bulksvc_user_info = kzalloc(sizeof(*bulksvc_user_info), GFP_KERNEL);
	if (!bulksvc_user_info)
		return NULL;
	u64 const max_cmds_per_queue = (1 << bulksvc_user_queue_size_pages_log2) * PAGE_SIZE / CACHELINE_SIZE;
	u64 num_overflow = 2 * max(BULKSVC_USER_MAX_NUM_CMDQS, BULKSVC_USER_MAX_NUM_CMPLQS) * max_cmds_per_queue;
	union hfi1_bulksvc_upd *overflows = kmalloc_array(num_overflow, sizeof(union hfi1_bulksvc_upd), GFP_KERNEL);
	if (!overflows) {
		kfree(bulksvc_user_info);
		return NULL;
	}
	struct hfi1_bulksvc_queue_record **overflow_records = kmalloc_array(num_overflow, sizeof(struct hfi1_bulksvc_queue_record*), GFP_KERNEL);
	if (!overflow_records) {
		kfree(overflows);
		kfree(bulksvc_user_info);
		return NULL;
	}

	bulksvc_user_info->completion_overflows_size = num_overflow;
	bulksvc_user_info->completion_overflows = overflows;
	bulksvc_user_info->completion_overflow_records = overflow_records;

	bulksvc_user_info->svc = fd->dd->bulksvc;

	/* freed when user context is freed */
	int rc = init_bulksvc_mmu(bulksvc_user_info);
	if (rc) {
		dd_dev_err(fd->dd,
				"Failed to create bulsvc pinnned mem handler %d\n",
				rc);
		kfree(bulksvc_user_info->completion_overflow_records);
		kfree(bulksvc_user_info->completion_overflows);
		kfree(bulksvc_user_info);
		return NULL;
	}

	mutex_init(&bulksvc_user_info->queue_records_lock);

	bulksvc_user_info->num_cmplqs = 0;
	bulksvc_user_info->num_cmdqs = 0;
	bulksvc_user_info->max_inflight = num_overflow + max_cmds_per_queue;

	bulksvc_user_info->client_key = atomic_inc_return(&fd->dd->bulksvc->last_client_key);
	pr_debug("assigned client key %u\n", bulksvc_user_info->client_key);

	mmgrab(current->mm);
	bulksvc_user_info->user_mm = current->mm;

	bulksvc_user_info->next_user_mr_handle = 0;

	INIT_LIST_HEAD(&bulksvc_user_info->active_access_list);
	INIT_LIST_HEAD(&bulksvc_user_info->user_mr_list);

	kref_init(&bulksvc_user_info->refcount);

	return bulksvc_user_info;
}

static void bulksvc_user_info_event_release(struct kref *ref)
{
	struct hfi1_bulksvc_user_info* info = container_of(ref, struct hfi1_bulksvc_user_info, refcount);
	struct hfi1_bulksvc_event_entry *event_entry = kzalloc(sizeof(*event_entry), GFP_KERNEL);
	if (!event_entry) {
		pr_err("Failed to allocate bulksvc event entry, leaking user info\n");
		return;
	}
	event_entry->event.type = BULKSVC_EVENT_TYPE_USER_INFO_RELEASE;
	event_entry->event.user_info = info;
	if (hfi1_bulksvc_enqueue_event(info->svc, event_entry)) {
		pr_err("Failed to enqueue bulksvc user info release event, leaking user info\n");
		kfree(event_entry);
		return;
	}

}

void bulksvc_user_info_destroy(struct hfi1_bulksvc_user_info* info)
{
	pr_debug("destroying user info\n");


/** TODO: this will be fixed in a follow up patch, but for now 
 * if we actually error here we can potentially "hang" the boxes
 * by printing 16k+ error lines. The boxes don't actually hang but we
 * can't reload the driver or do anything useful during that time
*/
#if 0
	struct hfi1_bulksvc_user_mr_access_record *access_record = list_first_entry(&info->active_access_list, typeof(*access_record), list_entry);
	struct hfi1_bulksvc_user_mr_access_record *access_record_next;
	while (!list_entry_is_head(access_record, &info->active_access_list, list_entry)) {
		access_record_next = list_next_entry(access_record, list_entry);
		dd_dev_dbg(info->svc->dd, "%s:%d:%s() bulksvc: Lingering user MR access %u: %p \n",
			   __FILENAME__, __LINE__, __func__, access_record->access_key, access_record);
		if (hfi1_dms_dma_access_disable(&info->svc->dms, info->client_key, access_record->access_key) == 0) {
			user_mr_access_record_destroy_and_remove(access_record);
		}
		access_record = access_record_next;
	}

	struct hfi1_bulksvc_user_mr_record* mr_record = list_first_entry(&info->user_mr_list, typeof(*mr_record), list_entry);
	struct hfi1_bulksvc_user_mr_record *mr_record_next;
	while (!list_entry_is_head(mr_record, &info->user_mr_list, list_entry)) {
		mr_record_next = list_next_entry(mr_record, list_entry);
		dd_dev_dbg(info->svc->dd, "%s:%d:%s() bulksvc: Lingering user MR %u: %p \n",
			   __FILENAME__, __LINE__, __func__, mr_record->user_handle, mr_record);
		user_mr_record_put(mr_record);
		mr_record = mr_record_next;
	}
#endif

	for (int i = 0; i < BULKSVC_USER_MAX_NUM_CMPLQS; i++) {
		if (info->cmplq_records[i].active) {
			vfree(info->cmplq_records[i].ctrl);
			vunmap(info->cmplq_records[i].queue_buf_magic);
			vfree(info->cmplq_records[i].queue_buf);
		}
	}
	for (int i = 0; i < BULKSVC_USER_MAX_NUM_CMDQS; i++) {
		if (info->cmdq_records[i].active) {
			vfree(info->cmdq_records[i].ctrl);
			vunmap(info->cmdq_records[i].queue_buf_magic);
			vfree(info->cmdq_records[i].queue_buf);
		}
	}
	kfree(info->completion_overflow_records);
	kfree(info->completion_overflows);

	if (info->mmu) {
		uninit_bulksvc_mmu(info);
	}

	hfi1_dms_release_client_key(&info->svc->dms, info->client_key);
	mmdrop(info->user_mm);
	info->user_mm = NULL;


	dd_dev_dbg(info->svc->dd, "%s:%d:%s() bulksvc: Destroyed user info %u\n",
			   __FILENAME__, __LINE__, __func__, info->client_key);

	kfree(info);
}

void hfi1_bulksvc_user_info_get(struct hfi1_bulksvc_user_info* info)
{
	kref_get(&info->refcount);
}
void hfi1_bulksvc_user_info_put(struct hfi1_bulksvc_user_info* info)
{
	kref_put(&info->refcount, bulksvc_user_info_event_release);
}

static struct hfi1_bulksvc_queue_record *
get_cmplq_record(struct hfi1_bulksvc *svc,
		 struct hfi1_bulksvc_user_info *user_info, u32 cmplq_id)
{
	struct hfi1_bulksvc_queue_record *cmplq_record;

	if (cmplq_id >= user_info->num_cmplqs) {
		dd_dev_err(svc->dd, "%s:%d:%s() invalid cmplq id %u\n",
			   __FILENAME__, __LINE__, __func__, cmplq_id);
		return NULL;
	}

	cmplq_record = &user_info->cmplq_records[cmplq_id];
	if (!cmplq_record->active) {
		dd_dev_err(svc->dd, "%s:%d:%s() cmplq record %u not active\n",
			   __FILENAME__, __LINE__, __func__, cmplq_id);
		return NULL;
	}
	return cmplq_record;
}

static void enqueue_overflow_completion(struct hfi1_bulksvc_user_info *user_info,
			struct hfi1_bulksvc_queue_record *cmplq_record,
			struct hfi1_bulksvc_cmplq_entry *cmpl)
{
	if (user_info->num_completion_overflows >= user_info->completion_overflows_size) {
		dd_dev_err(user_info->svc->dd,
			   "Completion overflow queue overflow, dropping completion\n");
		return;
	}
	u32 idx = user_info->num_completion_overflows;
	user_info->completion_overflows[idx] =
		(union hfi1_bulksvc_upd) {
			.cmplq_entry = *cmpl,
		};
	user_info->completion_overflow_records[idx] = cmplq_record;
	user_info->num_completion_overflows++;
}

static int try_give_completion(struct hfi1_bulksvc_user_info *user_info, struct hfi1_bulksvc_queue_record *cmplq_record,
			    struct hfi1_bulksvc_cmplq_entry *cmpl)
{
	u32 mask, cmplq_head, cmplq_tail;
	struct hfi1_bulksvc_cmplq_entry *entry;

	if (!cmplq_record) {
		pr_err("%s:%d:%s() invalid dma buffer op info\n",
		       __FILENAME__, __LINE__, __func__);
		return -EINVAL;
	}

	mask = cmplq_record->idx_mask;
	cmplq_head = atomic64_read(cmplq_record->head);
	cmplq_tail = atomic64_read(cmplq_record->tail);
	if (cmplq_tail - cmplq_head >= mask) {
		pr_debug("%s:%d:%s() cmplq full\n",
		       __FILENAME__, __LINE__, __func__);
		return -ENOSPC;
	}

	entry = &((union hfi1_bulksvc_upd *)
		cmplq_record->queue_buf_magic)[cmplq_tail & mask].cmplq_entry;

	*entry = *cmpl;

	atomic64_set_release(cmplq_record->tail, cmplq_tail + 1);
	user_info->num_inflight--;
	return 0;
}

static void give_completion(struct hfi1_bulksvc_user_info *user_info, struct hfi1_bulksvc_queue_record *cmplq_record,
			    struct hfi1_bulksvc_cmplq_entry *cmpl)
{
	int ret = try_give_completion(user_info, cmplq_record, cmpl);
	if (ret == -ENOSPC) {
		enqueue_overflow_completion(user_info, cmplq_record, cmpl);
	}
}

static int user_mr_record_pinned_check(struct hfi1_dms_mr *mr,
					 unsigned int start_page_index,
					 unsigned int npages_to_request)
{
	struct hfi1_bulksvc_user_mr_record* user_mr = container_of(mr, struct hfi1_bulksvc_user_mr_record, dms_mr);
	return hfi1_mem_region_pinned_check(user_mr->hfi1_mr, start_page_index, npages_to_request);
}

static struct hfi1_bulksvc_user_mr_record * user_mr_record_create_pinned_and_insert(struct hfi1_bulksvc_user_info* user_info, uintptr_t vaddr, u64 len, u64 flags)
{
	struct hfi1_bulksvc_user_mr_record *mr_record;

	mr_record = kzalloc(sizeof(*mr_record), GFP_KERNEL);
	if (!mr_record) {
		pr_err("%s:%d:%s() ERROR: Failed to allocate memory for mr_record\n", __FILENAME__, __LINE__, __func__);
		return NULL;
	}

	// TODO, async pin
	mr_record->hfi1_mr = hfi1_mem_region_pin(user_info->mmu, vaddr, len);
	if (!mr_record->hfi1_mr) {
		pr_err("%s:%d:%s() ERROR: Failed to pin memory region\n", __FILENAME__, __LINE__, __func__);
		kfree(mr_record);
		return NULL;
	}

	mr_record->dms_mr.user.addr = vaddr;
	mr_record->dms_mr.user.len = len;
	mr_record->dms_mr.region_offset = (u64)vaddr - ALIGN_DOWN((u64)vaddr, PAGE_SIZE);
	if (flags & HFI1_BULKSVC_MR_FLAG_MODE_VADDR) {
		mr_record->dms_mr.mode = HFI1_DMS_MR_MODE_VADDR;
	} else {
		mr_record->dms_mr.mode = HFI1_DMS_MR_MODE_OFFSET;
	}

	// Weak refs, lifetimes tied
	mr_record->dms_mr.dma_list = mr_record->hfi1_mr->dma_list;
	mr_record->dms_mr.pages = mr_record->hfi1_mr->pages;
	mr_record->dms_mr.extended_vaddr.addr = mr_record->hfi1_mr->rb.addr;
	mr_record->dms_mr.extended_vaddr.len = mr_record->hfi1_mr->rb.len;
	mr_record->dms_mr.npages_total = mr_record->hfi1_mr->npages_total;
	mr_record->dms_mr.npages_pinned = mr_record->hfi1_mr->npages_pinned;
	mr_record->dms_mr.pinned_check_fn = user_mr_record_pinned_check;

	mr_record->dms_mr.region_offset = mr_record->dms_mr.user.addr & (PAGE_SIZE - 1);
	mr_record->dms_mr.mode = HFI1_DMS_MR_MODE_OFFSET;

	mr_record->user_handle = user_info->next_user_mr_handle++;
	kref_init(&mr_record->refcount);

	list_add_tail(&mr_record->list_entry, &user_info->user_mr_list);

	return mr_record;
}

static void user_mr_record_destroy_and_remove(struct kref* ref)
{
	struct hfi1_bulksvc_user_mr_record *mr_record = container_of(ref, struct hfi1_bulksvc_user_mr_record, refcount);
	
	hfi1_mem_region_put(mr_record->hfi1_mr);
	list_del(&mr_record->list_entry);
	kfree(mr_record);
}

static void user_mr_record_get(struct hfi1_bulksvc_user_mr_record *mr_record)
{
	kref_get(&mr_record->refcount);
}

static void user_mr_record_put(struct hfi1_bulksvc_user_mr_record *mr_record)
{
	kref_put(&mr_record->refcount, user_mr_record_destroy_and_remove);
}

static struct hfi1_bulksvc_user_mr_record *
lookup_user_mr_record(struct hfi1_bulksvc_user_info *user_info,
		 u32 user_handle)
{
	struct hfi1_bulksvc_user_mr_record* result;
	list_for_each_entry(result, &user_info->user_mr_list, list_entry) {
		if (result->user_handle == user_handle) {
			return result;
		}
	}
	return NULL;
}

static struct hfi1_bulksvc_user_mr_access_record *
user_mr_access_record_create_and_insert(struct hfi1_bulksvc_user_info *user_info,
		 u32 access_key, struct hfi1_bulksvc_user_mr_record *mr_record)
{
	struct hfi1_bulksvc_user_mr_access_record *access_record;

	access_record = kzalloc(sizeof(*access_record), GFP_KERNEL);
	if (!access_record) {
		pr_err("%s:%d:%s() ERROR: Failed to allocate memory for access_record\n", __FILENAME__, __LINE__, __func__);
		return NULL;
	}

	access_record->access_key = access_key;
	access_record->mr_record = mr_record;

	list_add_tail(&access_record->list_entry, &user_info->active_access_list);

	// Currently all long-lived access records hold an owning reference to the MR record
	user_mr_record_get(mr_record);

	return access_record;
}

void user_mr_access_record_destroy_and_remove(struct hfi1_bulksvc_user_mr_access_record *access_record)
{
	list_del(&access_record->list_entry);
	user_mr_record_put(access_record->mr_record);
	kfree(access_record);
}

static struct hfi1_bulksvc_user_mr_access_record *
lookup_user_mr_access_record(struct hfi1_bulksvc_user_info *user_info,
		 u32 access_key)
{
	struct hfi1_bulksvc_user_mr_access_record* result;
	// TODO better lookup
	list_for_each_entry(result, &user_info->active_access_list, list_entry) {
		if (result->access_key == access_key) {
			return result;
		}
	}
	return NULL;
}

static int validate_mr_access(struct hfi1_bulksvc_user_mr_record *mr, u64 offset, u32 len)
{
	// FIXME this is the wrong validation
	if (mr->dms_mr.mode == HFI1_DMS_MR_MODE_VADDR) {
		if (offset - len > mr->dms_mr.user.len) {
			return -1;
		}
	} else if (mr->dms_mr.mode == HFI1_DMS_MR_MODE_OFFSET) {
		if (offset + len > mr->hfi1_mr->rb.len) {
			return -1;
		}
	} else {
		pr_err("%s:%d:%s() invalid mr mode %d\n",
		       __FILENAME__, __LINE__, __func__, mr->dms_mr.mode);
		return -1;
	}
	return 0;
}

///
/// ONE-TIME USE TRANSACTION
///

struct reg_dma_buffer_cmpl_cookie {
	struct hfi1_bulksvc_user_info* user_info;
	struct hfi1_bulksvc_queue_record* cmplq_record;
	u64 app_context;
	u32 access_key;
	struct hfi1_bulksvc_user_mr_record *mr_record;
};

static void on_registered_dma_buffer_completed_transact(union hfi1_dms_completion_cookie *cookie, u16 flags, u64 imm_data, int status)
{
	struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };

	BUILD_BUG_ON(sizeof(struct reg_dma_buffer_cmpl_cookie) > sizeof(union hfi1_dms_completion_cookie));
	struct reg_dma_buffer_cmpl_cookie *reg_cookie =
		(struct reg_dma_buffer_cmpl_cookie *)cookie;

	cmpl.app_context = reg_cookie->app_context;
	cmpl.status = status;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;
	cmpl.type_default.access_key = reg_cookie->access_key;

	give_completion(reg_cookie->user_info, reg_cookie->cmplq_record, &cmpl);

	user_mr_record_put(reg_cookie->mr_record); // one-time
	hfi1_bulksvc_user_info_put(reg_cookie->user_info);

}

static void bulksvc_on_cmd_reg_dma_buffer(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_user_info * const user_info,
	struct hfi1_bulksvc_cmd_reg_dma_buffer const * const cmd)
{
	struct hfi1_bulksvc_queue_record *cmplq_record;
	struct hfi1_bulksvc_user_mr_record *mr_record;
	u64 offset;

	cmplq_record = get_cmplq_record(svc, user_info, cmd->cmplq_id);
	if (!cmplq_record)
		goto exit;

	mr_record = user_mr_record_create_pinned_and_insert(user_info, cmd->vaddr, cmd->size_bytes, cmd->flags);
	if (!mr_record) {
		struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };

		dd_dev_err(svc->dd, "%s:%d:%s() failed to pin user dma buffer\n",
			   __FILENAME__, __LINE__, __func__);

		cmpl.app_context = cmd->app_context;
		cmpl.status = -EFAULT;
		cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;
		cmpl.type_default.access_key = cmd->access_key;
		give_completion(user_info, cmplq_record, &cmpl);
		goto exit;
	}

	if (cmd->flags & HFI1_BULKSVC_MR_FLAG_MODE_VADDR) {
		offset = cmd->vaddr;
	} else {
		offset = 0;
	}

	hfi1_bulksvc_user_info_get(user_info);
	BUILD_BUG_ON(sizeof(struct reg_dma_buffer_cmpl_cookie) > sizeof(union hfi1_dms_completion_cookie));
	int rc = hfi1_dms_register_access(&svc->dms, &mr_record->dms_mr, offset,
		cmd->size_bytes,
		(union hfi1_dms_key) { .access = cmd->access_key, .client = user_info->client_key },
		(struct hfi1_dms_access_completion) {
		.fn = on_registered_dma_buffer_completed_transact,
		.cookie = *(union hfi1_dms_completion_cookie*)&(struct reg_dma_buffer_cmpl_cookie) {
			.user_info = user_info,
			.cmplq_record = cmplq_record,
			.app_context = cmd->app_context,
			.access_key = cmd->access_key,
			.mr_record = mr_record,
		},
	}, HFI1_DMS_ACCESS_TYPE_EPHEMERAL, NULL);
	if (rc < 0) {
		struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };

		cmpl.status = (u32)rc;
		cmpl.app_context = cmd->app_context;
		cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;
		cmpl.type_default.access_key = cmd->access_key;
		give_completion(user_info, cmplq_record, &cmpl);
		user_mr_record_put(mr_record);
		hfi1_bulksvc_user_info_put(user_info);
	}
exit:
	return;
}

///
/// MANAGE LONG-LIVED MEMORY REGION
///

static void bulksvc_on_cmd_mr_open(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_user_info * const user_info,
	struct hfi1_bulksvc_cmd_mr_open const * const cmd)
{
	struct hfi1_bulksvc_queue_record *cmplq_record;
	struct hfi1_bulksvc_user_mr_record *mr_record;
	struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };

	cmplq_record = get_cmplq_record(svc, user_info, cmd->cmplq_id);
	if (!cmplq_record)
		goto exit;

	cmpl.app_context = cmd->app_context;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_MR;

	mr_record = user_mr_record_create_pinned_and_insert(user_info, cmd->vaddr, cmd->len, cmd->flags);

	if (!mr_record) {
		cmpl.status = -EFAULT;
		cmpl.type_mr.mr_key = 0;
	} else {
		cmpl.status = 0;
		cmpl.type_mr.mr_key = mr_record->user_handle;
	}

	give_completion(user_info, cmplq_record, &cmpl);

exit:
	return;
}

static void bulksvc_on_cmd_mr_close(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_user_info * const user_info,
	struct hfi1_bulksvc_cmd_mr_close const * const cmd)
{
	struct hfi1_bulksvc_queue_record *cmplq_record;
	struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };

	cmplq_record = get_cmplq_record(svc, user_info, cmd->cmplq_id);
	if (!cmplq_record)
		goto exit;

	struct hfi1_bulksvc_user_mr_record *mr = lookup_user_mr_record(user_info, cmd->mr_key);
	if (mr) {
		user_mr_record_put(mr);
		cmpl.status = 0;
	} else {
		cmpl.status = -EINVAL;
	}

	cmpl.app_context = cmd->app_context;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_MR;
	cmpl.type_mr.mr_key = cmd->mr_key;

	give_completion(user_info, cmplq_record, &cmpl);
exit:
	return;
}

///
/// GRANT ACCESS TO MEMORY REGION ONCE
///

struct dma_access_once_cmpl_cookie {
	struct hfi1_bulksvc_user_info* user_info;
	struct hfi1_bulksvc_queue_record* cmplq_record;
	struct hfi1_bulksvc_user_mr_record* mr_record;
	u64 app_context;
	u32 access_key;
};

static void on_dma_access_once_complete(union hfi1_dms_completion_cookie *cookie, u16 flags, u64 imm_data, int status)
{
	struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };

	BUILD_BUG_ON(sizeof(struct dma_access_once_cmpl_cookie) > sizeof(union hfi1_dms_completion_cookie));
	struct dma_access_once_cmpl_cookie *dma_cookie =
		(struct dma_access_once_cmpl_cookie *)cookie;

	cmpl.app_context = dma_cookie->app_context;
	cmpl.status = status;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;
	cmpl.type_default.access_key = dma_cookie->access_key;

	give_completion(dma_cookie->user_info, dma_cookie->cmplq_record, &cmpl);

	user_mr_record_put(dma_cookie->mr_record); // one-time
	hfi1_bulksvc_user_info_put(dma_cookie->user_info);
}

static void bulksvc_on_cmd_dma_access_once(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_user_info * const user_info,
	struct hfi1_bulksvc_cmd_dma_access_once const * const cmd)
{
	struct hfi1_bulksvc_queue_record *cmplq_record;
	u64 offset;
	struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };

	cmplq_record = get_cmplq_record(svc, user_info, cmd->cmplq_id);
	if (!cmplq_record)
		goto exit;

	cmpl.app_context = cmd->app_context;
	cmpl.status = -EINVAL;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;
	cmpl.type_default.access_key = cmd->access_key;

	struct hfi1_bulksvc_user_mr_record* mr_record = lookup_user_mr_record(user_info, cmd->mr_key);

	if (!mr_record) {
		pr_err("%s:%d:%s() invalid MR key %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->mr_key);
		goto compl_error;
	}
	if (0 != validate_mr_access(mr_record, cmd->offset, cmd->len)) {
		pr_err("%s:%d:%s() invalid MR access for key %u, offset %llu, len %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->mr_key, cmd->offset, cmd->len);
		goto compl_error;
	}

	offset = cmd->offset;

	hfi1_bulksvc_user_info_get(user_info);
	user_mr_record_get(mr_record);

	BUILD_BUG_ON(sizeof(struct dma_access_once_cmpl_cookie) > sizeof(union hfi1_dms_completion_cookie));

	int rc = hfi1_dms_register_access(&svc->dms, &mr_record->dms_mr, cmd->offset, cmd->len,
		(union hfi1_dms_key) {
			.client = user_info->client_key,
			.access = cmd->access_key
		},
		(struct hfi1_dms_access_completion) {
		.fn = on_dma_access_once_complete,
		.cookie = *(union hfi1_dms_completion_cookie*)&(struct dma_access_once_cmpl_cookie) {
			.user_info = user_info,
			.cmplq_record = cmplq_record,
			.mr_record = mr_record,
			.app_context = cmd->app_context,
			.access_key = cmd->access_key,
		}},
		HFI1_DMS_ACCESS_TYPE_EPHEMERAL, NULL);
		
	if (rc < 0) {
		cmpl.status = (u32)rc;
		user_mr_record_put(mr_record);
		hfi1_bulksvc_user_info_put(user_info);
		goto compl_error;
	}

exit:
	return;
compl_error:
	give_completion(user_info, cmplq_record, &cmpl);
	return;
}

///
/// GRANT ACCESS TO MEMORY REGION ONGOING
///

struct dma_access_notify_cookie {
	struct hfi1_bulksvc * const svc;
	struct hfi1_bulksvc_user_info* user_info;
	u32 cmplq_id;
	u64 app_context;
	u32 access_key;
};

static void on_dma_access_notify(union hfi1_dms_completion_cookie *cookie, u16 flags, u64 imm_data, int status)
{
	struct hfi1_bulksvc_queue_record *cmplq_record;
	struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };

	BUILD_BUG_ON(sizeof(struct dma_access_notify_cookie) > sizeof(union hfi1_dms_completion_cookie));
	struct dma_access_notify_cookie *access_cookie = (struct dma_access_notify_cookie *)cookie;

	cmplq_record = get_cmplq_record(access_cookie->svc, access_cookie->user_info, access_cookie->cmplq_id);
	if (!cmplq_record) {
		pr_err("%s:%d:%s() ERROR: Unable to get cmplq record for notify\n", __FILENAME__, __LINE__, __func__);
		return;
	}

	cmpl.app_context = access_cookie->app_context;
	cmpl.status = status;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_NOTIFY;
	cmpl.type_notify.access_key = access_cookie->access_key;
	cmpl.type_notify.flags = flags;
	cmpl.type_notify.imm_data = imm_data;

		give_completion(access_cookie->user_info, cmplq_record, &cmpl);
}

static void bulksvc_on_cmd_dma_access_enable(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_user_info * const user_info,
	struct hfi1_bulksvc_cmd_dma_access_enable const * const cmd)
{
	struct hfi1_bulksvc_queue_record *cmplq_record;
	struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };
	int rc;

	cmplq_record = get_cmplq_record(svc, user_info, cmd->cmplq_id);
	if (!cmplq_record)
		goto exit;

	struct hfi1_dms_access_completion notification = {
		.fn = on_dma_access_notify,
		.cookie = *(union hfi1_dms_completion_cookie*)&(struct dma_access_notify_cookie) {
			.svc = svc,
			.user_info = user_info,
			.cmplq_id = cmd->notification_cmplq_id,
			.app_context = cmd->notification_app_context,
			.access_key = cmd->access_key,
		}
	};

	cmpl.app_context = cmd->app_context;
	cmpl.status = -EINVAL;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;
	cmpl.type_default.access_key = cmd->access_key;

	struct hfi1_bulksvc_user_mr_record *mr_record = lookup_user_mr_record(user_info, cmd->mr_key);
	if (!mr_record) {
		pr_err("%s:%d:%s() invalid MR key %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->mr_key);
		goto exit;
	}

	struct hfi1_bulksvc_user_mr_access_record * access_record = 
		lookup_user_mr_access_record(user_info, cmd->access_key);
	
	if (access_record) {
		pr_err("%s:%d:%s() access key %u already exists\n",
		       __FILENAME__, __LINE__, __func__, cmd->access_key);
		cmpl.status = -EEXIST;
		goto exit;
	}

	access_record = user_mr_access_record_create_and_insert(user_info, cmd->access_key, mr_record);
	if (!access_record) {
		pr_err("%s:%d:%s() failed to create access record for key %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->access_key);
		cmpl.status = -ENOMEM;
		goto exit;
	}

	union hfi1_dms_key const dms_key = {
		.client = user_info->client_key,
		.access = cmd->access_key,
	};
	rc = hfi1_dms_register_access(&svc->dms, &mr_record->dms_mr, cmd->offset, cmd->len, dms_key,
				  notification, HFI1_DMS_ACCESS_TYPE_PERSISTENT, NULL);

	if (rc < 0) {
		pr_err("%s:%d:%s() failed to enable DMA access for key %u: %d\n",
		       __FILENAME__, __LINE__, __func__, cmd->access_key, rc);
		user_mr_access_record_destroy_and_remove(access_record);
	}

	cmpl.status = rc;

exit:
	give_completion(user_info, cmplq_record, &cmpl);
	return;
}

static void bulksvc_on_cmd_dma_access_disable(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_user_info * const user_info,
	struct hfi1_bulksvc_cmd_dma_access_disable const * const cmd)
{
	struct hfi1_bulksvc_queue_record *cmplq_record;
	struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };
	int rc;

	cmplq_record = get_cmplq_record(svc, user_info, cmd->cmplq_id);
	if (!cmplq_record) {
		pr_err("Invalid cmplq id\n");
		goto exit;
	}

	cmpl.app_context = cmd->app_context;
	cmpl.status = -EINVAL;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;
	cmpl.type_default.access_key = cmd->access_key;

	struct hfi1_bulksvc_user_mr_access_record *access_record =
		lookup_user_mr_access_record(user_info, cmd->access_key);
	if (!access_record) {
		pr_err("%s:%d:%s() invalid access key %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->access_key);
		goto exit;
	}

	union hfi1_dms_key const dms_key = {
		.client = user_info->client_key,
		.access = cmd->access_key,
	};
	rc = hfi1_dms_unregister_access(&svc->dms, dms_key);

	if (rc == 0) {
		user_mr_access_record_destroy_and_remove(access_record);
	} else {
		pr_err("%s:%d:%s() failed to disable DMA access for key %u: %d\n",
		       __FILENAME__, __LINE__, __func__, cmd->access_key, rc);
	}

	cmpl.app_context = cmd->app_context;
	cmpl.status = rc;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;
	cmpl.type_default.access_key = cmd->access_key;

exit:
	give_completion(user_info, cmplq_record, &cmpl);
	return;
}

///
/// INITIATED MEMORY REGION RDMA TRANSACTION
///

struct initiated_mr_rdma_transact_completion_cookie {
	struct hfi1_bulksvc_user_info *user_info;
	struct hfi1_bulksvc_queue_record *cmplq_record;
	u64 app_context;
	struct hfi1_bulksvc_user_mr_record *mr_record;
};

static void on_mr_rdma_transact_complete(union hfi1_dms_completion_cookie *cookie, int status)
{
	struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };

	BUILD_BUG_ON(sizeof(struct initiated_mr_rdma_transact_completion_cookie) > sizeof(union hfi1_dms_completion_cookie));
	struct initiated_mr_rdma_transact_completion_cookie *mr_transact_cookie =
		(struct initiated_mr_rdma_transact_completion_cookie *)cookie;

	cmpl.app_context = mr_transact_cookie->app_context;
	cmpl.status = status;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;

	give_completion(mr_transact_cookie->user_info, mr_transact_cookie->cmplq_record, &cmpl);

	user_mr_record_put(mr_transact_cookie->mr_record);
	hfi1_bulksvc_user_info_put(mr_transact_cookie->user_info);
}

static void bulksvc_on_cmd_rdma_read(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_user_info * const user_info,
	struct hfi1_bulksvc_cmd_rdma_read const * const cmd)
{
	struct hfi1_bulksvc_queue_record *cmplq_record;
	struct hfi1_bulksvc_user_mr_record *mr_record;
	struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };
	int rc;

	cmplq_record = get_cmplq_record(svc, user_info, cmd->cmplq_id);
	if (!cmplq_record)
		goto exit;

	cmpl.app_context = cmd->app_context;
	cmpl.status = -EINVAL;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;

	mr_record = lookup_user_mr_record(user_info, cmd->mr_key);
	if (!mr_record) {
		pr_err("%s:%d:%s() invalid MR key %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->mr_key);
		goto compl_error;
	}
	if (0 != validate_mr_access(mr_record, cmd->mr_offset, cmd->len_bytes)) {
		pr_err("%s:%d:%s() invalid MR access for key %u, offset %llu, len %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->mr_key, cmd->mr_offset, cmd->len_bytes);
		goto compl_error;
	}

	hfi1_bulksvc_user_info_get(user_info);
	user_mr_record_get(mr_record);

	BUILD_BUG_ON(sizeof(struct initiated_mr_rdma_transact_completion_cookie) > sizeof(union hfi1_dms_completion_cookie));
	rc = hfi1_dms_read_data(
		&svc->dms, cmd->lid,
		(union hfi1_dms_key) { .access = cmd->access_key, .client = user_info->client_key },
		cmd->remote_offset, cmd->len_bytes, &mr_record->dms_mr, cmd->mr_offset,
		cmd->flags, cmd->imm_data,
		(struct hfi1_dms_tracker_completion) {
		.fn = on_mr_rdma_transact_complete,
		.cookie = *(union hfi1_dms_completion_cookie*)&(struct initiated_mr_rdma_transact_completion_cookie) {
			.user_info = user_info,
			.cmplq_record = cmplq_record,
			.app_context = cmd->app_context,
			.mr_record = mr_record,
		},
	});

	if (rc < 0) {
		pr_err("Could not initiate RDMA read: %d\n", rc);
		cmpl.status = (u32)rc;
		user_mr_record_put(mr_record);
		hfi1_bulksvc_user_info_put(user_info);
		goto compl_error;
	}
exit:
	return;

compl_error:
	give_completion(user_info, cmplq_record, &cmpl);
}

static void bulksvc_on_cmd_rdma_write(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_user_info * const user_info,
	struct hfi1_bulksvc_cmd_rdma_write const * const cmd)
{
	struct hfi1_bulksvc_queue_record *cmplq_record;
	struct hfi1_bulksvc_user_mr_record *mr_record;
	struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };
	int rc;

	cmplq_record = get_cmplq_record(svc, user_info, cmd->cmplq_id);
	if (!cmplq_record)
		goto exit;

	cmpl.app_context = cmd->app_context;
	cmpl.status = -EINVAL;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;

	mr_record = lookup_user_mr_record(user_info, cmd->mr_key);
	if (!mr_record || validate_mr_access(mr_record, cmd->mr_offset, cmd->len_bytes) < 0) {
		pr_err("%s:%d:%s() invalid MR key %u or access for key %u, offset %llu, len %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->mr_key, cmd->mr_key, cmd->mr_offset, cmd->len_bytes);
		goto compl_error;
	}

	hfi1_bulksvc_user_info_get(user_info);
	user_mr_record_get(mr_record);

	rc = hfi1_dms_write_data(&svc->dms, cmd->lid,
						(union hfi1_dms_key) { .access = cmd->access_key, .client = cmd->client_key },
				    cmd->remote_offset, cmd->len_bytes, &mr_record->dms_mr,
				    cmd->mr_offset,
						(u16) cmd->flags,
						cmd->imm_data,
				    (struct hfi1_dms_tracker_completion){
					.fn = on_mr_rdma_transact_complete,
					.cookie = *(union hfi1_dms_completion_cookie*)&(struct initiated_mr_rdma_transact_completion_cookie) {
						.user_info = user_info,
						.cmplq_record = cmplq_record,
						.app_context = cmd->app_context,
						.mr_record = mr_record,
					},
				 });

	if (rc < 0) {
		cmpl.status = (u32)rc;
		user_mr_record_put(mr_record);
		hfi1_bulksvc_user_info_put(user_info);
		goto compl_error;
	}

exit:
	return;
compl_error:
	give_completion(user_info, cmplq_record, &cmpl);
}


///
/// INITIATED VA RDMA TRANSACTION
///

struct rdma_va_completion_cookie {
	struct hfi1_bulksvc_user_info* user_info;
	struct hfi1_bulksvc_queue_record* cmplq_record;
	u64 app_context;
	struct hfi1_bulksvc_user_mr_record *mr_record;
};

static void on_rdma_va_complete(
	union hfi1_dms_completion_cookie * const cookie, int status)
{
	struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };

	BUILD_BUG_ON(sizeof(struct rdma_va_completion_cookie) > sizeof(union hfi1_dms_completion_cookie));
	struct rdma_va_completion_cookie * const read_cookie =
		(struct rdma_va_completion_cookie *)cookie;

	cmpl.app_context = read_cookie->app_context;
	cmpl.status = status;
	cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;

	give_completion(read_cookie->user_info, read_cookie->cmplq_record, &cmpl);

	user_mr_record_put(read_cookie->mr_record); // Implicitly one-time

	hfi1_bulksvc_user_info_put(read_cookie->user_info);
}

static void bulksvc_on_cmd_rdma_read_va(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_user_info * const user_info,
	struct hfi1_bulksvc_cmd_rdma_read_va const * const cmd)
{
	struct hfi1_bulksvc_queue_record *cmplq_record;
	struct hfi1_bulksvc_user_mr_record *mr_record;
	u64 mr_offset;

	cmplq_record = get_cmplq_record(svc, user_info, cmd->cmplq_id);
	if (!cmplq_record)
		return;

	hfi1_bulksvc_user_info_get(user_info);

	mr_record = user_mr_record_create_pinned_and_insert(user_info, cmd->vaddr, cmd->len_bytes, 0);
	if (!mr_record) {
		struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };

		dd_dev_err(svc->dd, "%s:%d:%s() failed to pin user dma buffer\n",
			   __FILENAME__, __LINE__, __func__);

		cmpl.app_context = cmd->app_context;
		cmpl.status = -EFAULT;
		cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;
		give_completion(user_info, cmplq_record, &cmpl);
		hfi1_bulksvc_user_info_put(user_info);
		return;
	}
	mr_offset = cmd->vaddr - mr_record->dms_mr.user.addr;

	BUILD_BUG_ON(sizeof(struct rdma_va_completion_cookie) > sizeof(union hfi1_dms_completion_cookie));
	int rc = hfi1_dms_read_data(&svc->dms, cmd->lid,
		(union hfi1_dms_key) { .access = cmd->access_key, .client = cmd->client_key },
		cmd->remote_offset, cmd->len_bytes, &mr_record->dms_mr, mr_offset,
		cmd->flags, cmd->imm_data,
		(struct hfi1_dms_tracker_completion) {
		.fn = on_rdma_va_complete,
		.cookie = *(union hfi1_dms_completion_cookie*)&(struct rdma_va_completion_cookie) {
			.user_info = user_info,
			.cmplq_record = cmplq_record,
			.app_context = cmd->app_context,
			.mr_record = mr_record,
		},
	});
	if (rc < 0) {
		struct hfi1_bulksvc_cmplq_entry cmpl = { 0 };

		cmpl.status = (u32)rc;
		cmpl.app_context = cmd->app_context;
		cmpl.type = HFI1_HFISVC_CQ_ENTRY_TYPE_DEFAULT;
		give_completion(user_info, cmplq_record, &cmpl);
		user_mr_record_put(mr_record);
		hfi1_bulksvc_user_info_put(user_info);
	}
}

static void bulksvc_on_user_cmd(struct hfi1_bulksvc * const svc,
	struct hfi1_bulksvc_user_info * const user_info,
	struct hfi1_bulksvc_cmd const * const cmd)
{
	switch (cmd->hdr.op) {
	case HFI1_BULKSVC_CMD_REG_DMA_BUFFER:
		bulksvc_on_cmd_reg_dma_buffer(svc, user_info,
					      &cmd->payld[0].register_dma_buffer);
		break;
	case HFI1_BULKSVC_CMD_RDMA_READ_VA:
		bulksvc_on_cmd_rdma_read_va(svc, user_info,
					    &cmd->payld[0].rdma_read_va);
		break;
	case HFI1_BULKSVC_CMD_RDMA_READ:
		bulksvc_on_cmd_rdma_read(svc, user_info,
					 &cmd->payld[0].rdma_read);
		break;
	case HFI1_BULKSVC_CMD_RDMA_WRITE:
		bulksvc_on_cmd_rdma_write(svc, user_info,
					  &cmd->payld[0].rdma_write);
		break;
	case HFI1_BULKSVC_CMD_MR_OPEN:
		bulksvc_on_cmd_mr_open(svc, user_info, &cmd->payld[0].mr_open);
		break;
	case HFI1_BULKSVC_CMD_MR_CLOSE:
		bulksvc_on_cmd_mr_close(svc, user_info,
					&cmd->payld[0].mr_close);
		break;
	case HFI1_BULKSVC_CMD_DMA_ACCESS_ONCE:
		bulksvc_on_cmd_dma_access_once(svc, user_info,
					       &cmd->payld[0].dma_access_once);
		break;
	case HFI1_BULKSVC_CMD_DMA_ACCESS_ENABLE:
		bulksvc_on_cmd_dma_access_enable(svc, user_info,
						 &cmd->payld[0].dma_access_enable);
		break;
	case HFI1_BULKSVC_CMD_DMA_ACCESS_DISABLE:
		bulksvc_on_cmd_dma_access_disable(svc, user_info,
						  &cmd->payld[0].dma_access_disable);
		break;
	case HFI1_BULKSVC_CMD_UVERBS_POST_SEND:
		bulksvc_on_cmd_uverbs_post_send(svc, user_info,
						&cmd->payld[0].uverbs_post_send);
		/* completion will come through rvt not us so try_complete wont be called */
		user_info->num_inflight--;
		break;

	default:
		dd_dev_err(svc->dd, "%s:%d:%s() unknown bulksvc cmd op %u\n",
			   __FILENAME__, __LINE__, __func__, cmd->hdr.op);
		/* TODO enqueue failure somehow */
		break;
	}
}

int hfi1_bulksvc_poll_user_cmds(struct hfi1_bulksvc * const svc)
{
	struct hfi1_bulksvc_user_info *user_info;
	int processed = 0;

	mutex_lock(&svc->user_info_lock);
	list_for_each_entry(user_info, &svc->user_infos, list_entry) {
		while (user_info->num_completion_overflows > 0) {
			u32 stack_top = user_info->num_completion_overflows - 1;
			int rc = try_give_completion(user_info, user_info->completion_overflow_records[stack_top], &user_info->completion_overflows[stack_top].cmplq_entry);
			if (rc == -EINVAL || rc == 0) {
				// EINVAL implies completion queue is gone, ok to drop/treat as success
				user_info->num_completion_overflows--;
				processed += 1;
			} else {
				break;
			}
		}

		bool too_many_inflight = user_info->num_inflight >= user_info->max_inflight;
		bool completions_overflowing = user_info->num_completion_overflows > (user_info->completion_overflows_size / 2);
		if (too_many_inflight || completions_overflowing)
			continue;

		u64 tails_cached[BULKSVC_USER_MAX_NUM_CMDQS];
		for (int cmdq_index = 0; cmdq_index < user_info->num_cmdqs; ++cmdq_index) {
			struct hfi1_bulksvc_queue_record *rec =
				&user_info->cmdq_records[cmdq_index];
			if (rec->active) {
				tails_cached[cmdq_index] = atomic64_read_acquire(rec->tail);
			} else {
				tails_cached[cmdq_index] = 0;
			}
		}

		// Round robin over all cmdqs for this user until we hit a limit
		bool handled_any = true;
		while (user_info->num_inflight < user_info->max_inflight && handled_any) {
			handled_any = false;
			for (int cmdq_index = 0; cmdq_index < user_info->num_cmdqs; ++cmdq_index) {
				struct hfi1_bulksvc_queue_record *rec =
					&user_info->cmdq_records[cmdq_index];
				if (!rec->active)
					continue;
					
				const u64 tail_cached = tails_cached[cmdq_index];
				u64 head = atomic64_read(rec->head);
				if (head >= tail_cached)
					continue;

				struct hfi1_bulksvc_cmd const * const next_cmd =
					(struct hfi1_bulksvc_cmd const * const)
					(rec->queue_buf_magic +
					((head & rec->idx_mask) *
					CACHELINE_SIZE));
					
				// If it's a command of more than one block, and the full command is not available, continue
				if ((head + next_cmd->hdr.num_blocks) > tail_cached) {
					continue;
				}
				
				bulksvc_on_user_cmd(svc, user_info, next_cmd);
				head += next_cmd->hdr.num_blocks;
				atomic64_set_release(rec->head, head);

				user_info->num_inflight += 1;
				processed += 1;
				handled_any = true;
			}
		}
	}
	mutex_unlock(&svc->user_info_lock);
	return processed;
}
