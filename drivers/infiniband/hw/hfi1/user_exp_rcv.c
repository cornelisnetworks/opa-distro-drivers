// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2020-2024 Cornelis Networks, Inc.
 * Copyright(c) 2015-2018 Intel Corporation.
 */
#include <asm/page.h>
#include <linux/string.h>

#include "mmu_rb.h"
#include "user_exp_rcv.h"
#include "trace.h"

static void unlock_exp_tids(struct hfi1_ctxtdata *uctxt,
			    struct exp_tid_set *set,
			    struct hfi1_filedata *fd);
static int set_rcvarray_entry(struct hfi1_filedata *fd,
			      struct tid_user_buf *tbuf,
			      u32 rcventry, struct tid_group *grp,
			      struct tid_pageset pgset,
			      struct tid_rb_node **onode);
static void cacheless_tid_rb_remove(struct hfi1_filedata *fdata,
				    struct tid_rb_node *tnode);
static int program_rcvarray(struct hfi1_filedata *fd,
			    struct tid_user_buf *tbuf,
			    struct tid_group *grp, u16 count,
			    u32 *tidlist, unsigned int *tididx,
			    unsigned int *pmapped);
static int unprogram_rcvarray(struct hfi1_filedata *fd, u32 tidinfo);
static void __clear_tid_node(struct hfi1_filedata *fd,
			     struct tid_rb_node *node);
static void clear_tid_node(struct hfi1_filedata *fd, struct tid_rb_node *node);

/*
 * Initialize context and file private data needed for Expected
 * receive caching. This needs to be done after the context has
 * been configured with the eager/expected RcvEntry counts.
 */
int hfi1_user_exp_rcv_init(struct hfi1_filedata *fd,
			   struct hfi1_ctxtdata *uctxt)
{
	int ret = 0;

	fd->entry_to_rb = kcalloc(uctxt->expected_count,
				  sizeof(struct rb_node *),
				  GFP_KERNEL);
	if (!fd->entry_to_rb)
		return -ENOMEM;

	if (!HFI1_CAP_UGET_MASK(uctxt->flags, TID_UNMAP)) {
		fd->invalid_tid_idx = 0;
		fd->invalid_tids = kcalloc(uctxt->expected_count,
					   sizeof(*fd->invalid_tids),
					   GFP_KERNEL);
		if (!fd->invalid_tids) {
			kfree(fd->entry_to_rb);
			fd->entry_to_rb = NULL;
			return -ENOMEM;
		}
		fd->use_mn = true;
	}

	/*
	 * PSM does not have a good way to separate, count, and
	 * effectively enforce a limit on RcvArray entries used by
	 * subctxts (when context sharing is used) when TID caching
	 * is enabled. To help with that, we calculate a per-process
	 * RcvArray entry share and enforce that.
	 * If TID caching is not in use, PSM deals with usage on its
	 * own. In that case, we allow any subctxt to take all of the
	 * entries.
	 *
	 * Make sure that we set the tid counts only after successful
	 * init.
	 */
	spin_lock(&fd->tid_lock);
	if (uctxt->subctxt_cnt && fd->use_mn) {
		u16 remainder;

		fd->tid_limit = uctxt->expected_count / uctxt->subctxt_cnt;
		remainder = uctxt->expected_count % uctxt->subctxt_cnt;
		if (remainder && fd->subctxt < remainder)
			fd->tid_limit++;
	} else {
		fd->tid_limit = uctxt->expected_count;
	}
	spin_unlock(&fd->tid_lock);

	return ret;
}

void hfi1_user_exp_rcv_free(struct hfi1_filedata *fd)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;

	mutex_lock(&uctxt->exp_mutex);
	if (!EXP_TID_SET_EMPTY(uctxt->tid_full_list))
		unlock_exp_tids(uctxt, &uctxt->tid_full_list, fd);
	if (!EXP_TID_SET_EMPTY(uctxt->tid_used_list))
		unlock_exp_tids(uctxt, &uctxt->tid_used_list, fd);
	mutex_unlock(&uctxt->exp_mutex);

	kfree(fd->invalid_tids);
	fd->invalid_tids = NULL;

	kfree(fd->entry_to_rb);
	fd->entry_to_rb = NULL;
}

static struct tid_user_buf_ops *bufops[HFI1_MAX_MEMINFO_ENTRIES];
static struct tid_node_ops *nodeops[HFI1_MAX_MEMINFO_ENTRIES];

/**
 * Register TID memory-pinning implementation for @type memory.
 *
 * @type one of the HFI1_MEMINFO_TYPE* defines found in hfi1_ioctl.h
 * @op Buffer ops to register
 * @nops Node ops to register
 *
 * @return 0 on success, non-zero on error
 */
int register_tid_ops(u16 type, struct tid_user_buf_ops *op, struct tid_node_ops *nops)
{
	if (type >= HFI1_MAX_MEMINFO_ENTRIES)
		return -EINVAL;
	bufops[type] = op;
	nodeops[type] = nops;
	return 0;
}

void deregister_tid_ops(u16 type)
{
	if (type >= HFI1_MAX_MEMINFO_ENTRIES)
		return;
	bufops[type] = NULL;
	nodeops[type] = NULL;
}

static struct tid_user_buf_ops *get_bufops(u16 type)
{
	if (type >= HFI1_MAX_MEMINFO_ENTRIES)
		return NULL;
	return bufops[type];
}

static struct tid_node_ops *get_nodeops(u16 type)
{
	if (type >= HFI1_MAX_MEMINFO_ENTRIES)
		return NULL;
	return nodeops[type];
}

/**
 * Create user buf for @memtype, store at @*ubuf
 *
 * @return 0 on success, non-zero on failure.
 */
static int create_user_buf(struct hfi1_filedata *fd, u16 memtype, struct hfi1_tid_info_v3 *tinfo,
			   bool allow_unaligned, struct tid_user_buf **ubuf)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct tid_user_buf_ops *ops;
	int ret;

	ops = get_bufops(memtype);
	if (!ops)
		return -EINVAL;

	if (tinfo->length == 0)
		return -EINVAL;

	ret = ops->init(uctxt->expected_count, fd->use_mn, tinfo->vaddr,
			tinfo->length, allow_unaligned, ubuf);
	if (ret)
		return ret;

	return 0;
}

/*
 * RcvArray entry allocation for Expected Receives is done by the
 * following algorithm:
 *
 * The context keeps 3 lists of groups of RcvArray entries:
 *   1. List of empty groups - tid_group_list
 *      This list is created during user context creation and
 *      contains elements which describe sets (of 8) of empty
 *      RcvArray entries.
 *   2. List of partially used groups - tid_used_list
 *      This list contains sets of RcvArray entries which are
 *      not completely used up. Another mapping request could
 *      use some of all of the remaining entries.
 *   3. List of full groups - tid_full_list
 *      This is the list where sets that are completely used
 *      up go.
 *
 * An attempt to optimize the usage of RcvArray entries is
 * made by finding all sets of physically contiguous pages in a
 * user's buffer.
 * These physically contiguous sets are further split into
 * sizes supported by the receive engine of the HFI. The
 * resulting sets of pages are stored in struct tid_pageset,
 * which describes the sets as:
 *    * .count - number of pages in this set
 *    * .idx - starting index into struct page ** array
 *                    of this set
 *
 * From this point on, the algorithm deals with the page sets
 * described above. The number of pagesets is divided by the
 * RcvArray group size to produce the number of full groups
 * needed.
 *
 * Groups from the 3 lists are manipulated using the following
 * rules:
 *   1. For each set of 8 pagesets, a complete group from
 *      tid_group_list is taken, programmed, and moved to
 *      the tid_full_list list.
 *   2. For all remaining pagesets:
 *      2.1 If the tid_used_list is empty and the tid_group_list
 *          is empty, stop processing pageset and return only
 *          what has been programmed up to this point.
 *      2.2 If the tid_used_list is empty and the tid_group_list
 *          is not empty, move a group from tid_group_list to
 *          tid_used_list.
 *      2.3 For each group is tid_used_group, program as much as
 *          can fit into the group. If the group becomes fully
 *          used, move it to tid_full_list.
 */
int hfi1_user_exp_rcv_setup(struct hfi1_filedata *fd,
			    struct hfi1_tid_info_v3 *tinfo,
			    bool allow_unaligned)
{
	int ret = 0, need_group = 0, pinned;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;
	/*
	 * mapped and mapped_pages are implementation-sized pages, not
	 * EXPECTED_ADDR_SIZE-sized.
	 */
	unsigned int ngroups, pageset_count,
		tididx = 0, mapped, mapped_pages = 0;
	u32 *tidlist = NULL;
	struct tid_user_buf *tidbuf;
	u16 memtype = (tinfo->flags & HFI1_TID_UPDATE_V3_FLAGS_MEMINFO_MASK);

	trace_hfi1_exp_tid_update(uctxt->ctxt, fd->subctxt, tinfo);
	ret = create_user_buf(fd, memtype, tinfo, allow_unaligned, &tidbuf);
	if (ret)
		return ret;

	pinned = tidbuf->ops->pin_pages(fd, tidbuf);
	if (pinned <= 0) {
		ret = (pinned < 0) ? pinned : -ENOSPC;
		goto fail_unpin;
	}

	/* Cannot program TIDs for < EXPECTED_ADDR_SIZE pages */
	if (tidbuf->ops->page_size(tidbuf) < EXPECTED_ADDR_SIZE) {
		ret = -EOPNOTSUPP;
		goto fail_unpin;
	}

	/* Find sets of physically contiguous pages */
	ret = tidbuf->ops->find_phys_blocks(tidbuf, pinned);
	if (ret)
		goto fail_unpin;

	/* Reserve the number of expected tids to be used. */
	spin_lock(&fd->tid_lock);
	if (fd->tid_used + tidbuf->n_psets > fd->tid_limit)
		pageset_count = fd->tid_limit - fd->tid_used;
	else
		pageset_count = tidbuf->n_psets;
	fd->tid_used += pageset_count;
	spin_unlock(&fd->tid_lock);

	if (!pageset_count) {
		ret = -ENOSPC;
		goto fail_unreserve;
	}

	ngroups = pageset_count / dd->rcv_entries.group_size;
	tidlist = kcalloc(pageset_count, sizeof(*tidlist), GFP_KERNEL);
	if (!tidlist) {
		ret = -ENOMEM;
		goto fail_unreserve;
	}

	tididx = 0;

	/*
	 * From this point on, we are going to be using shared (between master
	 * and subcontexts) context resources. We need to take the lock.
	 */
	mutex_lock(&uctxt->exp_mutex);
	/*
	 * The first step is to program the RcvArray entries which are complete
	 * groups.
	 */
	while (ngroups && uctxt->tid_group_list.count) {
		struct tid_group *grp =
			tid_group_pop(&uctxt->tid_group_list);

		ret = program_rcvarray(fd, tidbuf, grp,
				       dd->rcv_entries.group_size,
				       tidlist, &tididx, &mapped);
		/*
		 * If there was a failure to program the RcvArray
		 * entries for the entire group, reset the grp fields
		 * and add the grp back to the free group list.
		 */
		if (ret <= 0) {
			tid_group_add_tail(grp, &uctxt->tid_group_list);
			hfi1_cdbg(TID,
				  "Failed to program RcvArray group %d", ret);
			goto unlock;
		}

		tid_group_add_tail(grp, &uctxt->tid_full_list);
		ngroups--;
		mapped_pages += mapped;
	}

	while (tididx < pageset_count) {
		struct tid_group *grp, *ptr;
		/*
		 * If we don't have any partially used tid groups, check
		 * if we have empty groups. If so, take one from there and
		 * put in the partially used list.
		 */
		if (!uctxt->tid_used_list.count || need_group) {
			if (!uctxt->tid_group_list.count)
				goto unlock;

			grp = tid_group_pop(&uctxt->tid_group_list);
			tid_group_add_tail(grp, &uctxt->tid_used_list);
			need_group = 0;
		}
		/*
		 * There is an optimization opportunity here - instead of
		 * fitting as many page sets as we can, check for a group
		 * later on in the list that could fit all of them.
		 */
		list_for_each_entry_safe(grp, ptr, &uctxt->tid_used_list.list,
					 list) {
			unsigned use = min_t(unsigned, pageset_count - tididx,
					     grp->size - grp->used);

			ret = program_rcvarray(fd, tidbuf, grp,
					       use, tidlist,
					       &tididx, &mapped);
			if (ret < 0) {
				hfi1_cdbg(TID,
					  "Failed to program RcvArray entries %d",
					  ret);
				goto unlock;
			} else if (ret > 0) {
				if (grp->used == grp->size)
					tid_group_move(grp,
						       &uctxt->tid_used_list,
						       &uctxt->tid_full_list);
				mapped_pages += mapped;
				need_group = 0;
				/* Check if we are done so we break out early */
				if (tididx >= pageset_count)
					break;
			} else if (WARN_ON(ret == 0)) {
				/*
				 * If ret is 0, we did not program any entries
				 * into this group, which can only happen if
				 * we've screwed up the accounting somewhere.
				 * Warn and try to continue.
				 */
				need_group = 1;
			}
		}
	}
unlock:
	mutex_unlock(&uctxt->exp_mutex);
	/*
	 * mapped_pages is based on implementation page size, not expected
	 * receive addressing.
	 *
	 * E.g. if implementation uses 64KiB pages and expected receive
	 * addressing is based on 4KiB, for 128KiB of mapped memory,
	 * mapped_pages=2 not mapped_pages=32.
	 */
	hfi1_cdbg(TID, "total mapped: tidpairs:%u pages:%u (%d)", tididx,
		  mapped_pages, ret);

	/* fail if nothing was programmed, set error if none provided */
	if (tididx == 0) {
		if (ret >= 0)
			ret = -ENOSPC;
		goto fail_unreserve;
	}

	/* adjust reserved tid_used to actual count */
	spin_lock(&fd->tid_lock);
	fd->tid_used -= pageset_count - tididx;
	spin_unlock(&fd->tid_lock);

	/* unpin all pages not covered by a TID */
	tidbuf->ops->unpin_pages(fd, tidbuf, mapped_pages, pinned - mapped_pages);

	/* check for an invalidate during setup */
	if (tidbuf->ops->invalidated(tidbuf)) {
		ret = -EBUSY;
		goto fail_unprogram;
	}

	tinfo->tidcnt = tididx;
	/* Should never happen but detect if somehow implementation pinned too many pages */
	if (check_mul_overflow(mapped_pages, tidbuf->ops->page_size(tidbuf), &tinfo->length)) {
		ret = -EFAULT;
		goto fail_unprogram;
	}

	if (copy_to_user(u64_to_user_ptr(tinfo->tidlist),
			 tidlist, sizeof(tidlist[0]) * tididx)) {
		ret = -EFAULT;
		goto fail_unprogram;
	}

	tidbuf->ops->unnotify(tidbuf);
	tidbuf->ops->free(tidbuf);
	kfree(tidlist);
	return 0;

fail_unprogram:
	/* unprogram, unmap, and unpin all allocated TIDs */
	tinfo->tidlist = (unsigned long)tidlist;
	hfi1_user_exp_rcv_clear(fd, (struct hfi1_tid_info *)tinfo);
	tinfo->tidlist = 0;
	pinned = 0;		/* nothing left to unpin */
	pageset_count = 0;	/* nothing left reserved */
fail_unreserve:
	spin_lock(&fd->tid_lock);
	fd->tid_used -= pageset_count;
	spin_unlock(&fd->tid_lock);
fail_unpin:
	tidbuf->ops->unnotify(tidbuf);
	if (pinned > 0)
		tidbuf->ops->unpin_pages(fd, tidbuf, 0, pinned);
	tidbuf->ops->free(tidbuf);
	kfree(tidlist);
	return ret;
}

int hfi1_user_exp_rcv_clear(struct hfi1_filedata *fd,
			    struct hfi1_tid_info *tinfo)
{
	int ret = 0;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	u32 *tidinfo;
	unsigned tididx;

	if (unlikely(tinfo->tidcnt > fd->tid_used))
		return -EINVAL;

	tidinfo = memdup_array_user(u64_to_user_ptr(tinfo->tidlist),
				    tinfo->tidcnt, sizeof(tidinfo[0]));
	if (IS_ERR(tidinfo))
		return PTR_ERR(tidinfo);

	mutex_lock(&uctxt->exp_mutex);
	for (tididx = 0; tididx < tinfo->tidcnt; tididx++) {
		ret = unprogram_rcvarray(fd, tidinfo[tididx]);
		if (ret) {
			hfi1_cdbg(TID, "Failed to unprogram rcv array %d",
				  ret);
			break;
		}
	}
	spin_lock(&fd->tid_lock);
	fd->tid_used -= tididx;
	spin_unlock(&fd->tid_lock);
	tinfo->tidcnt = tididx;
	mutex_unlock(&uctxt->exp_mutex);

	kfree(tidinfo);
	return ret;
}

int hfi1_user_exp_rcv_invalid(struct hfi1_filedata *fd,
			      struct hfi1_tid_info *tinfo)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	unsigned long *ev = uctxt->dd->events +
		(uctxt_offset(uctxt) + fd->subctxt);
	u32 *array;
	int ret = 0;

	/*
	 * copy_to_user() can sleep, which will leave the invalid_lock
	 * locked and cause the MMU notifier to be blocked on the lock
	 * for a long time.
	 * Copy the data to a local buffer so we can release the lock.
	 */
	array = kcalloc(uctxt->expected_count, sizeof(*array), GFP_KERNEL);
	if (!array)
		return -EFAULT;

	spin_lock(&fd->invalid_lock);
	if (fd->invalid_tid_idx) {
		memcpy(array, fd->invalid_tids, sizeof(*array) *
		       fd->invalid_tid_idx);
		memset(fd->invalid_tids, 0, sizeof(*fd->invalid_tids) *
		       fd->invalid_tid_idx);
		tinfo->tidcnt = fd->invalid_tid_idx;
		fd->invalid_tid_idx = 0;
		/*
		 * Reset the user flag while still holding the lock.
		 * Otherwise, PSM can miss events.
		 */
		clear_bit(_HFI1_EVENT_TID_MMU_NOTIFY_BIT, ev);
	} else {
		tinfo->tidcnt = 0;
	}
	spin_unlock(&fd->invalid_lock);

	if (tinfo->tidcnt) {
		if (copy_to_user((void __user *)tinfo->tidlist,
				 array, sizeof(*array) * tinfo->tidcnt))
			ret = -EFAULT;
	}
	kfree(array);

	return ret;
}

/*
 * Convert @node's implementation-defined npages to number of
 * EXPECTED_ADDR_SIZE pages.
 *
 * @return number of EXPECTED_ADDR_SIZE pages
 */
static unsigned int node_npages(const struct tid_rb_node *node)
{
	/* Underflow/overflow protection here depends on other places enforcing that:
	 *   page_shift >= EXPECTED_ADDR_SHIFT
	 *   node->npages * (1 << page_shift) <= MAX_EXPECTED_BUFFER
	 */
	return (node->npages << node->page_shift) >> EXPECTED_ADDR_SHIFT;
}

/**
 * program_rcvarray() - program an RcvArray group with receive buffers
 * @fd: filedata pointer
 * @tbuf: pointer to struct tid_user_buf that has the user buffer starting
 *	  virtual address, buffer length, page pointers, pagesets (array of
 *	  struct tid_pageset holding information on physically contiguous
 *	  chunks from the user buffer), and other fields.
 * @grp: RcvArray group
 * @count: number of struct tid_pageset's to program
 * @tidlist: the array of u32 elements when the information about the
 *           programmed RcvArray entries is to be encoded.
 * @tididx: starting offset into tidlist
 * @pmapped: (output parameter) number of implementation pages programmed into the RcvArray
 *           entries.
 *
 * This function will program up to 'count' number of RcvArray entries from the
 * group 'grp'. To make best use of write-combining writes, the function will
 * perform writes to the unused RcvArray entries which will be ignored by the
 * HW. Each RcvArray entry will be programmed with a physically contiguous
 * buffer chunk from the user's virtual buffer.
 *
 * Return:
 * -EINVAL if the requested count is larger than the size of the group,
 * -ENOMEM or -EFAULT on error from set_rcvarray_entry(), or
 * number of RcvArray entries programmed.
 */
static int program_rcvarray(struct hfi1_filedata *fd,
			    struct tid_user_buf *tbuf,
			    struct tid_group *grp, u16 count,
			    u32 *tidlist, unsigned int *tididx,
			    unsigned int *pmapped)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;
	u16 idx;
	unsigned int start = *tididx;
	u32 tidinfo = 0, rcventry, useidx = 0;
	int mapped = 0;

	/* Count should never be larger than the group size */
	if (count > grp->size)
		return -EINVAL;

	/* Find the first unused entry in the group */
	for (idx = 0; idx < grp->size; idx++) {
		if (!(grp->map & (1 << idx))) {
			useidx = idx;
			break;
		}
		rcv_array_wc_fill(dd, grp->base + idx);
	}

	idx = 0;
	while (idx < count) {
		u16 setidx = start + idx;
		struct tid_rb_node *node;
		int ret = 0;

		/*
		 * If this entry in the group is used, move to the next one.
		 * If we go past the end of the group, exit the loop.
		 */
		if (useidx >= grp->size) {
			break;
		} else if (grp->map & (1 << useidx)) {
			rcv_array_wc_fill(dd, grp->base + useidx);
			useidx++;
			continue;
		}

		rcventry = grp->base + useidx;
		ret = set_rcvarray_entry(fd, tbuf, rcventry, grp,
					 tbuf->psets[setidx], &node);
		if (ret)
			return ret;
		mapped += node->npages;

		/* In-memory TIDs requires EXPECTED_ADDR_SIZE page-size npages */
		tidinfo = create_tid(rcventry - uctxt->expected_base, node_npages(node));
		tidlist[(*tididx)++] = tidinfo;
		grp->used++;
		grp->map |= 1 << useidx++;
		idx++;
	}

	/* Fill the rest of the group with "blank" writes */
	for (; useidx < grp->size; useidx++)
		rcv_array_wc_fill(dd, grp->base + useidx);
	*pmapped = mapped;
	return idx;
}

/*
 * DMA-map and program single TID entry for physically contiguous pinned page
 * range.
 *
 * @fd
 * @tbuf
 * @rcventry
 * @grp
 * @pgset Gives page-range from @tbuf to DMA-map and program
 * @onode out node. Undefined on error.
 *
 * @return 0 on success, non-zero on error.
 */
static int set_rcvarray_entry(struct hfi1_filedata *fd,
			      struct tid_user_buf *tbuf,
			      u32 rcventry, struct tid_group *grp,
			      struct tid_pageset pgset,
			      struct tid_rb_node **onode)
{
	int ret;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct tid_rb_node *node;
	struct hfi1_devdata *dd = uctxt->dd;
	struct tid_node_ops *nodeops = get_nodeops(tbuf->type);
	unsigned int npages = pgset.count;
	u16 pageidx = pgset.idx;

	if (WARN_ON(!nodeops))
		return -EINVAL;

	ret = nodeops->init(fd, tbuf, rcventry, grp, pageidx, npages, &node);
	if (ret)
		return ret;

	if (node->use_mn) {
		ret = node->ops->register_notify(node);
		if (ret)
			goto out_unmap;
	}

	*onode = node;
	fd->entry_to_rb[node->rcventry - uctxt->expected_base] = node;

	/* RcvArray entry requires EXPECTED_ADDR_SIZE page-size npages */
	hfi1_put_tid(dd, rcventry, PT_EXPECTED, node->dma_addr,
		     ilog2(node_npages(node)) + 1);

	trace_hfi1_exp_tid_reg(uctxt->ctxt, fd->subctxt, rcventry,
			       node_npages(node),
			       node->vaddr, node->phys,
			       node->dma_addr, node->type);
	return 0;

out_unmap:
	hfi1_cdbg(TID, "Failed to insert RB node %u 0x%lx, 0x%lx %d",
		  node->rcventry, node->vaddr, node->phys, ret);

	node->ops->dma_unmap(node);
	node->ops->free(node);
	return -EFAULT;
}

static int unprogram_rcvarray(struct hfi1_filedata *fd, u32 tidinfo)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;
	struct tid_rb_node *node;
	u32 tidctrl = EXP_TID_GET(tidinfo, CTRL);
	u32 tididx = EXP_TID_GET(tidinfo, IDX) << 1, rcventry;

	if (tidctrl == 0x3 || tidctrl == 0x0)
		return -EINVAL;

	rcventry = tididx + (tidctrl - 1);

	if (rcventry >= uctxt->expected_count) {
		dd_dev_err(dd, "Invalid RcvArray entry (%u) index for ctxt %u\n",
			   rcventry, uctxt->ctxt);
		return -EINVAL;
	}

	node = fd->entry_to_rb[rcventry];
	if (!node || node->rcventry != (uctxt->expected_base + rcventry))
		return -EBADF;

	node->ops->unregister_notify(node);
	cacheless_tid_rb_remove(fd, node);

	return 0;
}

static void __clear_tid_node(struct hfi1_filedata *fd, struct tid_rb_node *node)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;

	mutex_lock(&node->invalidate_mutex);
	if (node->freed)
		goto done;
	node->freed = true;

	trace_hfi1_exp_tid_unreg(uctxt->ctxt, fd->subctxt, node->rcventry,
				 node_npages(node),
				 node->vaddr, node->phys,
				 node->dma_addr, node->type);

	/* Make sure device has seen the write before pages are unpinned */
	hfi1_put_tid(dd, node->rcventry, PT_INVALID_FLUSH, 0, 0);

	node->ops->unpin_pages(fd, node);
done:
	mutex_unlock(&node->invalidate_mutex);
}

static void clear_tid_node(struct hfi1_filedata *fd, struct tid_rb_node *node)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;

	__clear_tid_node(fd, node);

	node->grp->used--;
	node->grp->map &= ~(1 << (node->rcventry - node->grp->base));

	if (node->grp->used == node->grp->size - 1)
		tid_group_move(node->grp, &uctxt->tid_full_list,
			       &uctxt->tid_used_list);
	else if (!node->grp->used)
		tid_group_move(node->grp, &uctxt->tid_used_list,
			       &uctxt->tid_group_list);
	node->ops->free(node);
}

/*
 * As a simple helper for hfi1_user_exp_rcv_free, this function deals with
 * clearing nodes in the non-cached case.
 */
static void unlock_exp_tids(struct hfi1_ctxtdata *uctxt,
			    struct exp_tid_set *set,
			    struct hfi1_filedata *fd)
{
	struct tid_group *grp, *ptr;
	int i;

	list_for_each_entry_safe(grp, ptr, &set->list, list) {
		list_del_init(&grp->list);

		for (i = 0; i < grp->size; i++) {
			if (grp->map & (1 << i)) {
				u16 rcventry = grp->base + i;
				struct tid_rb_node *node;

				node = fd->entry_to_rb[rcventry -
							  uctxt->expected_base];
				if (!node || node->rcventry != rcventry)
					continue;

				node->ops->unregister_notify(node);
				cacheless_tid_rb_remove(fd, node);
			}
		}
	}
}

/**
 * Unprogram TID for @node, updating user TID invalidation events when
 * @node->fdata->use_mn is true.
 */
void hfi1_user_exp_rcv_invalidate(struct tid_rb_node *node)
{
	struct hfi1_filedata *fdata = node->fdata;
	struct hfi1_ctxtdata *uctxt = fdata->uctxt;

	trace_hfi1_exp_tid_inval(uctxt->ctxt, fdata->subctxt,
				 node->vaddr,
				 node->rcventry,
				 node_npages(node),
				 node->dma_addr, node->type);

	/* clear the hardware rcvarray entry */
	__clear_tid_node(fdata, node);

	/* User TID invalidation events not in use, nothing else to do */
	if (!node->use_mn)
		return;

	spin_lock(&fdata->invalid_lock);
	if (fdata->invalid_tid_idx < uctxt->expected_count) {
		/* In-memory TIDs requires EXPECTED_ADDR_SIZE page-size npages */
		fdata->invalid_tids[fdata->invalid_tid_idx] =
			create_tid(node->rcventry - uctxt->expected_base,
				   node_npages(node));
		if (!fdata->invalid_tid_idx) {
			unsigned long *ev;

			/*
			 * hfi1_set_uevent_bits() sets a user event flag
			 * for all processes. Because calling into the
			 * driver to process TID cache invalidations is
			 * expensive and TID cache invalidations are
			 * handled on a per-process basis, we can
			 * optimize this to set the flag only for the
			 * process in question.
			 */
			ev = uctxt->dd->events +
				(uctxt_offset(uctxt) + fdata->subctxt);
			set_bit(_HFI1_EVENT_TID_MMU_NOTIFY_BIT, ev);
		}
		fdata->invalid_tid_idx++;
	}
	spin_unlock(&fdata->invalid_lock);
}

static void cacheless_tid_rb_remove(struct hfi1_filedata *fdata,
				    struct tid_rb_node *tnode)
{
	u32 base = fdata->uctxt->expected_base;

	fdata->entry_to_rb[tnode->rcventry - base] = NULL;
	clear_tid_node(fdata, tnode);
}
