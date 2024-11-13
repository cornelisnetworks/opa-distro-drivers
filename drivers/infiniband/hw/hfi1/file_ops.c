// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2020-2024 Cornelis Networks, Inc.
 * Copyright(c) 2015-2020 Intel Corporation.
 */

#include <linux/poll.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/sched/mm.h>
#include <linux/bitmap.h>

#include <rdma/ib.h>

#include <uapi/rdma/hfi/hfi1_user.h>

#include "hfi.h"
#include "pio.h"
#include "device.h"
#include "common.h"
#include "trace.h"
#include "mmu_rb.h"
#include "user_sdma.h"
#include "user_exp_rcv.h"
#include "aspm.h"
#include "pinning.h"
#include "file_ops.h"
#include "uverbs.h"

#include "bulksvc.h"

#undef pr_fmt
#define pr_fmt(fmt) DRIVER_NAME ": " fmt

#define SEND_CTXT_HALT_TIMEOUT 1000 /* msecs */

/*
 * File operation functions
 */
static int hfi1_file_open(struct inode *inode, struct file *fp);
static int hfi1_file_close(struct inode *inode, struct file *fp);
static ssize_t hfi1_write_iter(struct kiocb *kiocb, struct iov_iter *from);
static __poll_t hfi1_poll(struct file *fp, struct poll_table_struct *pt);
static int hfi1_file_mmap(struct file *fp, struct vm_area_struct *vma);

static u64 kvirt_to_phys(void *addr);
static int assign_ctxt(struct hfi1_filedata *fd, unsigned long arg, u32 len);
static void init_subctxts(struct hfi1_ctxtdata *uctxt,
			  const struct hfi1_assign_ctxt_cmd *uinfo);
static int init_user_ctxt(struct hfi1_filedata *fd,
			  struct hfi1_ctxtdata *uctxt);
static void user_init(struct hfi1_ctxtdata *uctxt);
static int get_ctxt_info(struct hfi1_filedata *fd, unsigned long arg, u32 len);
static int get_base_info(struct hfi1_filedata *fd, unsigned long arg, u32 len);
static int user_exp_rcv_setup(struct hfi1_filedata *fd, unsigned long arg,
			      u32 len);
#ifdef NVIDIA_GPU_DIRECT
static int user_exp_rcv_setup_v2(struct hfi1_filedata *fd, unsigned long arg,
				 u32 len);
#endif
static int user_exp_rcv_clear(struct hfi1_filedata *fd, unsigned long arg,
			      u32 len);
static int user_exp_rcv_invalid(struct hfi1_filedata *fd, unsigned long arg,
				u32 len);
static int setup_base_ctxt(struct hfi1_filedata *fd,
			   struct hfi1_ctxtdata *uctxt);
static int setup_subctxt(struct hfi1_ctxtdata *uctxt);

static int find_sub_ctxt(struct hfi1_filedata *fd,
			 const struct hfi1_assign_ctxt_cmd *uinfo);
static int allocate_ctxt(struct hfi1_filedata *fd,
			 const struct hfi1_assign_ctxt_cmd *uinfo,
			 struct hfi1_ctxtdata **cd);
static void deallocate_ctxt(struct hfi1_ctxtdata *uctxt);
static __poll_t poll_urgent(struct file *fp, struct poll_table_struct *pt);
static __poll_t poll_next(struct file *fp, struct poll_table_struct *pt);
static vm_fault_t vma_fault(struct vm_fault *vmf);
static long hfi1_file_ioctl(struct file *fp, unsigned int cmd,
			    unsigned long arg);
static int get_pinning_stats(struct hfi1_filedata *fd, unsigned long arg,
			     u32 len);
static int create_bulksvc_cmplq(struct hfi1_filedata *fd, unsigned long arg,
				 u32 len);
static int create_bulksvc_cmdq(struct hfi1_filedata *fd, unsigned long arg,
				 u32 len);
static int ioctl_init_bulksvc_client(struct hfi1_filedata *fd, unsigned long arg, u32 len);
static int ioctl_bulksvc_doorbell(struct hfi1_filedata *fd, unsigned long arg, u32 len);

static const struct file_operations hfi1_file_ops = {
	.owner = THIS_MODULE,
	.write_iter = hfi1_write_iter,
	.open = hfi1_file_open,
	.release = hfi1_file_close,
	.unlocked_ioctl = hfi1_file_ioctl,
	.poll = hfi1_poll,
	.mmap = hfi1_file_mmap,
	.llseek = noop_llseek,
};

static const struct vm_operations_struct vm_ops = {
	.fault = vma_fault,
};

/*
 * Masks and offsets defining the mmap tokens
 */
#define HFI1_MMAP_OFFSET_MASK   0xfffULL
#define HFI1_MMAP_OFFSET_SHIFT  0
#define HFI1_MMAP_SUBCTXT_MASK  0xfULL
#define HFI1_MMAP_SUBCTXT_SHIFT 12
#define HFI1_MMAP_CTXT_MASK     0xffULL
#define HFI1_MMAP_CTXT_SHIFT    16
#define HFI1_MMAP_TYPE_MASK     0xffULL
#define HFI1_MMAP_TYPE_SHIFT    24
#define HFI1_MMAP_MAGIC_MASK    0xfffffffULL
#define HFI1_MMAP_MAGIC_SHIFT   36

#define HFI1_MMAP_MAGIC         0xdabbad0
// #define HFI1_MMAP_MAGIC         0xdabbad00

#define HFI1_MMAP_TOKEN_SET(field, val)	\
	(((val) & HFI1_MMAP_##field##_MASK) << HFI1_MMAP_##field##_SHIFT)
#define HFI1_MMAP_TOKEN_GET(field, token) \
	(((token) >> HFI1_MMAP_##field##_SHIFT) & HFI1_MMAP_##field##_MASK)
#define HFI1_MMAP_TOKEN(type, ctxt, subctxt, addr)   \
	(HFI1_MMAP_TOKEN_SET(MAGIC, HFI1_MMAP_MAGIC) | \
	HFI1_MMAP_TOKEN_SET(TYPE, type) | \
	HFI1_MMAP_TOKEN_SET(CTXT, ctxt) | \
	HFI1_MMAP_TOKEN_SET(SUBCTXT, subctxt) | \
	HFI1_MMAP_TOKEN_SET(OFFSET, (offset_in_page(addr))))

#define HFI1_BULKSVC_FAST_DB_INDEX (5ull)

#define dbg(fmt, ...)				\
	pr_info(fmt, ##__VA_ARGS__)

static inline int is_valid_mmap(u64 token)
{
	return (HFI1_MMAP_TOKEN_GET(MAGIC, token) == HFI1_MMAP_MAGIC);
}

struct hfi1_filedata *hfi1_alloc_filedata(struct hfi1_devdata *dd)
{
	struct hfi1_filedata *fd;

	/* The real work is performed later in assign_ctxt() */

	fd = kzalloc(sizeof(*fd), GFP_KERNEL);

	if (!fd || init_srcu_struct(&fd->pq_srcu))
		goto nomem;
	spin_lock_init(&fd->pq_rcu_lock);
	spin_lock_init(&fd->tid_lock);
	spin_lock_init(&fd->invalid_lock);
	fd->rec_cpu_num = -1; /* no cpu affinity by default */
	fd->dd = dd;
	/* no port yet */
	fd->ppd = NULL;
	return fd;
nomem:
	kfree(fd);
	return NULL;
}

static int hfi1_file_open(struct inode *inode, struct file *fp)
{
	struct hfi1_filedata *fd;
	struct hfi1_devdata *dd = container_of(inode->i_cdev,
					       struct hfi1_devdata,
					       user_cdev);

	if (!(dd->flags & HFI1_PRESENT))
		return -EINVAL;

	if (!refcount_inc_not_zero(&dd->user_refcount))
		return -ENXIO;

	fd = hfi1_alloc_filedata(dd);
	if (!fd)
		goto nomem;

	fp->private_data = fd;
	return 0;
nomem:
	fp->private_data = NULL;
	if (refcount_dec_and_test(&dd->user_refcount))
		complete(&dd->user_comp);
	return -ENOMEM;
}

static long hfi1_file_ioctl(struct file *fp, unsigned int cmd,
			    unsigned long arg)
{
	struct hfi1_filedata *fd = fp->private_data;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	int ret = 0;
	int uval = 0;

	hfi1_cdbg(IOCTL, "IOCTL recv: 0x%x", cmd);

	bool const allowed_init_ioctl =
		cmd == HFI1_IOCTL_ASSIGN_CTXT ||
		cmd == HFI1_IOCTL_GET_VERS ||
		cmd == HFI1_IOCTL_BULKSVC_CLIENT_INIT;

	bool const allowed_bulksvc_ioctl =
		fd->bulksvc_user_info &&
		(cmd == HFI1_IOCTL_BULKSVC_GET_CMDQ ||
		 cmd == HFI1_IOCTL_BULKSVC_GET_CMPLQ ||
		 cmd == HFI1_IOCTL_BULKSVC_DOORBELL);

	bool const allowed_uctxt_context = 
		uctxt &&
		(cmd != HFI1_IOCTL_BULKSVC_CLIENT_INIT &&
		 cmd != HFI1_IOCTL_BULKSVC_GET_CMDQ &&
		 cmd != HFI1_IOCTL_BULKSVC_GET_CMPLQ);
		
	if (!allowed_init_ioctl && !allowed_uctxt_context && !allowed_bulksvc_ioctl) {
		return -EINVAL;
	}

	switch (cmd) {
	case HFI1_IOCTL_ASSIGN_CTXT:
		ret = assign_ctxt(fd, arg, _IOC_SIZE(cmd));
		break;

	case HFI1_IOCTL_CTXT_INFO:
		ret = get_ctxt_info(fd, arg, _IOC_SIZE(cmd));
		break;

	case HFI1_IOCTL_USER_INFO:
		ret = get_base_info(fd, arg, _IOC_SIZE(cmd));
		break;

	case HFI1_IOCTL_CREDIT_UPD:
		if (uctxt)
			sc_return_credits(uctxt->sc);
		break;

	case HFI1_IOCTL_TID_UPDATE:
	case HFI1_IOCTL_TID_UPDATE_V3:
		ret = user_exp_rcv_setup(fd, arg, _IOC_SIZE(cmd));
		break;
#ifdef NVIDIA_GPU_DIRECT
	case HFI1_IOCTL_TID_UPDATE_V2:
		ret = user_exp_rcv_setup_v2(fd, arg, _IOC_SIZE(cmd));
		break;
#endif
	case HFI1_IOCTL_TID_FREE:
		ret = user_exp_rcv_clear(fd, arg, _IOC_SIZE(cmd));
		break;

	case HFI1_IOCTL_TID_INVAL_READ:
		ret = user_exp_rcv_invalid(fd, arg, _IOC_SIZE(cmd));
		break;

	case HFI1_IOCTL_RECV_CTRL:
		if (get_user(uval, (int __user *)arg))
			return -EFAULT;
		ret = manage_rcvq(uctxt, fd->subctxt, uval);
		break;

	case HFI1_IOCTL_POLL_TYPE:
		if (get_user(uval, (int __user *)arg))
			return -EFAULT;
		uctxt->poll_type = (typeof(uctxt->poll_type))uval;
		break;

	case HFI1_IOCTL_ACK_EVENT:
		unsigned long events;

		if (get_user(events, (unsigned long __user *)arg))
			return -EFAULT;
		ret = user_event_ack(uctxt, fd->subctxt, events);
		break;

	case HFI1_IOCTL_SET_PKEY:
		u16 pkey;

		if (get_user(pkey, (u16 __user *)arg))
			return -EFAULT;
		ret = set_ctxt_pkey(uctxt, pkey);
		break;

	case HFI1_IOCTL_CTXT_RESET:
		ret = ctxt_reset(uctxt);
		break;

	case HFI1_IOCTL_GET_VERS:
		uval = HFI1_USER_SWVERSION;
		if (put_user(uval, (int __user *)arg))
			return -EFAULT;
		break;
	case HFI1_IOCTL_PIN_STATS:
		ret = get_pinning_stats(fd, arg, _IOC_SIZE(cmd));
		break;
	case HFI1_IOCTL_BULKSVC_GET_CMPLQ:
		pr_debug("getting bulksvc cmplq\n");
		ret = create_bulksvc_cmplq(fd, arg, _IOC_SIZE(cmd));
		break;
	case HFI1_IOCTL_BULKSVC_GET_CMDQ:
		pr_debug("getting bulksvc cmdq\n");
		ret = create_bulksvc_cmdq(fd, arg, _IOC_SIZE(cmd));
		break;
	case HFI1_IOCTL_BULKSVC_CLIENT_INIT:
		pr_debug("initializing bulksvc client\n");
		ret = ioctl_init_bulksvc_client(fd, arg, _IOC_SIZE(cmd));
		break;
	case HFI1_IOCTL_BULKSVC_DOORBELL:
		ret = ioctl_bulksvc_doorbell(fd, arg, _IOC_SIZE(cmd));
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

ssize_t hfi1_do_write_iter(struct hfi1_filedata *fd, struct iov_iter *from)
{
	struct hfi1_user_sdma_pkt_q *pq;
	struct hfi1_user_sdma_comp_q *cq = fd->cq;
	int done = 0, reqs = 0;
	unsigned long dim = from->nr_segs;
	int idx;

	if (!HFI1_CAP_IS_KSET(SDMA))
		return -EINVAL;
	if (!from->user_backed)
		return -EINVAL;
	idx = srcu_read_lock(&fd->pq_srcu);
	pq = srcu_dereference(fd->pq, &fd->pq_srcu);
	if (!cq || !pq) {
		srcu_read_unlock(&fd->pq_srcu, idx);
		return -EIO;
	}

	trace_hfi1_sdma_request(fd->dd, fd->uctxt->ctxt, fd->subctxt, dim);

	if (atomic_read(&pq->n_reqs) == pq->n_max_reqs) {
		srcu_read_unlock(&fd->pq_srcu, idx);
		return -ENOSPC;
	}

	while (dim) {
		const struct iovec *iov = iter_iov(from);
		int ret;
		unsigned long count = 0;

		ret = hfi1_user_sdma_process_request(
			fd, (struct iovec *)(iov + done),
			dim, &count);
		if (ret) {
			reqs = ret;
			break;
		}
		dim -= count;
		done += count;
		reqs++;
	}

	srcu_read_unlock(&fd->pq_srcu, idx);
	return reqs;
}

static ssize_t hfi1_write_iter(struct kiocb *kiocb, struct iov_iter *from)
{
	struct hfi1_filedata *fd = kiocb->ki_filp->private_data;

	return hfi1_do_write_iter(fd, from);
}

static inline void mmap_cdbg(u16 ctxt, u16 subctxt, u8 type, u8 mapio, u8 vmf,
			     u64 memaddr, void *memvirt, dma_addr_t memdma,
			     ssize_t memlen, struct vm_area_struct *vma)
{
	hfi1_cdbg(PROC,
		  "%u:%u type:%u io/vf/dma:%d/%d/%d, addr:0x%llx, len:%lu(%lu), flags:0x%lx",
		  ctxt, subctxt, type, mapio, vmf, !!memdma,
		  memaddr ?: (u64)memvirt, memlen,
		  vma->vm_end - vma->vm_start, vma->vm_flags);
}

static int hfi1_file_mmap(struct file *fp, struct vm_area_struct *vma)
{
	struct hfi1_filedata *fd = fp->private_data;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	u64 token = vma->vm_pgoff << PAGE_SHIFT;
	u16 ctxt;
	u16 subctxt;
	u8 type;

	if (!is_valid_mmap(token))
		return -EINVAL;

	ctxt = HFI1_MMAP_TOKEN_GET(CTXT, token);
	subctxt = HFI1_MMAP_TOKEN_GET(SUBCTXT, token);
	type = HFI1_MMAP_TOKEN_GET(TYPE, token);

	if (type >= BULKSVC_QUEUE_TYPES_FIRST && type <= BULKSVC_QUEUE_TYPES_LAST) {
		if (!fd->bulksvc_user_info || subctxt != 0) {
			return -EINVAL;
		}
		return do_bulksvc_mmap(fd->bulksvc_user_info, type, vma);
	}

	if (!uctxt) {
		hfi1_cdbg(PROC, "mmap with no context assigned");
		return -EINVAL;
	}

	if (ctxt != uctxt->ctxt || subctxt != fd->subctxt)
		return -EINVAL;

	return hfi1_do_mmap(fd, type, vma);
}

int hfi1_do_mmap(struct hfi1_filedata *fd, u8 type, struct vm_area_struct *vma)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd;
	unsigned long flags;
	u64 memaddr = 0;
	void *memvirt = NULL;
	dma_addr_t memdma = 0;
	u8 mapio = 0, vmf = 0;
	ssize_t memlen = 0;
	int ret = 0;
	u32 cbi;
	u32 cbc;
	u16 ctxt;
	u16 subctxt;

	if (!uctxt || !(vma->vm_flags & VM_SHARED)) {
		ret = -EINVAL;
		goto done;
	}
	dd = uctxt->dd;
	ctxt = uctxt->ctxt;
	subctxt = fd->subctxt;

	/*
	 * vm_pgoff is used as a buffer selector cookie.  Always mmap from
	 * the beginning.
	 */ 
	vma->vm_pgoff = 0;
	flags = vma->vm_flags;

	switch (type) {
	case PIO_BUFS:
	case PIO_BUFS_SOP:
		cbi = ctxt_bar_idx(uctxt->sc->hw_context);
		cbc = ctxt_bar_ctxt(uctxt->sc->hw_context);
		memaddr = ((dd->bar_maps[cbi].physaddr + TXE_PIO_SEND) +
				/* chip pio base */
			   (cbc * BIT(16))) +
				/* 64K PIO space / ctxt */
			(type == PIO_BUFS_SOP ?
				(TXE_PIO_SIZE / 2) : 0); /* sop? */
		/*
		 * Map only the amount allocated to the context, not the
		 * entire available context's PIO space.
		 */
		memlen = PAGE_ALIGN(uctxt->sc->credits * PIO_BLOCK_SIZE);
		flags &= ~VM_MAYREAD;
		flags |= VM_DONTCOPY | VM_DONTEXPAND;
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
		mapio = 1;
		break;
	case PIO_CRED: {
		u64 cr_page_offset;
		if (flags & VM_WRITE) {
			ret = -EPERM;
			goto done;
		}
		/*
		 * The credit return location for this context could be on the
		 * second or third page allocated for credit returns (if number
		 * of enabled contexts > 64 and 128 respectively).
		 */
		cr_page_offset = ((u64)uctxt->sc->hw_free -
			  	     (u64)dd->cr_base[uctxt->numa_id].va) &
				   PAGE_MASK;
		memvirt = (void *)dd->cr_base[uctxt->numa_id].va + cr_page_offset;
		memdma = dd->cr_base[uctxt->numa_id].dma + cr_page_offset;
		memlen = PAGE_SIZE;
		flags &= ~VM_MAYWRITE;
		flags |= VM_DONTCOPY | VM_DONTEXPAND;
		/*
		 * The driver has already allocated memory for credit
		 * returns and programmed it into the chip. Has that
		 * memory been flagged as non-cached?
		 */
		/* vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot); */
		break;
	}
	case RCV_RHEQ:
		memlen = rheq_size(uctxt);
		memvirt = uctxt->rheq;
		memdma = uctxt->rheq_dma;
		if (!memvirt) {
			ret = -EINVAL;
			goto done;
		}
		if (vma->vm_flags & VM_WRITE) {
			ret = -EPERM;
			goto done;
		}
		break;
	case RCV_HDRQ:
		memlen = rcvhdrq_size(uctxt);
		memvirt = uctxt->rcvhdrq;
		memdma = uctxt->rcvhdrq_dma;
		break;
	case RCV_EGRBUF: {
		unsigned long vm_start_save;
		unsigned long vm_end_save;
		int i;
		/*
		 * The RcvEgr buffer need to be handled differently
		 * as multiple non-contiguous pages need to be mapped
		 * into the user process.
		 */
		memlen = uctxt->egrbufs.size;
		if ((vma->vm_end - vma->vm_start) != memlen) {
			dd_dev_err(dd, "Eager buffer map size invalid (%lu != %lu)\n",
				   (vma->vm_end - vma->vm_start), memlen);
			ret = -EINVAL;
			goto done;
		}
		if (vma->vm_flags & VM_WRITE) {
			ret = -EPERM;
			goto done;
		}
		vm_flags_clear(vma, VM_MAYWRITE);
		/*
		 * Mmap multiple separate allocations into a single vma.  From
		 * here, dma_mmap_coherent() calls dma_direct_mmap(), which
		 * requires the mmap to exactly fill the vma starting at
		 * vma_start.  Adjust the vma start and end for each eager
		 * buffer segment mapped.  Restore the originals when done.
		 */
		vm_start_save = vma->vm_start;
		vm_end_save = vma->vm_end;
		vma->vm_end = vma->vm_start;
		for (i = 0 ; i < uctxt->egrbufs.numbufs; i++) {
			memlen = uctxt->egrbufs.buffers[i].len;
			memvirt = uctxt->egrbufs.buffers[i].addr;
			memdma = uctxt->egrbufs.buffers[i].dma;
			vma->vm_end += memlen;
			mmap_cdbg(ctxt, subctxt, type, mapio, vmf, memaddr,
				  memvirt, memdma, memlen, vma);
			ret = dma_mmap_coherent(&dd->pcidev->dev, vma,
						memvirt, memdma, memlen);
			if (ret < 0) {
				vma->vm_start = vm_start_save;
				vma->vm_end = vm_end_save;
				goto done;
			}
			vma->vm_start += memlen;
		}
		vma->vm_start = vm_start_save;
		vma->vm_end = vm_end_save;
		ret = 0;
		goto done;
	}
	case UREGS:
		/*
		 * Map the part of BAR0 that contains this context's user
		 * registers.  RcvHdrTail is the first register in the hardware
		 * UCTXT block.  The TidFlow table is contained within this
		 * memory range.
		 */
		cbi = ctxt_bar_idx(uctxt->ctxt);
		cbc = ctxt_bar_ctxt(uctxt->ctxt);
		memaddr = (unsigned long)dd->bar_maps[cbi].physaddr +
				dd->params->rcv_hdr_tail_reg +
				(cbc * dd->params->rxe_uctxt_stride);
		memlen = dd->params->rxe_uctxt_stride;
		// hack: accept a 4K mmap for uregs
		{
		ssize_t sz = vma->vm_end - vma->vm_start;
		if (sz != memlen && sz == PAGE_SIZE) {
			printk("%s: UREGS override memlen to 4K\n", __func__);
			memlen = PAGE_SIZE;
		}
		}
		flags |= VM_DONTCOPY | VM_DONTEXPAND;
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		mapio = 1;
		break;
	case EVENTS:
		/*
		 * Use the page where this context's flags are. User level
		 * knows where it's own bitmap is within the page.
		 */
		memaddr = (unsigned long)
			(dd->events + uctxt_offset(uctxt)) & PAGE_MASK;
		memlen = PAGE_SIZE;
		/*
		 * v3.7 removes VM_RESERVED but the effect is kept by
		 * using VM_IO.
		 */
		flags |= VM_IO | VM_DONTEXPAND;
		vmf = 1;
		break;
	case STATUS:
		if (flags & VM_WRITE) {
			ret = -EPERM;
			goto done;
		}
		memaddr = kvirt_to_phys((void *)dd->status);
		memlen = PAGE_SIZE;
		flags |= VM_IO | VM_DONTEXPAND;
		break;
	case RTAIL:
		if (!HFI1_CAP_IS_USET(DMA_RTAIL)) {
			/*
			 * If the memory allocation failed, the context alloc
			 * also would have failed, so we would never get here
			 */
			ret = -EINVAL;
			goto done;
		}
		if ((flags & VM_WRITE) || !hfi1_rcvhdrtail_kvaddr(uctxt)) {
			ret = -EPERM;
			goto done;
		}
		memlen = PAGE_SIZE;
		memvirt = (void *)hfi1_rcvhdrtail_kvaddr(uctxt);
		memdma = uctxt->rcvhdrqtailaddr_dma;
		flags &= ~VM_MAYWRITE;
		break;
	case SUBCTXT_UREGS:
		memaddr = (u64)uctxt->subctxt_uregbase;
		memlen = PAGE_SIZE;
		flags |= VM_IO | VM_DONTEXPAND;
		vmf = 1;
		break;
	case SUBCTXT_RCV_HDRQ:
		memaddr = (u64)uctxt->subctxt_rcvhdr_base;
		memlen = rcvhdrq_size(uctxt) * uctxt->subctxt_cnt;
		flags |= VM_IO | VM_DONTEXPAND;
		vmf = 1;
		break;
	case SUBCTXT_EGRBUF:
		memaddr = (u64)uctxt->subctxt_rcvegrbuf;
		memlen = uctxt->egrbufs.size * uctxt->subctxt_cnt;
		flags |= VM_IO | VM_DONTEXPAND;
		flags &= ~VM_MAYWRITE;
		vmf = 1;
		break;
	case SDMA_COMP: {
		struct hfi1_user_sdma_comp_q *cq = fd->cq;

		if (!cq) {
			ret = -EFAULT;
			goto done;
		}
		memaddr = (u64)cq->comps;
		memlen = PAGE_ALIGN(sizeof(*cq->comps) * cq->nentries);
		flags |= VM_IO | VM_DONTEXPAND;
		vmf = 1;
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}

	if ((vma->vm_end - vma->vm_start) != memlen) {
		hfi1_cdbg(PROC, "%u:%u Memory size mismatch %lu:%lu",
			  uctxt->ctxt, fd->subctxt,
			  (vma->vm_end - vma->vm_start), memlen);
		ret = -EINVAL;
		goto done;
	}

	vm_flags_reset(vma, flags);
	mmap_cdbg(ctxt, subctxt, type, mapio, vmf, memaddr, memvirt, memdma, 
		  memlen, vma);
	if (vmf) {
		vma->vm_pgoff = PFN_DOWN(memaddr);
		vma->vm_ops = &vm_ops;
		ret = 0;
	} else if (memdma) {
		ret = dma_mmap_coherent(&dd->pcidev->dev, vma,
					memvirt, memdma, memlen);
	} else if (mapio) {
		ret = io_remap_pfn_range(vma, vma->vm_start,
					 PFN_DOWN(memaddr),
					 memlen,
					 vma->vm_page_prot);
	} else if (memvirt) {
		ret = remap_pfn_range(vma, vma->vm_start,
				      PFN_DOWN(__pa(memvirt)),
				      memlen,
				      vma->vm_page_prot);
	} else {
		ret = remap_pfn_range(vma, vma->vm_start,
				      PFN_DOWN(memaddr),
				      memlen,
				      vma->vm_page_prot);
	}
done:
	return ret;
}

int do_bulksvc_doorbell_mmap(struct hfi1_filedata *fd, struct vm_area_struct *vma)
{
	struct hfi1_devdata *dd;
	unsigned long flags;
	u64 memaddr = 0;
	int ret = 0;

	if (!fd || !vma)
		return -EINVAL;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	dd = fd->dd;
	if (!dd)
		return -EINVAL;
	if ((vma->vm_end - vma->vm_start) != PAGE_SIZE)
		return -EINVAL;

	flags = vma->vm_flags;
	flags |= VM_IO | VM_DONTEXPAND;
	memaddr = (u64)dd->bar_maps[0].physaddr + (u64) dd->params->cce_int_force_reg;
	vm_flags_reset(vma, flags);
	ret = io_remap_pfn_range(vma, vma->vm_start, PFN_DOWN(memaddr), PAGE_SIZE, vma->vm_page_prot);

	return ret;
}

int do_bulksvc_mmap(struct hfi1_bulksvc_user_info* info, int type, struct vm_area_struct *vma)
{
	unsigned long flags;
	u64 memaddr = 0;
	void *memvirt = NULL;
	dma_addr_t memdma = 0;
	u8 mapio = 0, vmf = 0;
	ssize_t memlen = 0;
	int ret = 0;

	if (WARN_ON(!info)) {
		ret = -EINVAL;
		goto done;
	}

	if (!(vma->vm_flags & VM_SHARED)) {
		ret = -EINVAL;
		goto done;
	}

	vma->vm_pgoff = 0;
	flags = vma->vm_flags;

	mutex_lock(&info->queue_records_lock);
	bool is_cmplq;
	bool is_ctrl;
	int qid;
	{
		if (type >= BULKSVC_CMPLQ_CTRL0 && type < BULKSVC_CMPLQ_CTRL0 + BULKSVC_USER_MAX_NUM_CMPLQS) {
			is_cmplq = true;
			is_ctrl = true;
			qid = type - BULKSVC_CMPLQ_CTRL0;
		} else if (type >= BULKSVC_CMPLQ_BUF0 && type < BULKSVC_CMPLQ_BUF0 + BULKSVC_USER_MAX_NUM_CMPLQS) {
			is_cmplq = true;
			is_ctrl = false;
			qid = type - BULKSVC_CMPLQ_BUF0;
		} else if (type >= BULKSVC_CMDQ_CTRL0 && type < BULKSVC_CMDQ_CTRL0 + BULKSVC_USER_MAX_NUM_CMDQS) {
			is_cmplq = false;
			is_ctrl = true;
			qid = type - BULKSVC_CMDQ_CTRL0;
		} else if (type >= BULKSVC_CMDQ_BUF0 && type < BULKSVC_CMDQ_BUF0 + BULKSVC_USER_MAX_NUM_CMDQS) {
			is_cmplq = false;
			is_ctrl = false;
			qid = type - BULKSVC_CMDQ_BUF0;
		} else {
			mutex_unlock(&info->queue_records_lock);
			ret = -EINVAL;
			goto done;
		}
	}
		
	u8 const current_present = is_cmplq ?
		info->num_cmplqs :
		info->num_cmdqs;
	
	u8 const idx = qid;
	if (idx >= current_present) {
		mutex_unlock(&info->queue_records_lock);
		ret = -EFAULT;
		goto done;
	}
	struct hfi1_bulksvc_queue_record* record = NULL;
	if (is_cmplq) {
		record = &info->cmplq_records[idx];
	} else {
		record = &info->cmdq_records[idx];
	}
	if (!record || !record->active) {
		pr_err("record %p, active %d\n",
			record, record ? record->active : 0);
		mutex_unlock(&info->queue_records_lock);
		ret = -EFAULT;
		goto done;
	}
	if (is_ctrl) {
		memaddr = (u64) record->ctrl;
		memlen = record->queue_info.queue_ctrl_mmap_size;
		flags |= VM_DONTEXPAND;
		vmf = 1;
	} else {
		memaddr = (u64) record->queue_buf;
		memlen = record->queue_info.queue_buffer_mmap_size;
		flags |= VM_DONTEXPAND;
		vmf = 1;
		// TODO if cmplq buf, mark RO
	}
	mutex_unlock(&info->queue_records_lock);

	if ((vma->vm_end - vma->vm_start) != memlen) {
		hfi1_cdbg(PROC, "Memory size mismatch for bulksvc queue %lu:%lu",
			  (vma->vm_end - vma->vm_start), memlen);
		ret = -EINVAL;
		goto done;
	}

	vm_flags_reset(vma, flags);
	if (!vmf || memdma || mapio || memvirt) {
		ret = -EINVAL;
		goto done;
	}
	vma->vm_pgoff = PFN_DOWN(memaddr);
	vma->vm_ops = &vm_ops;
	ret = 0;
	
done:
	return ret;
}

/*
 * Local (non-chip) user memory is not mapped right away but as it is
 * accessed by the user-level code.
 */
static vm_fault_t vma_fault(struct vm_fault *vmf)
{
	struct page *page;

	page = vmalloc_to_page((void *)(vmf->pgoff << PAGE_SHIFT));
	if (!page)
		return VM_FAULT_SIGBUS;

	get_page(page);
	vmf->page = page;

	return 0;
}

static __poll_t hfi1_poll(struct file *fp, struct poll_table_struct *pt)
{
	struct hfi1_ctxtdata *uctxt;
	__poll_t pollflag;

	uctxt = ((struct hfi1_filedata *)fp->private_data)->uctxt;
	if (!uctxt)
		pollflag = EPOLLERR;
	else if (uctxt->poll_type == HFI1_POLL_TYPE_URGENT)
		pollflag = poll_urgent(fp, pt);
	else  if (uctxt->poll_type == HFI1_POLL_TYPE_ANYRCV)
		pollflag = poll_next(fp, pt);
	else /* invalid */
		pollflag = EPOLLERR;

	return pollflag;
}

void hfi1_dealloc_filedata(struct hfi1_filedata *fdata)
{
	struct hfi1_ctxtdata *uctxt = fdata->uctxt;
	struct hfi1_devdata *dd = fdata->dd;
	unsigned long flags, *ev;

	if (!uctxt)
		goto done;

	hfi1_cdbg(PROC, "closing ctxt %u:%u", uctxt->ctxt, fdata->subctxt);

	flush_wc();
	/* drain user sdma queue */
	hfi1_user_sdma_free_queues(fdata, uctxt);

	/* release the cpu */
	hfi1_put_proc_affinity(fdata->rec_cpu_num);

	/* clean up rcv side */
	hfi1_user_exp_rcv_free(fdata);

	/*
	 * fdata->uctxt is used in the above cleanup.  It is not ready to be
	 * removed until here.
	 */
	fdata->uctxt = NULL;
	hfi1_rcd_put(uctxt);

	/*
	 * Clear any left over, unhandled events so the next process that
	 * gets this context doesn't get confused.
	 */
	ev = dd->events + uctxt_offset(uctxt) + fdata->subctxt;
	*ev = 0;

	spin_lock_irqsave(&dd->uctxt_lock, flags);
	__clear_bit(fdata->subctxt, uctxt->in_use_ctxts);
	if (!bitmap_empty(uctxt->in_use_ctxts, HFI1_MAX_SHARED_CTXTS)) {
		spin_unlock_irqrestore(&dd->uctxt_lock, flags);
		goto done;
	}
	spin_unlock_irqrestore(&dd->uctxt_lock, flags);

	/*
	 * Disable receive context and interrupt available, reset all
	 * RcvCtxtCtrl bits to default values.
	 */
	hfi1_rcvctrl(dd, HFI1_RCVCTRL_CTXT_DIS |
		     HFI1_RCVCTRL_TIDFLOW_DIS |
		     HFI1_RCVCTRL_INTRAVAIL_DIS |
		     HFI1_RCVCTRL_TAILUPD_DIS |
		     HFI1_RCVCTRL_ONE_PKT_EGR_DIS |
		     HFI1_RCVCTRL_NO_RHQ_DROP_DIS |
		     HFI1_RCVCTRL_NO_EGR_DROP_DIS |
		     HFI1_RCVCTRL_URGENT_DIS, uctxt);
	/* Clear the context's J_KEY */
	hfi1_clear_ctxt_jkey(dd, uctxt);
	/*
	 * If a send context is allocated, reset context integrity
	 * checks to default and disable the send context.
	 */
	if (uctxt->sc) {
		sc_disable(uctxt->sc);
		priv_reg_op(dd, uctxt->sc->ppd->hw_pidx, uctxt->sc->hw_context,
			    uctxt->sc->type, SC_CHK_ADJ_OP, 0);
	}

	hfi1_free_ctxt_rcv_groups(uctxt);
	hfi1_clear_ctxt_pkey(dd, uctxt);

	uctxt->event_flags = 0;

	deallocate_ctxt(uctxt);
done:
	if (fdata->bulksvc_user_info) {
		hfi1_bulksvc_user_info_put(fdata->bulksvc_user_info);
		fdata->bulksvc_user_info = NULL;
	}

	cleanup_srcu_struct(&fdata->pq_srcu);
	kfree(fdata);
}

static int hfi1_file_close(struct inode *inode, struct file *fp)
{
	struct hfi1_filedata *fdata = fp->private_data;
	struct hfi1_devdata *dd = container_of(inode->i_cdev,
					       struct hfi1_devdata,
					       user_cdev);

	fp->private_data = NULL;
	hfi1_dealloc_filedata(fdata);
	if (refcount_dec_and_test(&dd->user_refcount))
		complete(&dd->user_comp);

	return 0;
}

/*
 * Convert kernel *virtual* addresses to physical addresses.
 * This is used to vmalloc'ed addresses.
 */
static u64 kvirt_to_phys(void *addr)
{
	struct page *page;
	u64 paddr = 0;

	page = vmalloc_to_page(addr);
	if (page)
		paddr = page_to_pfn(page) << PAGE_SHIFT;

	return paddr;
}

/**
 * complete_subctxt - complete sub-context info
 * @fd: valid filedata pointer
 *
 * Sub-context info can only be set up after the base context
 * has been completed.  This is indicated by the clearing of the
 * HFI1_CTXT_BASE_UINIT bit.
 *
 * Wait for the bit to be cleared, and then complete the subcontext
 * initialization.
 *
 */
static int complete_subctxt(struct hfi1_filedata *fd)
{
	int ret;
	unsigned long flags;

	/*
	 * sub-context info can only be set up after the base context
	 * has been completed.
	 */
	ret = wait_event_interruptible(
		fd->uctxt->wait,
		!test_bit(HFI1_CTXT_BASE_UNINIT, &fd->uctxt->event_flags));

	if (test_bit(HFI1_CTXT_BASE_FAILED, &fd->uctxt->event_flags))
		ret = -ENOMEM;

	/* Finish the sub-context init */
	if (!ret) {
		fd->rec_cpu_num = hfi1_get_proc_affinity(fd->uctxt->numa_id);
		ret = init_user_ctxt(fd, fd->uctxt);
	}

	if (ret) {
		int last;

		spin_lock_irqsave(&fd->dd->uctxt_lock, flags);
		__clear_bit(fd->subctxt, fd->uctxt->in_use_ctxts);
		last = bitmap_empty(fd->uctxt->in_use_ctxts, HFI1_MAX_SHARED_CTXTS);
		spin_unlock_irqrestore(&fd->dd->uctxt_lock, flags);
		hfi1_rcd_put(fd->uctxt);

		/*
		 * When last is true this was the last reference to fd->uctxt.
		 * No new references to uctxt will be taken. So this task
		 * must free uctxt.
		 */
		if (last)
			deallocate_ctxt(fd->uctxt);
		fd->uctxt = NULL;
	}

	return ret;
}

static int assign_ctxt(struct hfi1_filedata *fd, unsigned long arg, u32 len)
{
	unsigned int swmajor;
	struct hfi1_assign_ctxt_cmd cmd = {};
	struct hfi1_user_info uinfo;
	u32 unused;
	u8 pidx;
	u8 kdeth_rcv_hdr;
	bool fail;

	if (sizeof(uinfo) != len)
		return -EINVAL;

	if (copy_from_user(&uinfo, (void __user *)arg, sizeof(uinfo)))
		return -EFAULT;

	swmajor = uinfo.userversion >> 16;
	if (swmajor != HFI1_USER_SWMAJOR)
		return -ENODEV;

	/*
	 * XXX temporary until a real implementation is done that can
	 * safely change the ABI.
	 *
	 * Extract information from pad:
	 *  bits   size   what
	 *  0: 0     1    port index
	 *  5: 1     5    KDETH RcvHdr size
	 * 31: 6    26    unused, expect to be zero
	 */
	pidx = uinfo.pad & 0x1;
	kdeth_rcv_hdr = (uinfo.pad >> 1) & 0x1f; /* 5 bits: 0-31 */
	unused = uinfo.pad >> 6;
	fail = false;
	if (pidx >= fd->dd->num_pports)
		fail = true;
	if (kdeth_rcv_hdr == 1) /* must be >= 2, unused means "default" */
		fail = true;
	if (unused != 0)
		fail = true;
	if (fail) {
		dd_dev_err(fd->dd, "Invalid user pad\n");
		return -EINVAL;
	}

	/* convert to new ioctl struct */
	cmd.userversion = uinfo.userversion;
	cmd.port = pidx + 1;
	cmd.kdeth_rcvhdrsz = kdeth_rcv_hdr;
	cmd.subctxt_cnt = uinfo.subctxt_cnt;
	cmd.subctxt_id = uinfo.subctxt_id;
	memcpy(cmd.uuid, uinfo.uuid, sizeof(cmd.uuid));

	return hfi1_do_assign_ctxt(fd, &cmd);
}

int hfi1_do_assign_ctxt(struct hfi1_filedata *fd,
			const struct hfi1_assign_ctxt_cmd *uinfo)
{
	struct hfi1_ctxtdata *uctxt = NULL;
	int ret;
	u8 pidx = uinfo->port - 1;
	u8 kdeth_rcv_hdr = uinfo->kdeth_rcvhdrsz;

	if (fd->uctxt)
		return -EINVAL;

	if (uinfo->subctxt_cnt > HFI1_MAX_SHARED_CTXTS)
		return -EINVAL;

	/* check, then assign port ASAP */
	if (pidx >= fd->dd->num_pports)
		return -EINVAL;
	fd->ppd = fd->dd->pport + pidx;

	/* verify kdeth receive header size */
	if (kdeth_rcv_hdr == 0) /* change to default size */
		kdeth_rcv_hdr = DEFAULT_RCVHDRSIZE;
	if (kdeth_rcv_hdr < 2 || kdeth_rcv_hdr > 31) /* valid HW range */
		return -EINVAL;

	/*
	 * Acquire the mutex to protect against multiple creations of what
	 * could be a shared base context.
	 */
	mutex_lock(&hfi1_mutex);
	/*
	 * Get a sub context if available  (fd->uctxt will be set).
	 * ret < 0 error, 0 no context, 1 sub-context found
	 */
	ret = find_sub_ctxt(fd, uinfo);

	/*
	 * Allocate a base context if context sharing is not required or a
	 * sub context wasn't found.
	 */
	if (!ret) {
		ret = allocate_ctxt(fd, uinfo, &uctxt);
		if (ret == 0) {
			/* override - must be done before setup_base_ctxt() */
			uctxt->kdeth_rcv_hdr = kdeth_rcv_hdr;
		}
	}

	mutex_unlock(&hfi1_mutex);

	/* Depending on the context type, finish the appropriate init */
	switch (ret) {
	case 0:
		ret = setup_base_ctxt(fd, uctxt);
		if (ret)
			deallocate_ctxt(uctxt);
		break;
	case 1:
		ret = complete_subctxt(fd);
		break;
	default:
		break;
	}

	return ret;
}

/**
 * match_ctxt - match context
 * @fd: valid filedata pointer
 * @uinfo: user info to compare base context with
 * @uctxt: context to compare uinfo to.
 *
 * Compare the given context with the given information to see if it
 * can be used for a sub context.
 */
static int match_ctxt(struct hfi1_filedata *fd,
		      const struct hfi1_assign_ctxt_cmd *uinfo,
		      struct hfi1_ctxtdata *uctxt)
{
	struct hfi1_devdata *dd = fd->dd;
	unsigned long flags;
	u16 subctxt;

	/* Skip dynamically allocated kernel contexts */
	if (uctxt->sc && (uctxt->sc->type == SC_KERNEL))
		return 0;

	/* Skip ctxt if it doesn't match the requested one */
	if (memcmp(uctxt->uuid, uinfo->uuid, sizeof(uctxt->uuid)) ||
	    uctxt->jkey != generate_jkey(current_uid()) ||
	    uctxt->subctxt_id != uinfo->subctxt_id ||
	    uctxt->subctxt_cnt != uinfo->subctxt_cnt)
		return 0;

	/* Verify the sharing process matches the base */
	if (uctxt->userversion != uinfo->userversion)
		return -EINVAL;

	/* Find an unused sub context */
	spin_lock_irqsave(&dd->uctxt_lock, flags);
	if (bitmap_empty(uctxt->in_use_ctxts, HFI1_MAX_SHARED_CTXTS)) {
		/* context is being closed, do not use */
		spin_unlock_irqrestore(&dd->uctxt_lock, flags);
		return 0;
	}

	subctxt = find_first_zero_bit(uctxt->in_use_ctxts,
				      HFI1_MAX_SHARED_CTXTS);
	if (subctxt >= uctxt->subctxt_cnt) {
		spin_unlock_irqrestore(&dd->uctxt_lock, flags);
		return -EBUSY;
	}

	fd->subctxt = subctxt;
	__set_bit(fd->subctxt, uctxt->in_use_ctxts);
	spin_unlock_irqrestore(&dd->uctxt_lock, flags);

	fd->uctxt = uctxt;
	hfi1_rcd_get(uctxt);

	return 1;
}

/**
 * find_sub_ctxt - fund sub-context
 * @fd: valid filedata pointer
 * @uinfo: matching info to use to find a possible context to share.
 *
 * The hfi1_mutex must be held when this function is called.  It is
 * necessary to ensure serialized creation of shared contexts.
 *
 * Return:
 *    0      No sub-context found
 *    1      Subcontext found and allocated
 *    errno  EINVAL (incorrect parameters)
 *           EBUSY (all sub contexts in use)
 */
static int find_sub_ctxt(struct hfi1_filedata *fd,
			 const struct hfi1_assign_ctxt_cmd *uinfo)
{
	struct hfi1_ctxtdata *uctxt;
	struct hfi1_devdata *dd = fd->dd;
	struct hfi1_pportdata *ppd = fd->ppd;
	struct hfi1_portrsrcs *pr = &dd->rsrcs.ppr[ppd->hw_pidx];
	u16 i;
	int ret;

	if (!uinfo->subctxt_cnt)
		return 0;

	for (i = pr->first_dyn_alloc_ctxt;
	     i < pr->rcv_context_base + pr->num_rcv_contexts;
	     i++) {
		uctxt = hfi1_rcd_get_by_index(dd, i);
		if (uctxt) {
			ret = match_ctxt(fd, uinfo, uctxt);
			hfi1_rcd_put(uctxt);
			/* value of != 0 will return */
			if (ret)
				return ret;
		}
	}

	return 0;
}

/* return true if there are any user allocated contexts across all ports */
static bool any_user_allocated_contexts(struct hfi1_devdata *dd)
{
	struct hfi1_devrsrcs *dr = &dd->rsrcs;
	int i;

	for (i = 0; i < dd->num_pports; i++) {
		if (dd->pport[i].freectxts != dr->ppr[i].num_user_contexts)
			return true;
	}
	return false;
}

static int allocate_ctxt(struct hfi1_filedata *fd,
			 const struct hfi1_assign_ctxt_cmd *uinfo,
			 struct hfi1_ctxtdata **rcd)
{
	struct hfi1_devdata *dd = fd->dd;
	struct hfi1_pportdata *ppd = fd->ppd;
	struct hfi1_ctxtdata *uctxt;
	int ret, numa;

	if (dd->flags & HFI1_FROZEN) {
		/*
		 * Pick an error that is unique from all other errors
		 * that are returned so the user process knows that
		 * it tried to allocate while the SPC was frozen.  It
		 * it should be able to retry with success in a short
		 * while.
		 */
		return -EIO;
	}

	if (!ppd->freectxts)
		return -EBUSY;

	/*
	 * If we don't have a NUMA node requested, preference is towards
	 * device NUMA node.
	 */
	fd->rec_cpu_num = hfi1_get_proc_affinity(dd->node);
	if (fd->rec_cpu_num != -1)
		numa = cpu_to_node(fd->rec_cpu_num);
	else
		numa = numa_node_id();
	ret = hfi1_create_ctxtdata(ppd, numa, DYNAMIC_CONTEXT, &uctxt);
	if (ret < 0) {
		dd_dev_err(dd, "user ctxtdata allocation failed\n");
		return ret;
	}
	hfi1_cdbg(PROC, "[%u:%u] pid %u assigned to CPU %d (NUMA %u)",
		  uctxt->ctxt, fd->subctxt, current->pid, fd->rec_cpu_num,
		  uctxt->numa_id);

	/*
	 * Allocate and enable a PIO send context.
	 */
	uctxt->sc = sc_alloc(ppd, SC_USER, uctxt->rcvhdrqentsize, numa);
	if (!uctxt->sc) {
		ret = -ENOMEM;
		goto ctxdata_free;
	}
	hfi1_cdbg(PROC, "allocated send context %u(%u)", uctxt->sc->sw_index,
		  uctxt->sc->hw_context);
	ret = sc_enable(uctxt->sc);
	if (ret)
		goto ctxdata_free;

	/*
	 * Setup sub context information if the user-level has requested
	 * sub contexts.
	 * This has to be done here so the rest of the sub-contexts find the
	 * proper base context.
	 * NOTE: _set_bit() can be used here because the context creation is
	 * protected by the mutex (rather than the spin_lock), and will be the
	 * very first instance of this context.
	 */
	__set_bit(0, uctxt->in_use_ctxts);
	if (uinfo->subctxt_cnt)
		init_subctxts(uctxt, uinfo);
	uctxt->userversion = uinfo->userversion;
	uctxt->flags = hfi1_cap_mask; /* save current flag state */
	init_waitqueue_head(&uctxt->wait);
	strscpy(uctxt->comm, current->comm, sizeof(uctxt->comm));
	memcpy(uctxt->uuid, uinfo->uuid, sizeof(uctxt->uuid));
	uctxt->jkey = generate_jkey(current_uid());
	hfi1_stats.sps_ctxts++;
	/*
	 * Disable ASPM when there are open user/PSM contexts to avoid
	 * issues with ASPM L1 exit latency
	 */
	if (!any_user_allocated_contexts(dd))
		aspm_disable_all(dd);
	ppd->freectxts--;

	*rcd = uctxt;

	return 0;

ctxdata_free:
	hfi1_free_ctxt(uctxt);
	return ret;
}

static void deallocate_ctxt(struct hfi1_ctxtdata *uctxt)
{
	mutex_lock(&hfi1_mutex);
	hfi1_stats.sps_ctxts--;
	uctxt->ppd->freectxts++;
	/* enable ASPM if there are no user contexts */
	if (!any_user_allocated_contexts(uctxt->dd))
		aspm_enable_all(uctxt->dd);
	mutex_unlock(&hfi1_mutex);

	hfi1_free_ctxt(uctxt);
}

static void init_subctxts(struct hfi1_ctxtdata *uctxt,
			  const struct hfi1_assign_ctxt_cmd *uinfo)
{
	uctxt->subctxt_cnt = uinfo->subctxt_cnt;
	uctxt->subctxt_id = uinfo->subctxt_id;
	set_bit(HFI1_CTXT_BASE_UNINIT, &uctxt->event_flags);
}

static int setup_subctxt(struct hfi1_ctxtdata *uctxt)
{
	int ret = 0;
	u16 num_subctxts = uctxt->subctxt_cnt;

	uctxt->subctxt_uregbase = vmalloc_user(PAGE_SIZE);
	if (!uctxt->subctxt_uregbase)
		return -ENOMEM;

	/* We can take the size of the RcvHdr Queue from the master */
	uctxt->subctxt_rcvhdr_base = vmalloc_user(rcvhdrq_size(uctxt) *
						  num_subctxts);
	if (!uctxt->subctxt_rcvhdr_base) {
		ret = -ENOMEM;
		goto bail_ureg;
	}

	uctxt->subctxt_rcvegrbuf = vmalloc_user(uctxt->egrbufs.size *
						num_subctxts);
	if (!uctxt->subctxt_rcvegrbuf) {
		ret = -ENOMEM;
		goto bail_rhdr;
	}

	return 0;

bail_rhdr:
	vfree(uctxt->subctxt_rcvhdr_base);
	uctxt->subctxt_rcvhdr_base = NULL;
bail_ureg:
	vfree(uctxt->subctxt_uregbase);
	uctxt->subctxt_uregbase = NULL;

	return ret;
}

static void user_init(struct hfi1_ctxtdata *uctxt)
{
	unsigned int rcvctrl_ops = 0;

	/* initialize poll variables... */
	uctxt->urgent = 0;
	uctxt->urgent_poll = 0;

	/*
	 * Now enable the ctxt for receive.
	 * For chips that are set to DMA the tail register to memory
	 * when they change (and when the update bit transitions from
	 * 0 to 1.  So for those chips, we turn it off and then back on.
	 * This will (very briefly) affect any other open ctxts, but the
	 * duration is very short, and therefore isn't an issue.  We
	 * explicitly set the in-memory tail copy to 0 beforehand, so we
	 * don't have to wait to be sure the DMA update has happened
	 * (chip resets head/tail to 0 on transition to enable).
	 */
	if (hfi1_rcvhdrtail_kvaddr(uctxt))
		clear_rcvhdrtail(uctxt);

	/* Setup J_KEY before enabling the context */
	hfi1_set_ctxt_jkey(uctxt->dd, uctxt, uctxt->jkey);

	rcvctrl_ops = HFI1_RCVCTRL_CTXT_ENB;
	rcvctrl_ops |= HFI1_RCVCTRL_URGENT_ENB;
	if (HFI1_CAP_UGET_MASK(uctxt->flags, HDRSUPP))
		rcvctrl_ops |= HFI1_RCVCTRL_TIDFLOW_ENB;
	/*
	 * Ignore the bit in the flags for now until proper
	 * support for multiple packet per rcv array entry is
	 * added.
	 */
	if (!HFI1_CAP_UGET_MASK(uctxt->flags, MULTI_PKT_EGR))
		rcvctrl_ops |= HFI1_RCVCTRL_ONE_PKT_EGR_ENB;
	if (HFI1_CAP_UGET_MASK(uctxt->flags, NODROP_EGR_FULL))
		rcvctrl_ops |= HFI1_RCVCTRL_NO_EGR_DROP_ENB;
	if (HFI1_CAP_UGET_MASK(uctxt->flags, NODROP_RHQ_FULL))
		rcvctrl_ops |= HFI1_RCVCTRL_NO_RHQ_DROP_ENB;
	/*
	 * The RcvCtxtCtrl.TailUpd bit has to be explicitly written.
	 * We can't rely on the correct value to be set from prior
	 * uses of the chip or ctxt. Therefore, add the rcvctrl op
	 * for both cases.
	 */
	if (HFI1_CAP_UGET_MASK(uctxt->flags, DMA_RTAIL))
		rcvctrl_ops |= HFI1_RCVCTRL_TAILUPD_ENB;
	else
		rcvctrl_ops |= HFI1_RCVCTRL_TAILUPD_DIS;
	hfi1_rcvctrl(uctxt->dd, rcvctrl_ops, uctxt);
}

static int get_ctxt_info(struct hfi1_filedata *fd, unsigned long arg, u32 len)
{
	struct hfi1_ctxt_info cinfo;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;

	if (sizeof(cinfo) != len)
		return -EINVAL;

	memset(&cinfo, 0, sizeof(cinfo));
	cinfo.runtime_flags = (((uctxt->flags >> HFI1_CAP_MISC_SHIFT) &
				HFI1_CAP_MISC_MASK) << HFI1_CAP_USER_SHIFT) |
#ifdef NVIDIA_GPU_DIRECT
			HFI1_CAP_GPUDIRECT_OT |
#endif
			HFI1_CAP_UGET_MASK(uctxt->flags, MASK) |
			HFI1_CAP_KGET_MASK(uctxt->flags, K2U);
	/* adjust flag if this fd is not able to cache */
	if (!fd->use_mn)
		cinfo.runtime_flags |= HFI1_CAP_TID_UNMAP; /* no caching */

	cinfo.num_active = hfi1_count_active_units();
	cinfo.unit = uctxt->dd->unit;
	cinfo.ctxt = uctxt->ctxt;
	cinfo.subctxt = fd->subctxt;
	cinfo.rcvtids = roundup(uctxt->egrbufs.alloced,
				uctxt->dd->rcv_entries.group_size) +
		uctxt->expected_count;
	cinfo.credits = uctxt->sc->credits;
	cinfo.numa_node = uctxt->numa_id;
	cinfo.rec_cpu = fd->rec_cpu_num;
	cinfo.send_ctxt = uctxt->sc->hw_context;

	cinfo.egrtids = uctxt->egrbufs.alloced;
	cinfo.rcvhdrq_cnt = get_hdrq_cnt(uctxt);
	cinfo.rcvhdrq_entsize = get_hdrqentsize(uctxt) << 2;
	cinfo.sdma_ring_size = fd->cq->nentries;
	cinfo.rcvegr_size = uctxt->egrbufs.rcvtid_size;

	trace_hfi1_ctxt_info(uctxt->dd, uctxt->ctxt, fd->subctxt, &cinfo);
	if (copy_to_user((void __user *)arg, &cinfo, len))
		return -EFAULT;

	return 0;
}

static int init_user_ctxt(struct hfi1_filedata *fd,
			  struct hfi1_ctxtdata *uctxt)
{
	int ret;

	ret = hfi1_user_sdma_alloc_queues(uctxt, fd);
	if (ret)
		return ret;

	ret = hfi1_user_exp_rcv_init(fd, uctxt);
	if (ret)
		hfi1_user_sdma_free_queues(fd, uctxt);

	return ret;
}

static int setup_base_ctxt(struct hfi1_filedata *fd,
			   struct hfi1_ctxtdata *uctxt)
{
	struct hfi1_devdata *dd = uctxt->dd;
	int ret = 0;

	hfi1_init_ctxt(uctxt->sc);

	/* Now allocate the RcvHdr queue and eager buffers. */
	ret = hfi1_create_rcvhdrq(dd, uctxt);
	if (ret)
		goto done;

	ret = hfi1_setup_eagerbufs(uctxt);
	if (ret)
		goto done;

	/* If sub-contexts are enabled, do the appropriate setup */
	if (uctxt->subctxt_cnt)
		ret = setup_subctxt(uctxt);
	if (ret)
		goto done;

	ret = hfi1_alloc_ctxt_rcv_groups(uctxt);
	if (ret)
		goto done;

	ret = init_user_ctxt(fd, uctxt);
	if (ret) {
		hfi1_free_ctxt_rcv_groups(uctxt);
		goto done;
	}

	user_init(uctxt);

	/* Now that the context is set up, the fd can get a reference. */
	fd->uctxt = uctxt;
	hfi1_rcd_get(uctxt);

done:
	if (uctxt->subctxt_cnt) {
		/*
		 * On error, set the failed bit so sub-contexts will clean up
		 * correctly.
		 */
		if (ret)
			set_bit(HFI1_CTXT_BASE_FAILED, &uctxt->event_flags);

		/*
		 * Base context is done (successfully or not), notify anybody
		 * using a sub-context that is waiting for this completion.
		 */
		clear_bit(HFI1_CTXT_BASE_UNINIT, &uctxt->event_flags);
		wake_up(&uctxt->wait);
	}

	return ret;
}

static int get_base_info(struct hfi1_filedata *fd, unsigned long arg, u32 len)
{
	struct hfi1_base_info binfo;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;
	unsigned offset;

	trace_hfi1_uctxtdata(uctxt->dd, uctxt, fd->subctxt);

	if (sizeof(binfo) != len)
		return -EINVAL;

	memset(&binfo, 0, sizeof(binfo));
	binfo.hw_version = dd->revision;
	binfo.sw_version = HFI1_USER_SWVERSION;
	binfo.bthqp = RVT_KDETH_QP_PREFIX;
	binfo.jkey = uctxt->jkey;
	/*
	 * If more than 64 contexts are enabled the allocated credit
	 * return will span two or three contiguous pages. Since we only
	 * map the page containing the context's credit return address,
	 * we need to calculate the offset in the proper page.
	 */
	offset = ((u64)uctxt->sc->hw_free -
		  (u64)dd->cr_base[uctxt->numa_id].va) % PAGE_SIZE;
	binfo.sc_credits_addr = HFI1_MMAP_TOKEN(PIO_CRED, uctxt->ctxt,
						fd->subctxt, offset);
	binfo.pio_bufbase = HFI1_MMAP_TOKEN(PIO_BUFS, uctxt->ctxt,
					    fd->subctxt,
					    uctxt->sc->base_addr);
	binfo.pio_bufbase_sop = HFI1_MMAP_TOKEN(PIO_BUFS_SOP,
						uctxt->ctxt,
						fd->subctxt,
						uctxt->sc->base_addr);
	binfo.rcvhdr_bufbase = HFI1_MMAP_TOKEN(RCV_HDRQ, uctxt->ctxt,
					       fd->subctxt,
					       uctxt->rcvhdrq);
	binfo.rcvegr_bufbase = HFI1_MMAP_TOKEN(RCV_EGRBUF, uctxt->ctxt,
					       fd->subctxt,
					       uctxt->egrbufs.rcvtids[0].dma);
	binfo.sdma_comp_bufbase = HFI1_MMAP_TOKEN(SDMA_COMP, uctxt->ctxt,
						  fd->subctxt, 0);
	/*
	 * user regs are at
	 * (RXE_PER_CONTEXT_USER + (ctxt * RXE_PER_CONTEXT_SIZE))
	 */
	binfo.user_regbase = HFI1_MMAP_TOKEN(UREGS, uctxt->ctxt,
					     fd->subctxt, 0);
	offset = offset_in_page((uctxt_offset(uctxt) + fd->subctxt) *
				sizeof(*dd->events));
	binfo.events_bufbase = HFI1_MMAP_TOKEN(EVENTS, uctxt->ctxt,
					       fd->subctxt,
					       offset);
	binfo.status_bufbase = HFI1_MMAP_TOKEN(STATUS, uctxt->ctxt,
					       fd->subctxt,
					       dd->status);
	if (HFI1_CAP_IS_USET(DMA_RTAIL))
		binfo.rcvhdrtail_base = HFI1_MMAP_TOKEN(RTAIL, uctxt->ctxt,
							fd->subctxt, 0);
	if (uctxt->subctxt_cnt) {
		binfo.subctxt_uregbase = HFI1_MMAP_TOKEN(SUBCTXT_UREGS,
							 uctxt->ctxt,
							 fd->subctxt, 0);
		binfo.subctxt_rcvhdrbuf = HFI1_MMAP_TOKEN(SUBCTXT_RCV_HDRQ,
							  uctxt->ctxt,
							  fd->subctxt, 0);
		binfo.subctxt_rcvegrbuf = HFI1_MMAP_TOKEN(SUBCTXT_EGRBUF,
							  uctxt->ctxt,
							  fd->subctxt, 0);
	}

	if (copy_to_user((void __user *)arg, &binfo, len))
		return -EFAULT;

	return 0;
}

/*
 * Require that hfi1_tid_info and hfi1_tid_info_v3 shared fields are the same.
 */
static_assert(offsetof(struct hfi1_tid_info, vaddr) == offsetof(struct hfi1_tid_info_v3, vaddr));
static_assert(offsetof(struct hfi1_tid_info, tidlist) == offsetof(struct hfi1_tid_info_v3, tidlist));
static_assert(offsetof(struct hfi1_tid_info, tidcnt) == offsetof(struct hfi1_tid_info_v3, tidcnt));
static_assert(offsetof(struct hfi1_tid_info, length) == offsetof(struct hfi1_tid_info_v3, length));
static_assert(offsetofend(struct hfi1_tid_info, length) == offsetofend(struct hfi1_tid_info_v3, length));

/**
 * _user_exp_rcv_setup - Set up the given tid rcv list
 * @fd: file data of the current driver instance
 * @tinfo: already copied from userspace
 * @arg: ioctl argumnent for user space information
 * @len: length of data structure associated with ioctl command
 * @allow_unaligned: when true, try to handle non-page-size multiple
 *   (vaddr,length) in tidinfo from userspace.
 *
 * Wrapper to validate ioctl information before doing _rcv_setup.
 *
 */
static int _user_exp_rcv_setup(struct hfi1_filedata *fd, struct hfi1_tid_info_v3 *tinfo,
			       unsigned long arg, u32 len, bool allow_unaligned)
{
	int ret;
	unsigned long addr;

	/* Reserved .flags bits must be 0 */
	if (tinfo->flags & HFI1_TID_UPDATE_V3_FLAGS_RESERVED_MASK)
		return -EINVAL;
	/* Reserved for now */
	if (tinfo->context)
		return -EINVAL;

	ret = hfi1_user_exp_rcv_setup(fd, tinfo, allow_unaligned, false);
	if (!ret) {
		/*
		 * Copy the number of tidlist entries we used
		 * and the length of the buffer we registered.
		 */
		addr = arg + offsetof(struct hfi1_tid_info, tidcnt);
		if (copy_to_user((void __user *)addr, &tinfo->tidcnt,
				 sizeof(tinfo->tidcnt)))
			ret = -EFAULT;

		addr = arg + offsetof(struct hfi1_tid_info, length);
		if (!ret && copy_to_user((void __user *)addr, &tinfo->length,
					 sizeof(tinfo->length)))
			ret = -EFAULT;

		if (ret)
			hfi1_user_exp_rcv_clear(fd, (struct hfi1_tid_info *)tinfo);
	}

	return ret;
}

/**
 * Handles HFI1_IOCTL_TID_UPDATE and HFI1_IOCTL_TID_UPDATE_V3
 */
static int user_exp_rcv_setup(struct hfi1_filedata *fd, unsigned long arg,
			      u32 len)
{
	struct hfi1_tid_info_v3 tinfo;

	if (copy_struct_from_user(&tinfo, sizeof(tinfo), (void __user *)arg, len))
		return -EFAULT;

	return _user_exp_rcv_setup(fd, &tinfo, arg, len, false);
}

#ifdef NVIDIA_GPU_DIRECT

/* Require that hfi1_tid_info_v2 is subset of hfi1_tid_info_v3 */
static_assert(sizeof(struct hfi1_tid_info_v2) <= sizeof(struct hfi1_tid_info_v3));
static_assert(offsetof(struct hfi1_tid_info_v2, flags) == offsetof(struct hfi1_tid_info_v3, flags));
static_assert(offsetofend(struct hfi1_tid_info_v2, flags) <= offsetofend(struct hfi1_tid_info_v3, flags));

/**
 * Wrapper around _user_exp_rcv_setup() for HFI1_IOCTL_TID_UPDATE_V2.
 */
static int user_exp_rcv_setup_v2(struct hfi1_filedata *fd, unsigned long arg,
				 u32 len)
{
	struct hfi1_tid_info_v3 tinfo;
	struct hfi1_tid_info_v2 *tinfov2 = (struct hfi1_tid_info_v2 *)&tinfo;
	int ret;

	/*
	 * offsetofend(struct hfi1_tid_info_v2,flags) <= offsetofend(struct hfi1_tid_info_v3,flags).
	 * So copy_struct_from_user() is guaranteed to zero-fill everything
	 * after struct hfi1_tid_info_v3.flags.
	 */
	ret = copy_struct_from_user(&tinfo, sizeof(tinfo), (void __user *)arg, len);
	if (ret)
		return ret;

	/* Reserved .flags bits must be 0 */
	if (tinfov2->flags & HFI1_TID_UPDATE_V2_FLAGS_RESERVED_MASK)
		return -EINVAL;

	/*
	 * If no _v2 flags were set, zero-out the v3 .flags so that any garbage
	 * between the end of hfi1_tid_info_v2.flags and hfi1_tid_info_v3.flags
	 * is cleared.
	 */
	if ((tinfov2->flags & HFI1_TID_UPDATE_V2_FLAGS_GPU_MASK) == HFI1_BUF_GPU_MEM)
		tinfo.flags = HFI1_MEMINFO_TYPE_NVIDIA;
	else
		tinfo.flags = 0;

	return _user_exp_rcv_setup(fd, &tinfo, arg, len, true);
}
#endif

/**
 * user_exp_rcv_clear - Clear the given tid rcv list
 * @fd: file data of the current driver instance
 * @arg: ioctl argumnent for user space information
 * @len: length of data structure associated with ioctl command
 *
 * The hfi1_user_exp_rcv_clear() can be called from the error path.  Because
 * of this, we need to use this wrapper to copy the user space information
 * before doing the clear.
 */
static int user_exp_rcv_clear(struct hfi1_filedata *fd, unsigned long arg,
			      u32 len)
{
	int ret;
	unsigned long addr;
	struct hfi1_tid_info tinfo;

	if (sizeof(tinfo) != len)
		return -EINVAL;

	if (copy_from_user(&tinfo, (void __user *)arg, (sizeof(tinfo))))
		return -EFAULT;

	ret = hfi1_user_exp_rcv_clear(fd, &tinfo);
	if (!ret) {
		addr = arg + offsetof(struct hfi1_tid_info, tidcnt);
		if (copy_to_user((void __user *)addr, &tinfo.tidcnt,
				 sizeof(tinfo.tidcnt)))
			return -EFAULT;
	}

	return ret;
}

/**
 * user_exp_rcv_invalid - Invalidate the given tid rcv list
 * @fd: file data of the current driver instance
 * @arg: ioctl argumnent for user space information
 * @len: length of data structure associated with ioctl command
 *
 * Wrapper to validate ioctl information before doing _rcv_invalid.
 *
 */
static int user_exp_rcv_invalid(struct hfi1_filedata *fd, unsigned long arg,
				u32 len)
{
	int ret;
	unsigned long addr;
	struct hfi1_tid_info tinfo;

	if (sizeof(tinfo) != len)
		return -EINVAL;

	if (copy_from_user(&tinfo, (void __user *)arg, (sizeof(tinfo))))
		return -EFAULT;

	ret = hfi1_user_exp_rcv_invalid(fd, &tinfo, false);
	if (ret)
		return ret;

	addr = arg + offsetof(struct hfi1_tid_info, tidcnt);
	if (copy_to_user((void __user *)addr, &tinfo.tidcnt,
			 sizeof(tinfo.tidcnt)))
		ret = -EFAULT;

	return ret;
}

static __poll_t poll_urgent(struct file *fp,
				struct poll_table_struct *pt)
{
	struct hfi1_filedata *fd = fp->private_data;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;
	__poll_t pollflag;

	poll_wait(fp, &uctxt->wait, pt);

	spin_lock_irq(&dd->uctxt_lock);
	if (uctxt->urgent != uctxt->urgent_poll) {
		pollflag = EPOLLIN | EPOLLRDNORM;
		uctxt->urgent_poll = uctxt->urgent;
	} else {
		pollflag = 0;
		set_bit(HFI1_CTXT_WAITING_URG, &uctxt->event_flags);
	}
	spin_unlock_irq(&dd->uctxt_lock);

	return pollflag;
}

static __poll_t poll_next(struct file *fp,
			      struct poll_table_struct *pt)
{
	struct hfi1_filedata *fd = fp->private_data;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;
	__poll_t pollflag;

	poll_wait(fp, &uctxt->wait, pt);

	spin_lock_irq(&dd->uctxt_lock);
	if (hdrqempty(uctxt)) {
		set_bit(HFI1_CTXT_WAITING_RCV, &uctxt->event_flags);
		hfi1_rcvctrl(dd, HFI1_RCVCTRL_INTRAVAIL_ENB, uctxt);
		pollflag = 0;
	} else {
		pollflag = EPOLLIN | EPOLLRDNORM;
	}
	spin_unlock_irq(&dd->uctxt_lock);

	return pollflag;
}

/*
 * Find all user contexts in use, and set the specified bit in their
 * event mask.
 * See also find_ctxt() for a similar use, that is specific to send buffers.
 */
int hfi1_set_uevent_bits(struct hfi1_pportdata *ppd, const int evtbit)
{
	struct hfi1_ctxtdata *uctxt;
	struct hfi1_devdata *dd = ppd->dd;
	struct hfi1_portrsrcs *pr = &dd->rsrcs.ppr[ppd->hw_pidx];
	u16 ctxt;

	if (!dd->events)
		return -EINVAL;

	for (ctxt = pr->first_dyn_alloc_ctxt;
	     ctxt < pr->rcv_context_base + pr->num_rcv_contexts;
	     ctxt++) {
		uctxt = hfi1_rcd_get_by_index(dd, ctxt);
		if (uctxt) {
			unsigned long *evs;
			int i;
			/*
			 * subctxt_cnt is 0 if not shared, so do base
			 * separately, first, then remaining subctxt, if any
			 */
			evs = dd->events + uctxt_offset(uctxt);
			set_bit(evtbit, evs);
			for (i = 1; i < uctxt->subctxt_cnt; i++)
				set_bit(evtbit, evs + i);
			hfi1_rcd_put(uctxt);
		}
	}

	return 0;
}

/**
 * manage_rcvq - manage a context's receive queue
 * @uctxt: the context
 * @subctxt: the sub-context
 * @start_stop: action to carry out
 *
 * start_stop == 0 disables receive on the context, for use in queue
 * overflow conditions.  start_stop==1 re-enables, to be used to
 * re-init the software copy of the head register
 */
int manage_rcvq(struct hfi1_ctxtdata *uctxt, u16 subctxt, int start_stop)
{
	struct hfi1_devdata *dd = uctxt->dd;
	unsigned int rcvctrl_op;

	if (subctxt)
		return 0;

	/* atomically clear receive enable ctxt. */
	if (start_stop) {
		/*
		 * On enable, force in-memory copy of the tail register to
		 * 0, so that protocol code doesn't have to worry about
		 * whether or not the chip has yet updated the in-memory
		 * copy or not on return from the system call. The chip
		 * always resets it's tail register back to 0 on a
		 * transition from disabled to enabled.
		 */
		if (hfi1_rcvhdrtail_kvaddr(uctxt))
			clear_rcvhdrtail(uctxt);
		rcvctrl_op = HFI1_RCVCTRL_CTXT_ENB;
	} else {
		rcvctrl_op = HFI1_RCVCTRL_CTXT_DIS;
	}
	hfi1_rcvctrl(dd, rcvctrl_op, uctxt);
	/* always; new head should be equal to new tail; see above */

	return 0;
}

/*
 * clear the event notifier events for this context.
 * User process then performs actions appropriate to bit having been
 * set, if desired, and checks again in future.
 */
int user_event_ack(struct hfi1_ctxtdata *uctxt, u16 subctxt,
		   unsigned long events)
{
	int i;
	struct hfi1_devdata *dd = uctxt->dd;
	unsigned long *evs;

	if (!dd->events)
		return 0;

	evs = dd->events + uctxt_offset(uctxt) + subctxt;

	for (i = 0; i <= _HFI1_MAX_EVENT_BIT; i++) {
		if (!test_bit(i, &events))
			continue;
		clear_bit(i, evs);
	}
	return 0;
}

int set_ctxt_pkey(struct hfi1_ctxtdata *uctxt, u16 pkey)
{
	int i;
	struct hfi1_pportdata *ppd = uctxt->ppd;
	struct hfi1_devdata *dd = uctxt->dd;

	if (!HFI1_CAP_IS_USET(PKEY_CHECK))
		return -EPERM;

	if (pkey == LIM_MGMT_P_KEY || pkey == FULL_MGMT_P_KEY)
		return -EINVAL;

	for (i = 0; i < dd->params->pkey_table_size; i++)
		if (pkey == ppd->pkeys[i])
			return hfi1_set_ctxt_pkey(dd, uctxt, pkey);

	return -ENOENT;
}

/**
 * ctxt_reset - Reset the user context
 * @uctxt: valid user context
 */
int ctxt_reset(struct hfi1_ctxtdata *uctxt)
{
	struct send_context *sc;
	struct hfi1_devdata *dd;
	int ret = 0;

	if (!uctxt || !uctxt->dd || !uctxt->sc)
		return -EINVAL;

	/*
	 * There is no protection here. User level has to guarantee that
	 * no one will be writing to the send context while it is being
	 * re-initialized.  If user level breaks that guarantee, it will
	 * break it's own context and no one else's.
	 */
	dd = uctxt->dd;
	sc = uctxt->sc;

	/*
	 * Wait until the interrupt handler has marked the context as
	 * halted or frozen. Report error if we time out.
	 */
	wait_event_interruptible_timeout(
		sc->halt_wait, (sc->flags & (SCF_HALTED | SCF_LINK_DOWN)),
		msecs_to_jiffies(SEND_CTXT_HALT_TIMEOUT));
	if (!(sc->flags & (SCF_HALTED | SCF_LINK_DOWN)))
		return -ENOLCK;

	/*
	 * If the send context was halted due to a Freeze, wait until the
	 * device has been "unfrozen" before resetting the context.
	 */
	if (sc->flags & SCF_FROZEN) {
		wait_event_interruptible_timeout(
			dd->event_queue,
			!(READ_ONCE(dd->flags) & HFI1_FROZEN),
			msecs_to_jiffies(SEND_CTXT_HALT_TIMEOUT));
		if (dd->flags & HFI1_FROZEN)
			return -ENOLCK;

		if (dd->flags & HFI1_FORCED_FREEZE)
			/*
			 * Don't allow context reset if we are into
			 * forced freeze
			 */
			return -ENODEV;

		sc_disable(sc);
		ret = sc_enable(sc);
		hfi1_rcvctrl(dd, HFI1_RCVCTRL_CTXT_ENB, uctxt);
	} else {
		ret = sc_restart(sc);
	}
	if (!ret)
		sc_return_credits(sc);

	return ret;
}

static void user_remove(struct hfi1_devdata *dd)
{

	hfi1_cdev_cleanup(&dd->user_cdev, &dd->user_device);
}

static int user_add(struct hfi1_devdata *dd)
{
	char name[10];
	int ret;

	snprintf(name, sizeof(name), "%s_%d", class_name(), dd->unit);
	ret = hfi1_cdev_init(dd->unit, name, &hfi1_file_ops,
			     &dd->user_cdev, &dd->user_device,
			     true, &dd->verbs_dev.rdi.ibdev.dev.kobj);
	if (ret)
		user_remove(dd);

	return ret;
}

/*
 * Create per-unit files in /dev
 */
int hfi1_device_create(struct hfi1_devdata *dd)
{
	hfi1_diag_add(dd);
	return user_add(dd);
}

/*
 * Remove per-unit files in /dev
 * void, core kernel returns no errors for this stuff
 */
void hfi1_device_remove(struct hfi1_devdata *dd)
{
	hfi1_diag_remove(dd);
	user_remove(dd);
}

static int get_pinning_stats(struct hfi1_filedata *fd, unsigned long arg,
			     u32 len)
{
	struct hfi1_pin_stats stats;
	unsigned int memtype;
	int index;
	int ret;

	if (sizeof(stats) != len)
		return -EINVAL;

	if (copy_from_user(&stats, (void __user *)arg, len))
		return -EFAULT;

	memtype = stats.memtype;
	index = stats.index;
	memset(&stats, 0, sizeof(stats));
	stats.memtype = memtype;
	stats.index = index;

	ret = hfi1_get_pinning_stats(fd, &stats);
	if (ret)
		return ret;

	if (copy_to_user((void __user *)arg, &stats, len))
		return -EFAULT;

	return 0;
}

/* expects stats is already zeroed with memtype and index filled in */
int hfi1_get_pinning_stats(struct hfi1_filedata *fd,
			   struct hfi1_pin_stats *stats)
{
	struct hfi1_user_sdma_pkt_q *pq;
	int lockidx;
	int ret;

	if (!pinning_type_supported(stats->memtype))
		return -EINVAL;

	lockidx = srcu_read_lock(&fd->pq_srcu);
	pq = srcu_dereference(fd->pq, &fd->pq_srcu);
	if (pq)
		ret = pinning_interfaces[stats->memtype].get_stats(pq, stats->index, stats);
	else
		ret = -EIO;
	srcu_read_unlock(&fd->pq_srcu, lockidx);

	return ret;
}

static int create_bulksvc_cmplq(struct hfi1_filedata *fd, unsigned long arg, u32 len)
{
	int ret;
	(void) len;

	struct hfi1_devdata * const dd = fd->dd;
	struct hfi1_bulksvc* const bulksvc = dd->bulksvc;
	struct hfi1_bulksvc_queue_info *out;

	if (!bulksvc) {
		dd_dev_err(dd, "tried to get bulksvc cmplq, but bulksvc not enabled\n");
		return -ENODEV;
	}

	if (!fd->bulksvc_user_info) {
		dd_dev_err(dd, "tried to get bulksvc cmplq, but user info not initialized\n");
		return -ENODEV;
	}

	struct hfi1_bulksvc_user_info* const bulksvc_user_info = fd->bulksvc_user_info;


	ret = create_bulksvc_queue(dd, bulksvc_user_info, true, false, &out);
	if (ret)
		return ret;

	return copy_to_user((struct hfi1_bulksvc_user_info *)arg,
			    out, sizeof(*out));
}

static int create_bulksvc_cmdq(struct hfi1_filedata *fd, unsigned long arg, u32 len)
{
	(void) len;

	struct hfi1_devdata * const dd = fd->dd;
	struct hfi1_bulksvc* const bulksvc = dd->bulksvc;
	struct hfi1_bulksvc_queue_info *out;
	int ret;

	if (!bulksvc) {
		dd_dev_err(dd, "tried to get bulksvc cmdq, but bulksvc not enabled\n");
		return -ENODEV;
	}

	if (!fd->bulksvc_user_info) {
		dd_dev_err(dd, "tried to get bulksvc cmdq, but user info not initialized\n");
		return -ENODEV;
	}

	struct hfi1_bulksvc_user_info* const bulksvc_user_info = fd->bulksvc_user_info;

	ret = create_bulksvc_queue(dd, bulksvc_user_info, false, false, &out);
	if (ret)
		return ret;

	return copy_to_user((struct hfi1_bulksvc_queue_info *)arg, out,
			    sizeof(*out));
}

// module_param in bulksvc.c
extern uint bulksvc_user_queue_size_pages_log2;
int create_bulksvc_queue(struct hfi1_devdata *dd, struct hfi1_bulksvc_user_info* const bulksvc_user_info,
			 bool is_cmplq, bool is_uverbs,
			 struct hfi1_bulksvc_queue_info ** output_info)
{
	int rc = 0;
	u64 c_token, b_token;

	mutex_lock(&bulksvc_user_info->queue_records_lock);

	*output_info = NULL;

	struct hfi1_bulksvc_queue_record * const queue_rec = is_cmplq ? &bulksvc_user_info->cmplq_records[bulksvc_user_info->num_cmplqs] : &bulksvc_user_info->cmdq_records[bulksvc_user_info->num_cmdqs];

	u8 *num = is_cmplq ? &bulksvc_user_info->num_cmplqs : &bulksvc_user_info->num_cmdqs;
	u8 const max_queues = is_cmplq ? BULKSVC_USER_MAX_NUM_CMPLQS : BULKSVC_USER_MAX_NUM_CMDQS;

	if (*num >= max_queues) {
		rc = -ENOSPC;
		dd_dev_info(dd, "tried to get bulksvc queue, but no more available\n");
		goto out;
	}

	queue_rec->queue_info.queue_id = *num;

	/* TODO constants */
	int const ctrl_token_type = (is_cmplq ? BULKSVC_CMPLQ_CTRL0 : BULKSVC_CMDQ_CTRL0) + *num;
	int const queue_token_type = (is_cmplq ? BULKSVC_CMPLQ_BUF0 : BULKSVC_CMDQ_BUF0) + *num;
	queue_rec->queue_info.queue_ctrl_mmap_size = PAGE_SIZE;

	if (is_uverbs) {
		/* format is <8bit type><PAGE_SIZE offset> */
		c_token = rdma_mmap_token_i(ctrl_token_type, 0);
		b_token = rdma_mmap_token_i(queue_token_type, 0);
	} else {
		/* format is <32 bit magic><8bit type><8bit ctxt><8bit subctxt><PAGE_SIZE offset> */
		c_token = HFI1_MMAP_TOKEN(ctrl_token_type, 0, 0, 0);
		b_token = HFI1_MMAP_TOKEN(queue_token_type, 0, 0, 0);
	}
	queue_rec->queue_info.queue_ctrl_mmap_token = c_token;
	queue_rec->queue_info.queue_buffer_mmap_token = b_token;
	queue_rec->queue_info.queue_buffer_mmap_size = (1 << bulksvc_user_queue_size_pages_log2) * PAGE_SIZE;

	queue_rec->ctrl = vmalloc_user(queue_rec->queue_info.queue_ctrl_mmap_size);
	if (!queue_rec->ctrl) {
		rc = -ENOMEM;
		goto out;
	}
	WARN_ON(!IS_ALIGNED((unsigned long)queue_rec->ctrl, PAGE_SIZE));
	queue_rec->queue_buf = vmalloc_user(queue_rec->queue_info.queue_buffer_mmap_size);
	if (!queue_rec->queue_buf) {
		vfree(queue_rec->ctrl);
		rc = -ENOMEM;
		goto out;
	}
	WARN_ON(!IS_ALIGNED((unsigned long)queue_rec->queue_buf, PAGE_SIZE));
	u64 const num_buf_pages = queue_rec->queue_info.queue_buffer_mmap_size / PAGE_SIZE;
	struct page** const magic_buf_pages = (struct page **)kmalloc(2 * num_buf_pages * sizeof(struct page*), GFP_KERNEL);
	if (!magic_buf_pages) {
		vfree(queue_rec->ctrl);
		vfree(queue_rec->queue_buf);
		rc = -ENOMEM;
		goto out;
	}
	for (u32 i = 0; i < 2 * num_buf_pages; i++) {
		magic_buf_pages[i] = vmalloc_to_page(queue_rec->queue_buf + ((i % num_buf_pages) * PAGE_SIZE));
	}
	queue_rec->queue_buf_magic = vmap(magic_buf_pages, 2 * num_buf_pages, 0, PAGE_KERNEL);
	kfree(magic_buf_pages);
	if (!queue_rec->queue_buf_magic) {
		vfree(queue_rec->ctrl);
		vfree(queue_rec->queue_buf);
		rc = -ENOMEM;
		goto out;
	}

	dd_dev_dbg(dd, "created bulksvc %s queue with id %d\n",
		is_cmplq ? "completion" : "command", queue_rec->queue_info.queue_id);

	*output_info = &queue_rec->queue_info;

	u32 const block_size = is_cmplq ? sizeof(union hfi1_bulksvc_upd) : CACHELINE_SIZE;
	BUG_ON(queue_rec->queue_info.queue_buffer_mmap_size % block_size != 0);
	queue_rec->idx_mask = (queue_rec->queue_info.queue_buffer_mmap_size / block_size) - 1;
	queue_rec->head = (atomic64_t *) &queue_rec->ctrl->head;
	queue_rec->tail = (atomic64_t *) &queue_rec->ctrl->tail;
	queue_rec->active = true;
	/* update count last when everything is setup*/
	wmb();
	*num += 1;

out:
	mutex_unlock(&bulksvc_user_info->queue_records_lock);
	return rc;
}

static int ioctl_init_bulksvc_client(struct hfi1_filedata *fd, unsigned long arg, u32 len)
{
	struct hfi1_bulksvc_client_init out;
	int ret;

	ret = init_bulksvc_client(fd, &out);
	if (ret)
		return ret;

	if (copy_to_user((struct hfi1_bulksvc_client_init *)arg, &out,
			 sizeof(out))) {
		pr_err("failed to copy bulksvc client key to user\n");
		hfi1_bulksvc_user_info_put(fd->bulksvc_user_info);
		fd->bulksvc_user_info = NULL;
		return -EFAULT;
	}

	return 0;
}

int init_bulksvc_client(struct hfi1_filedata *fd, struct hfi1_bulksvc_client_init *out)
{
	u32 client_flags = 0;
	struct hfi1_bulksvc_event_entry *event_entry;

	if (WARN_ON(!fd || !fd->dd || !fd->dd->bulksvc)) {
		pr_err("Bulksvc not enabled\n");
		return -EINVAL;
	}

	if (fd->dd->params->cce_int_force_reg  == 0) {
		pr_err("Bulksvc - DD not fully initialized");
		return -EINVAL;
	}

	if (fd->bulksvc_user_info) {
		pr_err("Bulksvc client already initialized\n");
		return -EALREADY;
	}

	struct hfi1_bulksvc* const bulksvc = fd->dd->bulksvc;

	fd->bulksvc_user_info = hfi1_bulksvc_user_info_create(fd);
	if (!fd->bulksvc_user_info) {
		return -ENOMEM;
	}

	if (hfi1_bulksvc_requires_doorbell(bulksvc)) {
		client_flags |= HFI1_HFISVC_CLIENT_FLAG_DOORBELL;
	}

	event_entry = kzalloc(sizeof(*event_entry), GFP_KERNEL);
	if (!event_entry) {
		return -ENOMEM;
	}
	event_entry->event.type = BULKSVC_EVENT_TYPE_USER_INFO_ADD;
	event_entry->event.user_info = fd->bulksvc_user_info;
	if (hfi1_bulksvc_enqueue_event(bulksvc, event_entry)) {
		pr_err("failed to enqueue bulksvc user info add event\n");
		kfree(event_entry);
		hfi1_bulksvc_user_info_put(fd->bulksvc_user_info);
		fd->bulksvc_user_info = NULL;
		return -EAGAIN;
	}

	out->client_key = fd->bulksvc_user_info->client_key;
	out->flags = client_flags;
	out->fast_doorbell = rdma_mmap_token_i(BULKSVC_FAST_DOORBELL, 0);
	out->fast_doorbell_mmap_size = PAGE_SIZE;

	return 0;
}

static int ioctl_bulksvc_doorbell(struct hfi1_filedata *fd, unsigned long arg, u32 len)
{
	if (WARN_ON(!fd || !fd->dd || !fd->dd->bulksvc)) {
		pr_err("Bulksvc not enabled\n");
		return -EINVAL;
	}

	if (!fd->bulksvc_user_info) {
		pr_err("Bulksvc client not initialized\n");
		return -EALREADY;
	}

	struct hfi1_bulksvc* const svc = fd->dd->bulksvc;
	if (WARN_ON(svc->dd == NULL)) {
		pr_err("Bulksvc not initialized\n");
		return -EINVAL;
	}

	hfi1_bulksvc_schedule(svc);

	return 0;
}
