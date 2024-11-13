// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 *
 * SRIOV support for VFs making requests to PF0.
 */

#include "hfi.h"
#include "chip.h"
#include "chip_gen.h"
#include "sriov.h"
#include "vf2pf_int.h"

uint vf2pf_to = 1;
module_param_named(vf2pf_to, vf2pf_to, uint, 0644);
MODULE_PARM_DESC(vf2pf_to, "Timeout for vf2pf responses, seconds, default 1");

#define IS_LOCAL_VF(dd)		(!(dd)->is_vm)
#define IS_LOCAL_VDD(vdd)	(vdd)

static struct vf2pf_devops vf2pf_nodev = { };

static struct vf2pf_devops *vf2pf_dev = &vf2pf_nodev;

/* for additional output to "hw_resources" */
int vf2pf_sysfs_emit_at(struct hfi1_devdata *dd, char *buf, int at)
{
	int off = at;

	/*
	 * Anything for vf2pf core goes here.
	 */

	if (vf2pf_dev->sysfs_emit_at)
		off += vf2pf_dev->sysfs_emit_at(dd, buf, off);

	return off - at;
}

/*
 * Allocate memory for a vf2pf message to transmit.
 * Returns pointer to allocation, to be used in kfree() and
 * passing to vf2pf_devops.send().
 *
 * On success,
 * 'msg' is set to struct vf2pf_hdr (vf2pf payload) part of allocation,
 *
 * buffer contents/structure:
 *
 * ret->	struct vf2pf_prefix
 *		-align u64-
 *		[opt: implimentation headers]
 * msg->	struct vf2pf_hdr
 *		variable payload...
 */
static void *msg_alloc(struct hfi1_devdata *dd, struct vf2pf_hdr **msg)
{
	if (!vf2pf_dev->msg_alloc)
		return NULL;

	return vf2pf_dev->msg_alloc(dd, msg);
}

/*
 * Send a message to 'si'.
 *
 * 'buf' is opaque pointer returned by msg_alloc().
 * header part (vf2pf_dev->get_msg(dd, buf)) must have been filled out.
 * caller may kfree on return.
 */
static int vf2pf_send(struct hfi1_devdata *dd, u8 si, void *buf)
{
	if (!vf2pf_dev->send)
		return -ENXIO;

	return vf2pf_dev->send(dd, si, buf);
}

/*
 * overwrites 'buf' with response.
 * caller acquired 'buf' via msg_alloc().
 * on success, 'buf' contains the response (caller kfrees when done).
 */
static int vf2pf_send_recv(struct hfi1_devdata *dd, u8 si, void *buf, long to)
{
	struct vf2pf_prefix *pfx = buf;
	struct vf2pf_hdr *hdr;
	int ret;

	if (!vf2pf_dev->set_tid || !vf2pf_dev->get_msg)
		return -EINVAL;

	if (to > 0) {
		pfx->type = VF2PF_PFX_TYPE_WAIT;
		init_waitqueue_head(&pfx->wait);
	} else {
		to = -to;
		pfx->type = VF2PF_PFX_TYPE_SEMA;
		sema_init(&pfx->sema, 0);
	}
	hdr = vf2pf_dev->get_msg(dd, buf);
	hdr->tid = vf2pf_dev->set_tid(dd, buf);

	ret = vf2pf_send(dd, si, buf);
	if (ret) {
		vf2pf_dev->get_tid(dd, hdr->tid); /* discard tid */
		return ret;
	}

	if (pfx->type == VF2PF_PFX_TYPE_WAIT) {
		if (vf2pf_dev->rcv_wait) {
			ret = vf2pf_dev->rcv_wait(dd, buf, to);
		} else {
			ret = wait_event_timeout(pfx->wait,
						 (hdr->op & VF2PF_OP_RESP), to);
			ret = ret ? 0 : -ETIME; /* convert residual time  to error */
		}
	} else {
		ret = down_timeout(&pfx->sema, to);
	}
	if (ret)	/* timeout or other error */
		vf2pf_dev->get_tid(dd, hdr->tid); /* discard tid */

	return ret;
}

/*
 * VF call to PF0 to setup dd->rsrcs.
 */
int vf2pf_get_config(struct hfi1_devdata *dd, struct hfi1_devrsrcs *out, int si)
{
	int ret;

	if (!dd->is_vf)
		return -EINVAL;
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi1_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		ret = sriov_get_config(pdd, out, si);
		if (ret)
			return ret;
		dd->base_guid = pdd->base_guid;
		dd->revision = pdd->revision;
		dd->hfi1_id = pdd->hfi1_id;
		dd->icode = pdd->icode;
		dd->irev = pdd->irev;
		return 0;
	}
	/* TODO: send message to PF0 */
	return -EINVAL;
}

/*
 * VF call to PF0 to assign chip resources to this SI.
 * May include additional early setup.
 */
int vf2pf_assign_rsrcs(struct hfi1_devdata *dd, struct hfi1_devrsrcs *vfr)
{
	if (!dd->is_vf)
		return -EINVAL;
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi1_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return hfi1_sriov_assign_rsrcs(pdd, vfr);
	}
	/* TODO: send message to PF0 */
	return -EINVAL;
}

/*
 * VF call to PF0 to release chip resources.
 * May include other late shutdown.
 */
int vf2pf_free_rsrcs(struct hfi1_devdata *dd, struct hfi1_devrsrcs *vfr)
{
	if (!dd->is_vf)
		return -EINVAL;
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi1_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		hfi1_sriov_free_rsrcs(pdd, vfr);
		return 0;
	}
	/* TODO: send message to PF0 */
	return -EINVAL;
}

int vf2pf_priv_reg_op(struct hfi1_devdata *dd, int pidx, u32 ctxt, int type,
		      enum preg_op op, u64 arg)
{
	if (!dd->is_vf)
		return -EINVAL;
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi1_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return priv_reg_op(pdd, pidx, ctxt, type, op, arg);
	}
	/* TODO: send message to PF0 */
	return -EINVAL;
}

/* Called for PF0 and VFs */
u64 pf0_read_csr(struct hfi1_devdata *dd, enum csr_type type, u32 off,
		 u16 ctxt, u8 pidx_eng)
{
	if (!dd->is_vf)
		return read_csr(dd, off);
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi1_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return read_csr_type(pdd, type, off, ctxt, pidx_eng);
	}
	/* TODO: send message to PF0 */
	return ~(u64)0; /* error */
}

/* Only called for VFs */
u64 pf0_rctxt_ctrl_op(struct hfi1_devdata *dd, u16 ctxt, unsigned int op)
{
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi1_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return rctxt_ctrl_op(pdd, ctxt, op);
	}
	/* TODO: send message to PF0 */
	return ~(u64)0; /* error */
}

void vf2pf_tid_config(struct hfi1_devdata *dd, int pidx, u16 ctxt,
		      u32 eager_base, u16 alloced,
		      u32 expected_base, u32 expected_count)
{
	if (!dd->is_vf)
		return; /*should never happen */
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi1_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		pdd->params->set_port_tid_config(pdd, pidx, ctxt, eager_base, alloced,
						 expected_base, expected_count);
		return;
	}
	/* TODO:
	 * send 'off' to PF0 and get response.
	msg = kzalloc(...);
	msg->op = TID_CONFIG;
	msg->pidx = pidx;
	msg->ctxt = ctxt;
	msg->eager_base = eager_base;
	msg->alloced = alloced;
	msg->expected_base = expected_base;
	msg->expected_count = expected_count;
	ret = vf2pf_send_recv(dd, msg);
	 */
	dd_dev_err(dd, "%s not implemented\n", __func__);
}

u16 vf2pf_get_qp_map(struct hfi1_devdata *dd, int pidx, u16 idx)
{
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi1_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return hfi1_get_qp_map(pdd->pport + pidx, idx);
	}
	/* TODO: send message to PF0 */
	return 0; /* guaranteed to error(?) */
}

/* TODO:
 * Need a message handler for PF0 here. Receive a message from a VF,
 * determine 'si', make appropriate call, return results.
	switch (op) {
	...
	case GET_CONFIG:
		ret = sriov_get_config(dd, &msg->buf, si);
		break;
	case ASGN_RSRCS:
		ret = hfi1_sriov_assign_rsrcs(dd, &msg->buf);
		break;
	case FREE_RSRCS:
		ret = hfi1_sriov_free_rsrcs(dd, &msg->buf);
		break;
	case SC_OP:
		ret = priv_reg_op(dd, ...);
		break;
	...
	}
	msg->ret = ret;
	vf2pf_send_resp(dd, msg...);
 */

static void vf2pf_syncup(struct hfi1_devdata *dd, int si)
{
	atomic_or(1 << si, &dd->rsrcs.sync_pending);
	queue_work(dd->hfi1_wq, &dd->sync_vf_work);
}

static void vf2pf_sync_fn(struct work_struct *work)
{
	int ret;

	struct hfi1_devdata *dd = container_of(work, struct hfi1_devdata, sync_vf_work);
	int sync_pending = atomic_fetch_and(0, &dd->rsrcs.sync_pending);

	if (!sync_pending)
		return;

	dd_dev_info(dd, "syncing VFs %02x\n", sync_pending);
	dd->rsrcs.sync_done |= sync_pending;
	ret = hfi1_sriov_sync_ports(dd, sync_pending);
	if (ret)
		dd_dev_err(dd, "Failed to sync ports to %02x (%d)\n", sync_pending, ret);
}

/*
 * received responses handled elsewhere.
 * 'buf' (and 'hdr') are allocated memory.
 * must be safe to destroy 'buf' on return.
 */
void vf2pf_rcv_msg(struct hfi1_devdata *dd, struct vf2pf_hdr *hdr, void *buf)
{
	int ret = 0;

	/* hdr == vf2pf_dev->get_msg(dd, buf) */
	switch (hdr->op) {
	case VF2PF_OP_PING: {
		struct vf2pf_ping_msg *ping = (struct vf2pf_ping_msg *)hdr;

		dd_dev_info(dd, "vf2pf ping-pong with %u \"%.*s\"\n", hdr->si,
			    hdr->len, ping->data);
		if (hdr->len >= sizeof(ping->data))
			hdr->len = sizeof(ping->data) - 1;
		ping->data[hdr->len++] = '!';
		break;
	}
	/* TODO: implement other message handlers */
	default:
		dd_dev_err(dd, "Unknown vf2pf msg op %u from %u\n", hdr->op, hdr->si);
		return;
	}

	/* reaching here means response is to be sent */
	hdr->op |= VF2PF_OP_RESP;
	hdr->status = ret;
	vf2pf_send(dd, hdr->si, buf);
}

/*
 * 'buf' may point to h/w recv buffer.
 * called from intr context: must expedite handling.
 * hdr->op has VF2PF_OP_RESP set, in order to reach here.
 */
void vf2pf_rsp_msg(struct hfi1_devdata *dd, void *buf)
{
	struct vf2pf_hdr *hdr = buf;
	struct vf2pf_prefix *wpfx;	/* msg object waiting for response */
	struct vf2pf_hdr *whdr;		/* hdr waiting for response */
	void *wbuf;

	wpfx = vf2pf_dev->get_tid(dd, hdr->tid);
	if (!wpfx) {
		dd_dev_err(dd, "vf2pf response op %x has no waiter\n", hdr->op);
		return;
	}
	whdr = vf2pf_dev->get_msg(dd, wpfx);
	wbuf = whdr;
	/*
	 * need to avoid race by setting VF2PF_OP_RESP in whdr->op last (after barrier).
	 * this requires that VF2PF_OP_RESP is cleared in 'op' before the memcpy,
	 * then set after in the destination.
	 */
	hdr->op &= ~VF2PF_OP_RESP;
	memcpy(wbuf, buf, hdr->len + sizeof(*hdr));
	smp_wmb(); /* needed? */
	whdr->op |= VF2PF_OP_RESP; /* to trigger wakeup condition */
	if (wpfx->type == VF2PF_PFX_TYPE_WAIT)
		wake_up(&wpfx->wait);
	else
		up(&wpfx->sema);
}

/*
 * Return number of special contexts needed by implementation.
 * Should be either 0 or JKR_C_CCE_NUM_VFS + 1.
 */
int vf2pf_num_ctxts(struct hfi1_devdata *dd)
{
	if (dd->params->chip_type == CHIP_WFR || !dd->is_sriov)
		return 0;
	return vf2pf_dev->num_ctxts;
}

int vf2pf_num_irq(struct hfi1_devdata *dd)
{
	if (dd->params->chip_type == CHIP_WFR || !dd->is_sriov)
		return 0;
	return vf2pf_dev->num_irq;
}

/* returns 0 on error (invalid VF SI) */
int vf2pf_probe_si(struct hfi1_devdata *dd)
{
	if (vf2pf_dev->probe_si)
		return vf2pf_dev->probe_si(dd);
	return 0;
}

static ssize_t vf2pf_ping_store(struct device *device,
				struct device_attribute *attr, const char *buf,
				size_t count)
{
	struct hfi1_ibdev *dev = rdma_device_to_drv_device(device, struct hfi1_ibdev, rdi.ibdev);
	struct hfi1_devdata *dd = dd_from_dev(dev);
	void *mem;
	struct vf2pf_hdr *hdr;
	struct vf2pf_ping_msg *ping;
	size_t len = count;
	int ret;

	if (count > sizeof(ping->data))
		return -EINVAL;

	/* trim one newline if present */
	if (buf[len - 1] == '\n')
		--len;

	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return -ENOMEM;

	ping = (struct vf2pf_ping_msg *)hdr;
	ping->hdr.op = VF2PF_OP_PING;
	ping->hdr.len = len;
	memcpy(ping->data, buf, len);

	dd_dev_info(dd, "vf2pf ping 0 \"%.*s\"\n", ping->hdr.len, buf);
	ret = vf2pf_send_recv(dd, 0, mem, vf2pf_to * HZ);
	if (ret)
		dd_dev_warn(dd, "vf2pf ping send failed (%d)\n", ret);
	else
		dd_dev_info(dd, "vf2pf ping resp from %u \"%.*s\"\n",
			    ping->hdr.si, ping->hdr.len, (char *)ping->data);
	kfree(mem);
	return count;
}

static DEVICE_ATTR_WO(vf2pf_ping);

static ssize_t vf2pf_sync_store(struct device *device,
				struct device_attribute *attr, const char *buf,
				size_t count)
{
	struct hfi1_ibdev *dev = rdma_device_to_drv_device(device, struct hfi1_ibdev, rdi.ibdev);
	struct hfi1_devdata *dd = dd_from_dev(dev);
	unsigned long sync_mask;
	int ret;

	/* allow 0 mask and trigger work func anyway */
	ret = kstrtoul(buf, 0, &sync_mask);
	if (ret || (sync_mask & ~0b011111110))
		return -EINVAL;

	atomic_or(sync_mask, &dd->rsrcs.sync_pending);
	queue_work(dd->hfi1_wq, &dd->sync_vf_work);

	return count;
}

static DEVICE_ATTR_WO(vf2pf_sync);

void vf2pf_set_si_enables(struct hfi1_devdata *dd, int si, u64 *csrs,
			  void (*si_enables)(struct hfi1_devdata *dd,
					     u64 *csrs, u32 start, u32 end))
{
	if (!vf2pf_dev->set_si_enables)
		return;
	vf2pf_dev->set_si_enables(dd, si, csrs, si_enables);
}

void vf2pf_ready(struct hfi1_devdata *dd)
{
	if (!dd->is_vf)
		return;

	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi1_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		vf2pf_syncup(pdd, dd->rsrcs.si_idx);
		return;
	}
	dd_dev_err(dd, "%s not implemended from VMs\n", __func__);
}

void vf2pf_init_sysfs(struct hfi1_devdata *dd, struct device *class_dev)
{
	struct vf2pf_lbdata *lbd = dd->vf2pf;
	int ret;

	if (!lbd)
		return;

	if (dd->is_vf) {
		ret = sysfs_create_file(&class_dev->kobj, &dev_attr_vf2pf_ping.attr);
		if (ret)
			dd_dev_warn(dd, "failed to create sysfs attr %s (%d)\n",
				    dev_attr_vf2pf_ping.attr.name, ret);
	} else {
		ret = sysfs_create_file(&class_dev->kobj, &dev_attr_vf2pf_sync.attr);
		if (ret)
			dd_dev_warn(dd, "failed to create sysfs attr %s (%d)\n",
				    dev_attr_vf2pf_sync.attr.name, ret);
	}
	if (vf2pf_dev->init_sysfs)
		vf2pf_dev->init_sysfs(dd, class_dev);
}

int vf2pf_init_irq(struct hfi1_devdata *dd)
{
	if (!vf2pf_dev->init_irq)
		return 0;
	return vf2pf_dev->init_irq(dd);
}

void vf2pf_deinit_irq(struct hfi1_devdata *dd)
{
	if (!vf2pf_dev->deinit_irq)
		return;
	vf2pf_dev->deinit_irq(dd);
}

/*
 * This is called on PF0 only, just before creation of VFs.
 *
 * This may be called multiple times throughout the life of the PF0
 * driver, if VFs are destroyed and recreated.
 */
int vf2pf_prep(struct hfi1_devdata *dd)
{
	if (!vf2pf_dev->init)
		return 0;
	return vf2pf_dev->init(dd, VF2PF_INIT_ALL);
}

/*
 * This is called early in the initialization.
 * It must not depend on any SRIOV configuration being setup,
 * but may call into the sriov module to decide if SRIOV is allowed.
 */
int vf2pf_init(struct hfi1_devdata *dd)
{
	if (dd->params->chip_type == CHIP_WFR || !dd->is_sriov)
		return 0;

	if (!dd->is_vf) {
		INIT_WORK(&dd->sync_vf_work, vf2pf_sync_fn);
		atomic_set(&dd->rsrcs.sync_pending, 0);
		dd->rsrcs.sync_done = 0;
	}

	if (!vf2pf_dev->init)
		return 0;
	return vf2pf_dev->init(dd, dd->rsrcs.si_idx);
}

/*
 * On VFs, this only sends a notification to PF0.
 * On PF0, this does a full de-initialization.
 */
void vf2pf_deinit(struct hfi1_devdata *dd)
{
	if (dd->is_vf) {
		if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
			struct hfi1_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

			if (vf2pf_dev->deinit)
				vf2pf_dev->deinit(pdd, dd->rsrcs.si_idx);
			goto out;
		}
		/* perform other communication to PF0 */
		dd_dev_err(dd, "Failed to notify PF0 (%d)\n", -ENXIO);
	}
out:
	if (vf2pf_dev->deinit)
		vf2pf_dev->deinit(dd, dd->rsrcs.si_idx);
}
