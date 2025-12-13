// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2018 - 2020 Intel Corporation.
 */

#include "bulksvc.h"
#include "hfi.h"
#include "affinity.h"
#include "sdma.h"
#include "netdev.h"
#include "vf2pf.h"

/**
 * msix_initialize() - Calculate, request and configure MSIx IRQs
 * @dd: valid hfi1 devdata
 *
 */
int msix_initialize(struct hfi1_devdata *dd)
{
	struct hfi1_devrsrcs *dr = &dd->rsrcs;
	u32 total;
	int ret;
	int pidx;
	struct hfi1_msix_entry *entries;

	/*
	 * MSIx interrupt count:
	 *	one for the general, "slow path" interrupt
	 *	three per used SDMA engine
	 *	one per kernel receive context
	 *	one for each bulksvc context
	 *	one for each VNIC context
	 *	one for the bulksvc doorbell
	 *      ...any new IRQs should be added here.
	 */
	total = 1 + vf2pf_num_irq(dd) +(3 * (dr->last_sdma_engine - dr->first_sdma_engine));
	for (pidx = 0; pidx < dd->num_pports; pidx++) {
		struct hfi1_portrsrcs *pr = &dr->ppr[pidx];

		total += pr->n_krcv_queues + pr->num_netdev_contexts +
			 pr->num_bulksvc_contexts;
	}
	total += 1;

	if (total >= CCE_NUM_MSIX_VECTORS)
		return -EINVAL;

	ret = pci_alloc_irq_vectors(dd->pcidev, total, total, PCI_IRQ_MSIX);
	if (ret < 0) {
		dd_dev_err(dd, "pci_alloc_irq_vectors() failed: %d\n", ret);
		return ret;
	}

	entries = kcalloc(total, sizeof(*dd->msix_info.msix_entries),
			  GFP_KERNEL);
	if (!entries) {
		pci_free_irq_vectors(dd->pcidev);
		return -ENOMEM;
	}

	dd->msix_info.msix_entries = entries;
	spin_lock_init(&dd->msix_info.msix_lock);
	bitmap_zero(dd->msix_info.in_use_msix, total);
	dd->msix_info.max_requested = total;
	dd_dev_info(dd, "%u MSI-X interrupts allocated\n", total);

	return 0;
}

/**
 * msix_request_irq() - Allocate a free MSIx IRQ
 * @dd: valid devdata
 * @arg: context information for the IRQ
 * @handler: IRQ handler
 * @thread: IRQ thread handler (could be NULL)
 * @type: affinty IRQ type
 * @name: IRQ name
 *
 * Allocated an MSIx vector if available, and then create the appropriate
 * meta data needed to keep track of the pci IRQ request.
 *
 * Return:
 *   < 0   Error
 *   >= 0  MSIx vector
 *
 */
static int msix_request_irq(struct hfi1_devdata *dd, void *arg,
			    irq_handler_t handler, irq_handler_t thread,
			    enum irq_type type, const char *name)
{
	unsigned long nr;
	int irq;
	int ret;
	struct hfi1_msix_entry *me;

	/* Allocate an MSIx vector */
	spin_lock(&dd->msix_info.msix_lock);
	nr = find_first_zero_bit(dd->msix_info.in_use_msix,
				 dd->msix_info.max_requested);
	if (nr < dd->msix_info.max_requested)
		__set_bit(nr, dd->msix_info.in_use_msix);
	spin_unlock(&dd->msix_info.msix_lock);

	if (nr == dd->msix_info.max_requested)
{
printk("%s: failed, nr %ld, max_requested %d, -ENOSPC\n", __func__, nr, dd->msix_info.max_requested);
		return -ENOSPC;
}

	if (type < IRQ_SDMA || type >= IRQ_OTHER)
		return -EINVAL;

	irq = pci_irq_vector(dd->pcidev, nr);
	ret = pci_request_irq(dd->pcidev, nr, handler, thread, arg, name);
	if (ret) {
		dd_dev_err(dd,
			   "%s: request for IRQ %d failed, MSIx %lx, err %d\n",
			   name, irq, nr, ret);
		spin_lock(&dd->msix_info.msix_lock);
		__clear_bit(nr, dd->msix_info.in_use_msix);
		spin_unlock(&dd->msix_info.msix_lock);
		return ret;
	}

	/*
	 * assign arg after pci_request_irq call, so it will be
	 * cleaned up
	 */
	me = &dd->msix_info.msix_entries[nr];
	me->irq = irq;
	me->arg = arg;
	me->type = type;

	/* affinity is not set up when the general interrupt is requested */
	if (type != IRQ_GENERAL && type != IRQ_BULKSVC_DOORBELL) {
		/* This is a request, so a failure is not fatal */
		ret = hfi1_get_irq_affinity(dd, me);
		if (ret)
			dd_dev_err(dd, "%s: unable to pin IRQ %d, vector %ld\n",
				   name, irq, nr);
	}

	return nr;
}

static int msix_request_rcd_irq_common(struct hfi1_ctxtdata *rcd,
				       irq_handler_t handler,
				       irq_handler_t thread,
				       const char *name)
{
	u32 source;
	int nr;

	nr = msix_request_irq(rcd->dd, rcd, handler, thread,
			      rcd->is_vnic ? IRQ_NETDEVCTXT : IRQ_RCVCTXT,
			      name);
	if (nr < 0)
		return nr;

	/*
	 * Set the interrupt register and mask for this context's interrupt.
	 */
	source = rcd->dd->params->is_rcvavail_start + rcd->ctxt;
	rcd->ireg = source / 64;
	rcd->imask = ((u64)1) << (source % 64);
	rcd->msix_intr = nr;
	remap_intr(rcd->dd, source, nr);

	return 0;
}

/**
 * msix_request_rcd_irq() - Helper function for RCVAVAIL IRQs
 * @rcd: valid rcd context
 *
 */
int msix_request_rcd_irq(struct hfi1_ctxtdata *rcd)
{
	char name[MAX_NAME_SIZE];

	snprintf(name, sizeof(name), DRIVER_NAME "_%d kctxt%d",
		 rcd->dd->unit, rcd->ctxt);

	return msix_request_rcd_irq_common(rcd, receive_context_interrupt,
					   receive_context_thread, name);
}

/**
 * msix_netdev_request_rcd_irq  - Helper function for RCVAVAIL IRQs
 * for netdev context
 * @rcd: valid netdev contexti
 */
int msix_netdev_request_rcd_irq(struct hfi1_ctxtdata *rcd)
{
	char name[MAX_NAME_SIZE];

	snprintf(name, sizeof(name), DRIVER_NAME "_%d nd kctxt%d",
		 rcd->dd->unit, rcd->ctxt);
	return msix_request_rcd_irq_common(rcd, receive_context_interrupt_napi,
					   NULL, name);
}

/**
 * msix_request_sdma_irq  - Helper for getting SDMA IRQ resources
 * @sde: valid sdma engine
 *
 */
int msix_request_sdma_irq(struct sdma_engine *sde)
{
	struct hfi1_devdata *dd = sde->dd;
	int nr;
	char name[MAX_NAME_SIZE];

	snprintf(name, sizeof(name), DRIVER_NAME "_%d sdma%d",
		 dd->unit, sde->this_idx);
	nr = msix_request_irq(dd, sde, sdma_interrupt, sdma_interrupt_thr,
			      IRQ_SDMA, name);
	if (nr < 0)
		return nr;
	sde->msix_intr[0] = nr;

	snprintf(name, sizeof(name), DRIVER_NAME "_%d sdma_progress%d",
		 dd->unit, sde->this_idx);
	nr = msix_request_irq(dd, sde, sdma_progress_interrupt, sdma_progress_interrupt_thr,
			      IRQ_SDMA, name);
	if (nr < 0)
		return nr;
	sde->msix_intr[1] = nr;

	snprintf(name, sizeof(name), DRIVER_NAME "_%d sdma_idle%d",
		 dd->unit, sde->this_idx);
	nr = msix_request_irq(dd, sde, sdma_idle_interrupt, sdma_idle_interrupt_thr,
			      IRQ_SDMA, name);
	if (nr < 0)
		return nr;
	sde->msix_intr[2] = nr;

	remap_sdma_interrupts(dd, sde->this_idx, sde->msix_intr);

	return 0;
}

/**
 * msix_request_general_irq - Helper for getting general IRQ
 * resources
 * @dd: valid device data
 */
int msix_request_general_irq(struct hfi1_devdata *dd)
{
	int nr;
	char name[MAX_NAME_SIZE];

	snprintf(name, sizeof(name), DRIVER_NAME "_%d", dd->unit);
	nr = msix_request_irq(dd, dd, general_interrupt, NULL, IRQ_GENERAL,
			      name);
	if (nr < 0)
		return nr;

	/* general interrupt must be MSIx vector 0 */
	if (nr) {
		msix_free_irq(dd, (u8)nr);
		dd_dev_err(dd, "Invalid index %d for GENERAL IRQ\n", nr);
		return -EINVAL;
	}

	return 0;
}

int msix_request_doorbell_irq(struct hfi1_devdata *dd)
{
	int nr;
	char name[MAX_NAME_SIZE];

	if (!dd->bulksvc)
		return -EINVAL;

	snprintf(name, sizeof(name), DRIVER_NAME "_%d doorbell", dd->unit);
	nr = msix_request_irq(dd, dd->bulksvc, hfi1_bulksvc_doorbell_interrupt, hfi1_bulksvc_doorbell_interrupt_thr, IRQ_BULKSVC_DOORBELL, name);
	dd_dev_dbg(dd, "requsted bulksvc doorbell msix irq, got %d\n", nr);
	if (nr < 0)
		return nr;
	dd->bulksvc->doorbell_msix_intr = nr;
	remap_intr(dd, 330, nr);
	remap_intr(dd, 331, nr);
	return 0;
}

/**
 * enable_sdma_srcs - Helper to enable SDMA IRQ srcs
 * @dd: valid devdata structure
 * @i: index of SDMA engine
 */
static void enable_sdma_srcs(struct hfi1_devdata *dd, int i)
{
	set_intr_bits(dd, dd->params->is_sdma_start + i,
		      dd->params->is_sdma_start + i, true);
	set_intr_bits(dd, dd->params->is_sdma_progress_start + i,
		      dd->params->is_sdma_progress_start + i, true);
	set_intr_bits(dd, dd->params->is_sdma_idle_start + i,
		      dd->params->is_sdma_idle_start + i, true);
	set_intr_bits(dd, dd->params->is_sdmaeng_err_start + i,
		      dd->params->is_sdmaeng_err_start + i, true);
}

/**
 * msix_request_irqs() - Allocate SDMA and receive IRQs
 * @dd: valid devdata structure
 *
 * Helper function to request MSIx IRQs for SDMA and receive.
 */
int msix_request_irqs(struct hfi1_devdata *dd)
{
	struct hfi1_devrsrcs *dr = &dd->rsrcs;
	int i;
	int j;
	int ret;

	/*
	 * The general interrupt has already been requested, but affinity
	 * has not been set due to affinity being initialized after the
	 * interrupt is needed.  Set the affinity here.
	 *
	 * This code expects the general interrupt at index 0.  This is
	 * enforced by msix_request_general_irq().
	 *
	 * This is a request, so a failure is not fatal.
	 */
	ret = hfi1_get_irq_affinity(dd, &dd->msix_info.msix_entries[0]);
	if (ret) {
		dd_dev_err(dd, "general irq: unable to pin IRQ %d, vector 0\n",
			   dd->msix_info.msix_entries[0].irq);
	}

	for (i = dr->first_sdma_engine; i < dr->last_sdma_engine; i++) {
		struct sdma_engine *sde = &dd->per_sdma[i];

		ret = msix_request_sdma_irq(sde);
		if (ret)
			return ret;
		enable_sdma_srcs(sde->dd, i);
	}

	for (i = 0; i < dd->num_pports; i++) {
		struct hfi1_portrsrcs *pr = &dr->ppr[i];

		for (j = 0; j < pr->n_krcv_queues; j++) {
			u16 ctxt = pr->rcv_context_base + j;
			struct hfi1_ctxtdata *rcd = hfi1_rcd_get_by_index(dd, ctxt);

			if (rcd)
				ret = msix_request_rcd_irq(rcd);
			hfi1_rcd_put(rcd);
			if (ret)
				return ret;
		}
	}

	return 0;
}

/**
 * msix_early_request_irqs() - Allocate needed early IRQs.
 * @dd: valid devdata structure
 *
 * Helper function to request an MSIx IRQs for anthing needed early in the
 * device initialize.  Presently, only the general interrupt handler.
 */
int msix_early_request_irqs(struct hfi1_devdata *dd)
{
	int ret;

	ret = msix_request_general_irq(dd);
	if (ret)
		return ret;
	/*
	 * Only VFs can/must init VF2PF IRQs this early.
	 * The PF must wait until CPORT f/w has reset all
	 * resources in start_cport().
	 */
	if (dd->is_vf)
		ret = vf2pf_init_irq(dd);

	return ret;
}

/**
 * msix_free_irq() - Free the specified MSIx resources and IRQ
 * @dd: valid devdata
 * @msix_intr: MSIx vector to free.
 *
 */
void msix_free_irq(struct hfi1_devdata *dd, u8 msix_intr)
{
	struct hfi1_msix_entry *me;

	if (msix_intr >= dd->msix_info.max_requested)
		return;

	me = &dd->msix_info.msix_entries[msix_intr];

	if (!me->arg) /* => no irq, no affinity */
		return;

	hfi1_put_irq_affinity(dd, me);
	pci_free_irq(dd->pcidev, msix_intr, me->arg);

	me->arg = NULL;

	spin_lock(&dd->msix_info.msix_lock);
	__clear_bit(msix_intr, dd->msix_info.in_use_msix);
	spin_unlock(&dd->msix_info.msix_lock);
}

/**
 * msix_clean_up_interrupts  - Free all MSIx IRQ resources
 * @dd: valid device data data structure
 *
 * Free the MSIx and associated PCI resources, if they have been allocated.
 */
void msix_clean_up_interrupts(struct hfi1_devdata *dd)
{
	int i;

	/* remove irqs - must happen before disabling/turning off */
	for (i = 0; i < dd->msix_info.max_requested; i++)
		msix_free_irq(dd, i);

	/* clean structures */
	kfree(dd->msix_info.msix_entries);
	dd->msix_info.msix_entries = NULL;
	dd->msix_info.max_requested = 0;

	pci_free_irq_vectors(dd->pcidev);
}

/*
 * msix_shut_down_interrupts - Free all or most IRQs
 * @dd: device data structure
 * @keep_gen: when true, keep general interrupt
 *
 * Free all IRQs with the possible exception of the general IRQ.  Retain all
 * structures.  This should eventually be followed by a call to
 * msix_clean_up_interrupts().
 */
void msix_shut_down_interrupts(struct hfi1_devdata *dd, bool keep_gen)
{
	struct hfi1_msix_entry *me;
	int i;

	/* remove irqs - must happen before disabling/turning off */
	for (i = 0; i < dd->msix_info.max_requested; i++) {
		me = &dd->msix_info.msix_entries[i];
		if (keep_gen && me->type == IRQ_GENERAL)
			continue;
		msix_free_irq(dd, i);
	}
}

/**
 * msix_netdev_synchronize_irq - netdev IRQ synchronize
 * @ppd: valid port data
 */
void msix_netdev_synchronize_irq(struct hfi1_pportdata *ppd)
{
	int i;
	int ctxt_count = hfi1_netdev_ctxt_count(ppd);

	for (i = 0; i < ctxt_count; i++) {
		struct hfi1_ctxtdata *rcd = hfi1_netdev_get_ctxt(ppd, i);
		struct hfi1_msix_entry *me;

		me = &ppd->dd->msix_info.msix_entries[rcd->msix_intr];

		synchronize_irq(me->irq);
	}
}

int msix_request_irq_remap(struct hfi1_devdata *dd, u16 ctxt,
			   enum irq_type type, int src,
			   irq_handler_t handler, irq_handler_t thread,
			   void *arg, const char *name)
{
	int nr;

	nr = msix_request_irq(dd, arg, handler, thread, type, name);
	if (nr < 0)
		return nr;

	src = dd->params->is_rcvavail_start + ctxt;
	remap_intr(dd, src, nr);
	return nr;
}
