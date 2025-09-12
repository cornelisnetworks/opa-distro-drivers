/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2025 Cornelis Networks.
 */

#include "bulksvc.h"
#include "chip.h"
#include "common.h"
#include "dms.h"
#include "hfi.h"
#include "linux/workqueue.h"
#include "sdma.h"
#include "exp_rcv.h"
#include "trace_dbg.h"
#include "mem_region.h"
#include "verbs_txreq.h"
#include "bulksvc_verbs.h"

#include <linux/string.h>
#include <uapi/rdma/hfi/hfi1_user.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

uint bulksvc_num_sdma = 4;
module_param(bulksvc_num_sdma, uint, S_IRUGO);
MODULE_PARM_DESC(bulksvc_num_sdma,
	"Number of sdma engines to give to bulk service");

uint bulksvc_per_sdma_credits = 392;
module_param(bulksvc_per_sdma_credits, uint, S_IRUGO);
MODULE_PARM_DESC(bulksvc_per_sdma_credits,
	"Number of credits to give to each sdma engine in bulk service");

/* currently unused, rctx comes with a send context */
uint bulksvc_num_sctx = 2;
module_param(bulksvc_num_sctx, uint, S_IRUGO);
MODULE_PARM_DESC(bulksvc_num_sctx,
	"Number of send contexts to give to bulk service");

uint bulksvc_num_rctx = 2;
module_param(bulksvc_num_rctx, uint, S_IRUGO);
MODULE_PARM_DESC(bulksvc_num_rctx,
	"Number of receive contexts per port to give to bulk service");

uint bulksvc_user_queue_size_pages_log2 = 3;
module_param(bulksvc_user_queue_size_pages_log2, uint, S_IRUGO);
MODULE_PARM_DESC(bulksvc_user_queue_size_pages_log2,
	"Size of user queues in pages log2 (default 3, or 8 pages)");

static bool bulksvc_polling_array[32];
static int bulksvc_polling_count;
module_param_array_named(bulksvc_polling, bulksvc_polling_array, bool, &bulksvc_polling_count, S_IRUGO);
MODULE_PARM_DESC(bulksvc_polling, "Whether bulksvc should poll or be event driven per-hfi (default false - non polling)");

static int bulksvc_cpu_array[32];
static int bulksvc_cpu_count;
module_param_array_named(bulksvc_cpu, bulksvc_cpu_array, int, &bulksvc_cpu_count, S_IRUGO);
MODULE_PARM_DESC(bulksvc_cpu,
	"CPU to run bulksvc work on per-hfi, -1 or unset for default behavior (bulksvc chooses CPU on device's numa).");

long bulksvc_progress_interval = 1000; /* 1ms */
module_param(bulksvc_progress_interval, long, S_IRUGO);
MODULE_PARM_DESC(bulksvc_progress_interval,
	"Interval in microseconds to progress bulksvc work when bulksvc_polling is false (default 1ms). 0 or -1 to disable");

// copy from chip.c
#define RSM_TYPE_BULKSVC          6

static void bulksvc_event_work(struct work_struct *work);
static void bulksvc_event_work_eventing(struct work_struct *work);
static void bulksvc_event_work_polling(struct work_struct *work);
static enum hrtimer_restart bulksvc_progress_timer_callback(struct hrtimer *timer);
static int get_bulksvc_cpu(struct hfi1_devdata *dd);
static bool get_bulksvc_polling(struct hfi1_devdata *dd);


// Defined in bulksvc_user.c - should be called from bulksvc event polling thread only
void bulksvc_user_info_destroy(struct hfi1_bulksvc_user_info* info);

static int bulksvc_loan_sdma(struct hfi1_devdata *dd, u32 start, u32 end)
{
	struct hfi1_bulksvc *svc = dd->bulksvc;
	u32 count = end - start; /* should equal prereqs.num_sdma */
	int ret = 0;

	svc->rsrc.sde_arr = kmalloc(sizeof(*svc->rsrc.sde_arr) * count,
				    GFP_KERNEL);
	if (!svc->rsrc.sde_arr) {
		ret = -ENOMEM;
		goto exit;
	}

	/* transfer references from dd to svc */
	for (int i = 0; i < count; i++)
		svc->rsrc.sde_arr[i] = &dd->per_sdma[start + i];

	dd->rsrcs.last_sdma_engine = start;

exit:
	return ret;
}

static void hfi1_bulksvc_return_sdma(struct hfi1_devdata *dd)
{
	u32 ret_count;


	if (!dd->bulksvc || !dd->bulksvc->rsrc.sde_arr)
		return;

	ret_count = dd->bulksvc->prereqs.num_sdma;
	dd->rsrcs.last_sdma_engine += ret_count;
	kfree(dd->bulksvc->rsrc.sde_arr);
	dd->bulksvc->rsrc.sde_arr = NULL;
}

/* does not clean up after itself, call hfi1_bulksvc_teardown on non-zero rc */
static int bulksvc_loan_rctxts(struct hfi1_devdata *dd,
		       struct hfi1_bulksvc_pp_rsrc *pp_loan)
{
	struct hfi1_devrsrcs *dr = &dd->rsrcs;
	struct hfi1_pportdata *ppd;
	struct hfi1_portrsrcs *pr;
	struct hfi1_bulksvc_pp_rsrc *pp_rsrc;
	struct napi_struct *napis;
	u32 cnt;
	int i, ret = 0;

	init_dummy_netdev(&dd->bulksvc->dummy_napi);
	/* store ctxdata pointer for dd->rcd[bulkvc_ctxts] */
	for (i = 0; i < dd->num_pports; i++) {
		ppd = dd->pport + i;
		pr = &dr->ppd[i];
		pp_rsrc = &pp_loan[i];
		cnt = 0;

		pp_rsrc->rcd_len = pr->num_bulksvc_contexts;
		pp_rsrc->rcd = kcalloc(pp_rsrc->rcd_len,
				       sizeof(*pp_rsrc->rcd), GFP_KERNEL);
		if (!pp_rsrc->rcd) {
			ret = -ENOMEM;
			goto bail;
		}

		pp_rsrc->napis = kcalloc(pp_rsrc->rcd_len,
					 sizeof(*pp_rsrc->napis), GFP_KERNEL);
		if (!pp_rsrc->napis) {
			ret = -ENOMEM;
			goto bail;
		}
		napis = pp_rsrc->napis;

		for (u32 ctxt = pr->first_bulksvc_alloc_ctxt;
		     ctxt < pr->first_dyn_alloc_ctxt; ctxt++) {
			struct hfi1_ctxtdata *rcd;
			struct send_context *sc;

			/* use hfi1_create_kctxt despite not being a kctxt */
			if (hfi1_create_kctxt(ppd, ctxt, true)) {
				ret = -EFAULT;
				goto bail;
			}


			rcd = hfi1_rcd_get_by_index(dd, ctxt);
			sc = rcd->sc;
			/* create_kctxt got us a SC_USER send context
			 * to get the resources of a SC_USER but we want
			 * to behave like a kernel send context
			 * IOW we need a shadow ring to use sc_buffer_alloc
			 */
			sc->sr_size = sc->credits + 1;
			sc->sr = kcalloc_node(sc->sr_size,
					      sizeof(union pio_shadow_ring),
					      GFP_KERNEL, dd->node);
			if (!sc->sr) {
				goto bail;
			}

			/* use NAPI like netdev contexts do */
			rcd->napi = napis++;
			set_bit(NAPI_STATE_NO_BUSY_POLL, &rcd->napi->state);
			/* will set bulksvc_rx_napi as bottom half */
			netif_napi_add(&dd->bulksvc->dummy_napi, rcd->napi,
				       hfi1_bulksvc_rx_napi);
			/* will set receive_context_interrupt_napi as top half */
			if (msix_netdev_request_rcd_irq(rcd)) {
				ret = -EFAULT;
				goto bail;
			}

			/* initialize rcd */
			if (hfi1_create_rcvhdrq(dd, rcd) ||
			    hfi1_setup_eagerbufs(rcd) ||
			    hfi1_kern_exp_rcv_init(rcd, false)) {
				hfi1_rcd_put(rcd);
				ret = -EFAULT;
				goto bail;
			}
			/* enable rcd */
			hfi1_enable_kctxt(dd, rcd);
			pp_rsrc->rcd[cnt++] = rcd;
			hfi1_rcd_put(rcd);
			napi_enable(rcd->napi);
		}
	}

	goto exit;
bail:
	dd_dev_err(dd, "%s:%d:%s() bulksvc: Failed to allocate rcv contexts\n",
		   __FILENAME__, __LINE__, __func__);
	if (ret == 0)
		ret = -1;
	for (; i >= 0; i--) {
		ppd = dd->pport + i;
		pr = &dr->ppd[i];
		pp_rsrc = &pp_loan[i];
		if (!pp_rsrc->rcd)
			continue;
		for (u32 ctxt = pr->first_bulksvc_alloc_ctxt; ctxt <
		     pr->first_dyn_alloc_ctxt; ctxt++) {
			if (!dd->rcd[ctxt])
				continue;
			if (dd->rcd[ctxt]->napi) {
				napi_synchronize(dd->rcd[ctxt]->napi);
				napi_disable(dd->rcd[ctxt]->napi);
				netif_napi_del(dd->rcd[ctxt]->napi);
				dd->rcd[ctxt]->napi = NULL;
			}
			hfi1_free_ctxt_rcv_groups(dd->rcd[ctxt]);
			hfi1_free_ctxt(dd->rcd[ctxt]);
		}
		kfree(pp_rsrc->napis);
		kfree(pp_rsrc->rcd);
		pp_rsrc->rcd = NULL;
	}

exit:
	return ret;
}

int hfi1_bulksvc_loan_resources(struct hfi1_devdata *dd)
{
	struct hfi1_bulksvc *svc = dd->bulksvc;
	u32 last = dd->rsrcs.last_sdma_engine;
	u32 sdma_avail = last - dd->rsrcs.first_sdma_engine;
	bool bulksvc_polling = get_bulksvc_polling(dd);
	u32 sdma_rm;
	int ret = 0;

	if (!svc) {
		ret = -1;
		goto exit;
	}

	/* Must leave enough sde's for each VL */
	sdma_rm = svc->prereqs.num_sdma;
	if (!sdma_rm || sdma_rm > sdma_avail ||
		sdma_avail - sdma_rm < num_vls) {
		dd_dev_err(dd, "%s:%d:%s() Not enough sdma engines(%u) to cover VLs(%u) and enable hfisvc (%u)\n",
			   __FILENAME__, __LINE__, __func__,
			   sdma_avail, num_vls, sdma_rm);
		ret = -EINVAL;
		goto fail;
	}
	if (bulksvc_loan_sdma(dd, last - sdma_rm, last)) {
		ret = -EFAULT;
		goto fail;
	}

	/* allocate per port resources structure */
	svc->rsrc.pp = kcalloc(dd->num_pports, sizeof(*svc->rsrc.pp),
			       GFP_KERNEL);
	if (!svc->rsrc.pp) {
		ret = -ENOMEM;
		goto fail;
	}

	if (bulksvc_loan_rctxts(dd, svc->rsrc.pp)) {
		ret = -EFAULT;
		goto fail;
	}

	for (s32 i = 0; i < dd->num_pports; i++) {
		if (!port_available_ppd(&dd->pport[i]))
			continue;

		pr_debug("%s:%d:%s() bulksvc: Setting JKEY %u for port %u\n",
			   __FILENAME__, __LINE__, __func__, HFI1_DMS_JKEY, i);
		hfi1_set_ctxt_jkey(dd, svc->rsrc.pp[i].rcd[0], HFI1_DMS_JKEY);
	}

	if (dd->num_pports < 2) {
		dd_dev_err(dd, "%s:%d:%s() Not enough ports to enable bulk service (%u)\n",
			   __FILENAME__, __LINE__, __func__, dd->num_pports);
	} else {
		hfi1_dms_init(&svc->dms, dd, svc->rsrc.pp[1].rcd, svc->prereqs.num_rcv_ctxs, svc->rsrc.sde_arr,
				sdma_rm);
		bulksvc_rsm_init(svc);
		hfi1_bulksvc_verbs_dms_reg_client_id(&svc->dms);
	}

	/* setup polling event queue */
	/*
	 * Ideally we could set WQ_UNBOUND here in interrupt mode
	 * and then when queue_work_on moves us off the current cpu
	 * that would be fine. However in practice it looks like the
	 * kernel is very happy to move us off numa which is awful for perf
	 * so we'll just keep it as a bounded queue, which means we
	 * should respect bulksvc_cpu even when we are in interrupt mode
	 */
	svc->event_workq = alloc_workqueue("hfi%d-bulksvc-event",
					WQ_MEM_RECLAIM | WQ_CPU_INTENSIVE,
					1, // not sure if this is desired
					dd->unit);
	if (!svc->event_workq) {
		ret = -ENOMEM;
		goto fail;
	}

	if (bulksvc_polling) {
		pr_info("Bulksvc configured to poll\n");
		INIT_WORK(&svc->event_work, bulksvc_event_work_polling);
	} else {
		pr_info("Bulksvc configured to be event driven\n");
		INIT_WORK(&svc->event_work, bulksvc_event_work_eventing);
	}

	INIT_LIST_HEAD(&svc->event_queue);
	spin_lock_init(&svc->event_lock);

	if (bulksvc_polling) {
		queue_work_on(svc->cpu, svc->event_workq, &svc->event_work);
	} else if (svc->timer_interval > 0) {
		hrtimer_start(&svc->progress_timer, svc->timer_interval, HRTIMER_MODE_REL);
	}
	pr_debug("%s:%d:%s() LOANED RESOURCES\n", __FILENAME__, __LINE__, __func__);

	goto exit;

fail:
	hfi1_bulksvc_teardown(dd);
	if (ret == 0)
		ret = -1;
exit:
	return ret;
}

int hfi1_bulksvc_init(struct hfi1_devdata *dd)
{
	bool bulksvc_polling = get_bulksvc_polling(dd);
	struct hfi1_bulksvc_requirements *reqs;
	int bulksvc_cpu = get_bulksvc_cpu(dd);
	const struct cpumask *node_mask;
	unsigned int n_numa_cpus, nth_last_cpu_idx, nth_last_cpu_in_numa;
	int ret = 0;


	dd->bulksvc = kcalloc(sizeof(*dd->bulksvc), 1, GFP_KERNEL);
	if (!dd->bulksvc) {
		ret = -ENOMEM;
		goto exit;
	}

	dd->bulksvc->dd = dd; /* add backref */
	dd->bulksvc->first_rsm_rule = -1;
	dd->bulksvc->first_rsm_index = -1;
	reqs = &dd->bulksvc->prereqs;
	reqs->num_sdma = bulksvc_num_sdma;
	/* sanity checks */
	if (bulksvc_per_sdma_credits < chip_sdma_mem_size(dd) /
				       SDMA_BLOCK_SIZE &&
	    bulksvc_num_rctx < chip_rcv_contexts(dd)) {
		/* force even */
		reqs->credits_per_sdma = bulksvc_per_sdma_credits & ~1;
		reqs->num_rcv_ctxs = bulksvc_num_rctx;
		reqs->num_send_ctxs = bulksvc_num_sctx;
	} else {
		kfree(dd->bulksvc);
		dd->bulksvc = NULL;
		ret = 1;
		goto exit;
	}

	if (bulksvc_cpu != -1) {
		const struct cpumask *node_mask = cpumask_of_node(dd->node);
		const struct cpumask *bulksvc_cpu_mask = cpumask_of(bulksvc_cpu);
		if (!cpumask_intersects(node_mask, bulksvc_cpu_mask)) {
			dd_dev_warn(dd, "module param bulksvc_cpu (%d) is not on the device's numa node (%d). Performance will be affected\n",
					bulksvc_cpu, dd->node);
		}
		dd->bulksvc->cpu = bulksvc_cpu;
	} else {
		/* assign this units bts to the last cpu available in numa */
		node_mask = cpumask_of_node(dd->node);
		n_numa_cpus = cpumask_weight(node_mask);
		nth_last_cpu_idx = n_numa_cpus - (dd->unit % n_numa_cpus) - 1;
		nth_last_cpu_in_numa = cpumask_nth(nth_last_cpu_idx, node_mask);

		dd->bulksvc->cpu = nth_last_cpu_in_numa;
	}
	dd_dev_info(dd, "Bulksvc configured to run on CPU %d\n", dd->bulksvc->cpu);

	if (bulksvc_progress_interval > 0 && !bulksvc_polling) {
		dd->bulksvc->timer_interval = ns_to_ktime(bulksvc_progress_interval * NSEC_PER_USEC);
		hrtimer_init(&dd->bulksvc->progress_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		dd->bulksvc->progress_timer.function =
			bulksvc_progress_timer_callback;
	}

	mutex_init(&dd->bulksvc->user_info_lock);
	INIT_LIST_HEAD(&dd->bulksvc->user_infos);

	hfi1_bulksvc_verbs_state_init(&dd->bulksvc->verbs_state, &dd->bulksvc->dms);

	dd->verbs_dev.rdi.use_bulksvc = true;
	dd->bulksvc->stop_scheduling = false;

	atomic_set(&dd->bulksvc->last_client_key, 0);

exit:
	return ret;
}

static void flush_event_queue(struct hfi1_bulksvc *svc)
{
	struct list_head *entry, *tmp_entry;

	if (list_empty(&svc->event_queue))
		return;

	list_for_each_safe(entry, tmp_entry, &svc->event_queue) {
		list_del(entry);
		kfree(list_entry(entry, struct hfi1_bulksvc_event_entry,
				 list));
	}
}

/* can be called multiple times */
void hfi1_bulksvc_teardown(struct hfi1_devdata *dd)
{
	struct hfi1_bulksvc_user_info *user_info;
	struct hfi1_devrsrcs *dr = &dd->rsrcs;
	struct hfi1_bulksvc *svc;

	/* TODO add logic to wait until it safe to free bulksvc */
	dd->verbs_dev.rdi.use_bulksvc = false;

	if (!dd->bulksvc) {
		return;
	}

	svc = dd->bulksvc;
	svc->stop_scheduling = true;
	if (svc->timer_interval > 0) {
		hrtimer_cancel(&svc->progress_timer);
	}

	if (svc->event_workq) {
		flush_work(&svc->event_work);
		flush_event_queue(svc);
		destroy_workqueue(svc->event_workq);
		svc->event_workq = NULL;
	}

	hfi1_bulksvc_verbs_release_client_id(&dd->bulksvc->dms);
	hfi1_dms_uninit(&dd->bulksvc->dms);

	if (svc->rsrc.sde_arr)
		hfi1_bulksvc_return_sdma(dd);

	mutex_lock(&svc->user_info_lock);
	list_for_each_entry(user_info, &svc->user_infos, list_entry) {
		dd_dev_err(dd, "%s:%d:%s() bulksvc: Lingering user_info %u: %u \n",
		   __FILENAME__, __LINE__, __func__, user_info->client_key, kref_read(&user_info->refcount));
	}
	mutex_unlock(&svc->user_info_lock);
	if (svc->rsrc.pp) {
		/* free any bulksvc rctxts */
		for (u32 i = 0; i < dd->num_pports; i++) {
			struct hfi1_portrsrcs *pr = &dr->ppd[i];

			for (u32 ctxt = pr->first_bulksvc_alloc_ctxt;
			     ctxt < pr->first_dyn_alloc_ctxt; ctxt++) {
				if (!dd->rcd[ctxt])
					continue;
				hfi1_rcvctrl(dd,
					     HFI1_RCVCTRL_CTXT_DIS |
					     HFI1_RCVCTRL_INTRAVAIL_DIS,
					     dd->rcd[ctxt]);
				if (dd->rcd[ctxt]->msix_intr != CCE_NUM_MSIX_VECTORS)
					msix_free_irq(dd, dd->rcd[ctxt]->msix_intr);
				if (dd->rcd[ctxt]->napi) {
					napi_synchronize(dd->rcd[ctxt]->napi);
					napi_disable(dd->rcd[ctxt]->napi);
					netif_napi_del(dd->rcd[ctxt]->napi);
					dd->rcd[ctxt]->napi = NULL;
				}

				dd->rcd[ctxt]->msix_intr = CCE_NUM_MSIX_VECTORS;
				dd->rcd[ctxt]->event_flags = 0;
				hfi1_free_ctxt_rcv_groups(dd->rcd[ctxt]);
				hfi1_free_ctxt(dd->rcd[ctxt]);
			}
			/* release our napi and pointer array */
			kfree(svc->rsrc.pp[i].napis);
			svc->rsrc.pp[i].napis = NULL;
			kfree(svc->rsrc.pp[i].rcd);
			svc->rsrc.pp[i].rcd = NULL;
		}
		kfree(svc->rsrc.pp);
		svc->rsrc.pp = NULL;
	}

	kfree(svc);
	dd->bulksvc = NULL;
}

/* interrupt handler for bulksvc sdma irqs, bulksvc will clear the IRQs if/when it goes to sleep */
void bulksvc_sdma_irq(struct hfi1_devdata *dd, struct sdma_engine *sde)
{
	struct hfi1_bulksvc *svc = dd->bulksvc;

	if (!svc) {
		return;
	}

	hfi1_bulksvc_schedule(svc);
}

/* work queue function */
static int bulksvc_poll_event_queue(struct hfi1_bulksvc *svc)
{
	struct hfi1_bulksvc_event_entry *event_entry, *tmp;
	struct list_head local_list;
	unsigned long flags;
	int processed = 0;

	/* handle events */
	if (!list_empty(&svc->event_queue)) {
		INIT_LIST_HEAD(&local_list);
		spin_lock_irqsave(&svc->event_lock, flags);

		/* reduce time holding lock: move list locally and clear list */
		list_cut_position(&local_list, &svc->event_queue,
				svc->event_queue.prev);

		spin_unlock_irqrestore(&svc->event_lock, flags);

		list_for_each_entry_safe(event_entry, tmp, &local_list, list) {
			list_del(&event_entry->list);
			processed += 1;

			if (event_entry->event.type == BULKSVC_EVENT_TYPE_USER_INFO_ADD) {
				struct hfi1_bulksvc_user_info *user_info = 
					(struct hfi1_bulksvc_user_info *)event_entry->event.data;
				if (WARN_ON(user_info == NULL)) {
					continue;
				}

				if (hfi1_dms_create_client_key(&svc->dms,
								user_info->client_key)) {
					dd_dev_err(svc->dd, "Failed to create DMS client key %u\n",
						user_info->client_key);
					continue;
				}

				// can probably remove this lock soon now that we event to bulksvc
				mutex_lock(&svc->user_info_lock);
				list_add_tail(&user_info->list_entry, &svc->user_infos);
				mutex_unlock(&svc->user_info_lock);

			} else if (event_entry->event.type == BULKSVC_EVENT_TYPE_USER_INFO_RELEASE) {
				struct hfi1_bulksvc_user_info *user_info = (struct hfi1_bulksvc_user_info *)event_entry->event.data;
				if (WARN_ON(user_info == NULL)) {
					continue;
				}
				mutex_lock(&svc->user_info_lock);
				list_del(&user_info->list_entry);
				mutex_unlock(&svc->user_info_lock);

				bulksvc_user_info_destroy(user_info);
			}

			kfree(event_entry);
		}
	}
	return processed;
}

/* work queue function */
static void bulksvc_event_work(struct work_struct *work)
{
	struct hfi1_bulksvc *svc = container_of(work, struct hfi1_bulksvc, event_work);
	int max_iters_per_work = 100;
	int iters = 0;
	int processed = 0;

	do {
		ktime_t const now = ktime_get();

		iters += 1;
		processed = 0;
		processed += bulksvc_poll_event_queue(svc);
		processed += hfi1_dms_poll(&svc->dms, now);
		processed += hfi1_bulksvc_poll_user_cmds(svc);
		processed += hfi1_bulksvc_poll_verbs_cmds(svc);
	} while (iters < max_iters_per_work && processed != 0);

}

static void bulksvc_clear_interrupts(struct hfi1_bulksvc *svc)
{
	struct hfi1_devdata *dd = svc->dd;
	u32 off = 8 * (dd->params->is_sdma_start / 64);

	hfi1_rcd_eoi_intr(svc->dms.rctxt);
	for (int i = 0; i < svc->dms.num_engines; ++i) {
		struct sdma_engine *sde = svc->dms.sdma_engines[i];
		write_csr(dd, dd->params->cce_int_clear_reg + off, sde->imask);
	}
}

/* Polling work queue function that reschedules itself */
static void bulksvc_event_work_polling(struct work_struct *work)
{
	struct hfi1_bulksvc *svc = container_of(work, struct hfi1_bulksvc, event_work);

	bulksvc_event_work(work);
	cond_resched_tasks_rcu_qs();
	hfi1_bulksvc_schedule(svc);

	if (svc->stop_scheduling) {
		synchronize_rcu();
		// we're shutting bulksvc down, clear interrupts for whatever takes over
		bulksvc_clear_interrupts(svc);
	}
}

/* Work queue function when in event-driven mode that handles clearing interrupts when done */
static void bulksvc_event_work_eventing(struct work_struct *work)
{
	struct hfi1_bulksvc *svc = container_of(work, struct hfi1_bulksvc, event_work);

	bulksvc_event_work(work);
	bulksvc_clear_interrupts(svc);
	// do one more pass to ensure we haven't missed an interrupt
	bulksvc_event_work(work);
}

/* Guaranteed progress callback */
static enum hrtimer_restart bulksvc_progress_timer_callback(struct hrtimer *timer)
{
	struct hfi1_bulksvc *svc = container_of(timer, struct hfi1_bulksvc, progress_timer);

	if (svc->stop_scheduling) {
		return HRTIMER_NORESTART;
	}

	hfi1_bulksvc_schedule(svc);

	hrtimer_forward_now(timer, svc->timer_interval);
	return HRTIMER_RESTART;
}

void bulksvc_rsm_reserve(struct hfi1_devdata *dd, struct rsm_map_table *rmt)
{
	struct hfi1_bulksvc *svc = dd->bulksvc;

	BUG_ON(svc == NULL);

	for (int i = 0; i < dd->num_pports; ++i) {
		struct hfi1_pportdata *ppd = &dd->pport[i];
		int rule_index;

		BUG_ON(ppd == NULL);
		rule_index = alloc_rsm_rule(dd, RSM_TYPE_BULKSVC);
		if (rule_index < 0) {
			dd_dev_err(dd, "%s:%d:%s() bulksvc: Failed to allocate RSM rule for port %u\n",
				   __FILENAME__, __LINE__, __func__, i);
			return;
		}
		dd_dev_warn(dd, "%s:%d:%s() bulksvc: Allocated RSM rule %d for port %u\n",
			    __FILENAME__, __LINE__, __func__, rule_index, i);
		if (svc->first_rsm_rule == -1) {
			dd_dev_warn(dd, "%s:%d:%s() bulksvc: Setting first RSM rule to %d\n",
				    __FILENAME__, __LINE__, __func__, rule_index);
			svc->first_rsm_rule = rule_index;
			svc->first_rsm_index = rmt->used;
		}
		rmt->used += 1;
	}
}

static void bulksvc_rsm_write_map_table(struct hfi1_devdata *dd, u8 idx, u8 value)
{
	int regoff = ((int)idx % 8) * 8;
	int regidx = ((int)idx) / 8;
	u64 reg;

	reg = read_csr(dd, dd->params->rcv_rsm_map_table_reg + (8 * regidx));
	reg &= ~(dd->params->rsm_map_table_entry_mask << regoff);
	reg |= ((u64)value) << regoff;
	write_csr(dd, dd->params->rcv_rsm_map_table_reg + (8 * regidx), reg);
}

void bulksvc_rsm_init(struct hfi1_bulksvc *svc)
{
	struct rsm_rule_data rrd;
	struct hfi1_devdata *dd = svc->dd;

	// LRH16B (4 DW) + BTH (3 DW) + KDETH_1 (1 DW)
	u32 const HFI1_DMS_JKEY_OFFSET_LOWER = 256;
	u32 const HFI1_DMS_JKEY_OFFSET_UPPER = 264;

	BUG_ON(svc == NULL);
	BUG_ON(svc->dd == NULL);

	if (svc->first_rsm_rule < 0 || svc->first_rsm_index < 0) {
		dd_dev_err(svc->dd, "%s:%d:%s() bulksvc: No RSM rules reserved, cannot initialize RSM\n",
			   __FILENAME__, __LINE__, __func__);
		return;
	}

	for (int i = 0; i < dd->num_pports; ++i) {
		struct hfi1_pportdata *ppd = &dd->pport[i];
		struct hfi1_ctxtdata *rcd;
		u8 offset;
		int rule_index;

		BUG_ON(ppd == NULL);
		dd_dev_warn(dd, "%s:%d:%s() bulksvc: Checking if port available. i = %d, pidx = %u, ppd = %p",
			    __FILENAME__, __LINE__, __func__, i, ppd->hw_pidx, ppd);
		if (!port_available_ppd(ppd))
			continue;

		dd_dev_warn(dd, "%s:%d:%s() bulksvc: Port %u is available.\n",
			    __FILENAME__, __LINE__, __func__, i);
		BUG_ON(svc->rsrc.pp == NULL);
		if (svc->rsrc.pp[i].rcd_len == 0)
			continue;

		dd_dev_warn(dd, "%s:%d:%s() bulksvc: Registering RSM for port %u\n",
			    __FILENAME__, __LINE__, __func__, i);
		rcd = svc->rsrc.pp[i].rcd[0];
		BUG_ON(rcd == NULL);


		// write RsmMapTable for this index
		offset = (u8)(svc->first_rsm_index + i);
		bulksvc_rsm_write_map_table(dd, offset, rcd->ctxt);

		rule_index = svc->first_rsm_rule + i;
		rrd.offset = offset;
		rrd.pkt_type = RHF_RCV_TYPE_EAGER;
		rrd.pidx_mask = 1 << ppd->hw_pidx;
		rrd.field1_off = HFI1_DMS_JKEY_OFFSET_LOWER;
		rrd.field2_off = HFI1_DMS_JKEY_OFFSET_UPPER;
		rrd.index1_off = 0;
		rrd.index1_width = 0;
		rrd.index2_off = 0;
		rrd.index2_width = 0;
		rrd.mask1 = 0xFF;
		rrd.value1 = HFI1_DMS_JKEY & 0xFF;
		rrd.mask2 = 0xFF;
		rrd.value2 = (HFI1_DMS_JKEY >> 8) & 0xFF;

		add_rsm_rule(svc->dd, rule_index, &rrd);

		dd_dev_warn(dd, "%s:%d:%s() bulksvc: RSM rule %d for port %u registered at offset %u to ctxt %u\n",
			    __FILENAME__, __LINE__, __func__,
			    rule_index, i, offset, rcd->ctxt);
	}

	dd_dev_warn(dd, "%s:%d:%s() bulksvc: Finished registering RSM rules for bulksvc\n",
		    __FILENAME__, __LINE__, __func__);
}

/**
 * hfi1_netdev_rx_napi - napi poll function to move eoi inline
 * @napi: pointer to napi object
 * @budget: netdev budget
 */
int hfi1_bulksvc_rx_napi(struct napi_struct *napi, int budget)
{
	struct hfi1_bulksvc *svc = container_of(napi->dev, struct hfi1_bulksvc, dummy_napi);
	struct hfi1_bulksvc_pp_rsrc *pp_rsrc;
	struct hfi1_ctxtdata *rcd;
	u32 port_idx, svc_rctx_idx = -1;
	int work_done = 0;

	/* do some tricky business to figure out the port that this napi belongs to
	 * since napi stuctures are allocated coherently we can use the address
	 */
	for (port_idx = 0; port_idx < svc->dd->num_pports; port_idx++) {
		pp_rsrc = &svc->rsrc.pp[port_idx];
		if (!pp_rsrc->napis || napi < pp_rsrc->napis ||
		    napi > &pp_rsrc->napis[pp_rsrc->rcd_len - 1])
			continue;
		svc_rctx_idx = napi - pp_rsrc->napis;
		break;
	}

	if (svc_rctx_idx >= pp_rsrc->rcd_len) {
		dd_dev_err(svc->dd, "%s:%d:%s() bulksvc: Napi context %u greater than port %u max %u\n",
			   __FILENAME__, __LINE__, __func__,
			   svc_rctx_idx, port_idx, pp_rsrc->rcd_len);
		napi_complete_done(napi, 0);
		return 0;
	}
	rcd = pp_rsrc->rcd[svc_rctx_idx];

	/* do stuff here: something  like
	 * 	work_done = (some function)
	 * consider overwriting and using the rcd->do_interupt pointer
	 */
	// not sure if this is right but do it for now
	hfi1_bulksvc_schedule(svc);

	/* did not exceed limit, stop polling and rearm interrupts */
	if (work_done < budget) {
		napi_complete_done(napi, work_done);
		// bulksvc will clear this interrupt when it goes back to sleep
		// or if in polling mode we just won't clear this interrupt
		// hfi1_rcd_eoi_intr(rcd);
	}

	return work_done;
}

void hfi1_bulksvc_schedule(struct hfi1_bulksvc *svc)
{
	if (WARN_ON(svc == NULL)) {
		return;
	}

	if (!svc->stop_scheduling) {
		queue_work_on(svc->cpu, svc->event_workq, &svc->event_work);
	}
}

bool hfi1_bulksvc_requires_doorbell(struct hfi1_bulksvc *svc)
{
	bool polling_mode = get_bulksvc_polling(svc->dd);
	return !polling_mode;
}

int hfi1_bulksvc_enqueue_event(struct hfi1_bulksvc *svc, struct hfi1_bulksvc_event_entry *entry)
{
	unsigned long flags;

	if (WARN_ON(svc == NULL || entry == NULL)) {
		return -EINVAL;
	}

	spin_lock_irqsave(&svc->event_lock, flags);
	list_add_tail(&entry->list,
				&svc->event_queue);
	spin_unlock_irqrestore(&svc->event_lock, flags);

	return 0;
}

static int get_bulksvc_cpu(struct hfi1_devdata *dd)
{
	int start = dd->unit;
	int cpu;

	/* check if enough elements are set for this unit's port */
	if (start >= bulksvc_cpu_count)
		return -1;

	cpu = bulksvc_cpu_array[start];
	if (cpu >= nr_cpu_ids || cpu < -1) {
		dd_dev_warn(dd, "bulksvc_cpu %d for unit %d invalid, ignoring value", cpu, start);
		cpu = -1;
	}
	return cpu;
}

static bool get_bulksvc_polling(struct hfi1_devdata *dd)
{
	int start = dd->unit;

	if (start >= bulksvc_polling_count)
		return false;

	return bulksvc_polling_array[start];
}
