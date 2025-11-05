/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2025 Cornelis Networks.
 */
#ifndef DEF_HFI1_BULKSVC_H
#define DEF_HFI1_BULKSVC_H

#include "hfi.h"
#include "dms.h"
#include "bulksvc_user.h"
#include "bulksvc_verbs.h"
#include "linux/irqreturn.h"

struct rsm_map_table;

/* requirements defined prior to resource allocation */
struct hfi1_bulksvc_requirements {
	u32 num_sdma;
	u32 credits_per_sdma;
	u32 num_send_ctxs; /* are these per port? */
	u32 num_rcv_ctxs;
};

/* per port resources */
struct hfi1_bulksvc_pp_rsrc {
	u32 rcd_len;
	struct hfi1_ctxtdata **rcd; /* sized to  prereqs.num_rctxts */
	struct napi_struct *napis; /* indexs map to rcd indexs */
};

/* resources given to the service.
 * do not free these structures.
 */
struct hfi1_bulksvc_resource_loan {
	/* sized to prereqs.num_sdma, allocation implies ownership */
	struct sdma_engine **sde_arr;
	struct hfi1_bulksvc_pp_rsrc *pp; /* sized to num_ports */
};

enum hfi1_bulksvc_event_type {
  BULKSVC_EVENT_TYPE_SDMA = 0,
  BULKSVC_EVENT_TYPE_USER_INFO_ADD,
  BULKSVC_EVENT_TYPE_USER_INFO_RELEASE,
};

struct hfi1_bulksvc_event {
  enum hfi1_bulksvc_event_type type;
  union {
	struct hfi1_bulksvc_user_info *user_info;
  };
} __attribute__((packed, aligned(64)));

struct hfi1_bulksvc_event_entry {
	struct hfi1_bulksvc_event event;
	struct list_head list;
};

struct hfi1_bulksvc {
	struct hfi1_devdata *dd; /* pointer to device setting up the service */
	struct hfi1_bulksvc_requirements prereqs;
	struct hfi1_bulksvc_resource_loan rsrc;
	struct hfi1_dms dms;
	struct mmu_rb_handler *mmu_handler;
	/* event queue things */
	bool stop_scheduling;
	spinlock_t event_lock;
	struct list_head event_queue;
	struct work_struct event_work;
	struct workqueue_struct *event_workq;

	struct hrtimer progress_timer;
	ktime_t timer_interval;

	struct mutex user_info_lock;
	struct list_head user_infos;

	struct hfi1_bulksvc_verbs_state verbs_state;

	/* dummy netdev for napi, should probably be last in struct */
	struct net_device dummy_napi;

	int first_rsm_rule;
	int first_rsm_index;

	atomic_t last_client_key;

	int cpu; /* cpu to run on when scheduled */
	int doorbell_msix_intr;

	// If 0, nothing to do.  If 1, bulksvc should replace with an owning char* to debug output buffer
	atomic64_t debug_info_buf_ptr;
};

/* setup data structures, define requirements */
int hfi1_bulksvc_init(struct hfi1_devdata *dd);

/* loan sdma's/contexts to the service */
int hfi1_bulksvc_loan_resources(struct hfi1_devdata *dd);

/* Disable bulksvc, return (or free) all resources to the hfi1 device */
void hfi1_bulksvc_teardown(struct hfi1_devdata *dd);

/* sdma irq handler */
void bulksvc_sdma_irq(struct hfi1_devdata *dd, struct sdma_engine *sde);

/* rctxt napi poll function */
int hfi1_bulksvc_rx_napi(struct napi_struct *napi, int budget);

/* Wake up the bulksvc workqueue */
void hfi1_bulksvc_schedule(struct hfi1_bulksvc *svc);

/* Whether `hfi1_bulksvc_doorbell` is required to be invoked */
bool hfi1_bulksvc_requires_doorbell(struct hfi1_bulksvc *svc);

/* called during rsm init but before loan_resources */
void bulksvc_rsm_reserve(struct hfi1_devdata *dd, struct rsm_map_table *rmt);

/* bulksvc rsm init */
void bulksvc_rsm_init(struct hfi1_bulksvc *svc);

int hfi1_bulksvc_enqueue_event(struct hfi1_bulksvc *svc, struct hfi1_bulksvc_event_entry *entry);

/* Bulksvc doorbell handlers */
irqreturn_t hfi1_bulksvc_doorbell_interrupt(int irq, void *data);
irqreturn_t hfi1_bulksvc_doorbell_interrupt_thr(int irq, void *data);

/* 
 * Collects bulksvc info into human-readable output, must be called from bulksvc thread.  Will 
 * be called if debug_info_buf_ptr == 1
 */
char* hfi1_bulksvc_prepare_debug_info(struct hfi1_bulksvc *svc);

#endif          /* DEF_HFI1_BULKSVC_H */
