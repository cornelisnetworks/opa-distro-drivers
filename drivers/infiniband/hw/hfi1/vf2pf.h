/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 *
 * SRIOV support
 */

#ifndef _VF2PF_H
#define _VF2PF_H

#include "hfi.h"

#define VF2PF_SI_ALL	(-1)

int vf2pf_init(struct hfi1_devdata *dd);
int vf2pf_prep(struct hfi1_devdata *dd);
void vf2pf_deinit(struct hfi1_devdata *dd);
int vf2pf_init_irq(struct hfi1_devdata *dd);
void vf2pf_deinit_irq(struct hfi1_devdata *dd);
int vf2pf_num_ctxts(struct hfi1_devdata *dd);
int vf2pf_num_irq(struct hfi1_devdata *dd);
int vf2pf_probe_si(struct hfi1_devdata *dd);
void vf2pf_init_sysfs(struct hfi1_devdata *dd, struct device *class_dev);
int vf2pf_sysfs_emit_at(struct hfi1_devdata *dd, char *buf, int at);
void vf2pf_set_si_enables(struct hfi1_devdata *dd, int si,
			  void (*si_enables)(struct hfi1_devdata *dd,
					     u64 base, u32 start, u32 end));

/*
 * Add vf2pf_* methods here, to request actions from PF0
 *
 * int vf2pf_some-action(struct hfi1_devdata *dd, struct something *arg...);
 */
void vf2pf_ready(struct hfi1_devdata *dd);

#endif /* _VF2PF_H */
