/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 *
 * SRIOV support
 */

#ifndef _SRIOV_H
#define _SRIOV_H

#include <linux/pci.h>
#include "hfi.h"

void hfi1_sriov_free_cfg(struct hfi1_devdata *dd);
void hfi1_sriov_free_rsrcs(struct hfi1_devdata *dd, struct hfi1_devrsrcs *vfr);

int hfi1_sriov_init(struct pci_dev *pdev);
void hfi1_sriov_remove(struct pci_dev *pdev);
int hfi1_sriov_configure(struct pci_dev *pdev, int nvf);
int hfi1_sriov_auto_conf(struct hfi1_devdata *dd);

int hfi1_sriov_disable(struct pci_dev *pdev);

int sriov_is_enabled(void);

#endif /* _SRIOV_H */
