// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2024 - Cornelis Networks, Inc.
 *
 * SR-IOV related functions and variables.
 */

#include <linux/pci.h>

#include "hfi.h"
#include "sriov.h"
#include "chip_jkr.h"
#include "chip_gen.h"
#include "vf2pf.h"

#define HFI_SRIOV_DEBUG
#define HFI_SRIOV_BRINGUP
#define HFI_SRIOV_MOD_PARAMS	/* use module params to define SRIOV config */
#undef HFI_SRIOV_AUTO_CONF	/* automatically enable SRIOV if max_num_vfs > 0 */

bool sriov_auto; /* might default to 'true' in the future */
module_param_named(sriov_auto, sriov_auto, bool, 0644);
MODULE_PARM_DESC(sriov_auto, "Start SRIOV automatically, default N (off)");

#ifdef HFI_SRIOV_BRINGUP
bool vf_test;
module_param_named(vf_test, vf_test, bool, 0644);
MODULE_PARM_DESC(vf_test, "Enable host VF PCI device, default N (off)");

bool vf_claim;
module_param_named(vf_claim, vf_claim, bool, 0644);
MODULE_PARM_DESC(vf_claim, "Claim VF PCI devices on host");
#endif

#ifdef HFI_SRIOV_MOD_PARAMS
static uint max_num_vfs;
module_param_named(max_num_vfs, max_num_vfs, uint, 0444);
MODULE_PARM_DESC(max_num_vfs, "Allow SRIOV and specify max num VFs");
#endif

/*
 * Free all SRIOV configuration resources. Called during
 * driver unload.
 *
 * Resets SiIdx CSRs as well as freeing memory.
 */
void hfi1_sriov_free_cfg(struct hfi1_devdata *dd)
{
	/* TODO: free resources back to PF0 */
}

/* NOTE:
 * There are three types of PCI devices when using SRIOV and VMs:
 *	in host OS, there is the PF0 pci_dev (pdev->is_physfn != 0)
 *	in host OS, there is the VFx pci_dev (pdev->is_virtfn != 0)
 *		(this will never have a 'dd'?)
 *	in guest OS, there is the VFx pci_dev (PCI_FUNC(pdev->devfn) != 0?)
 *		(what do pdev->is_physfn and pdev->is_virtfn mean?
 *		since pdev->physfn cannot be valid - nor pdev->sriov?)
 *		(this needs to have a 'dd' but handled different)
 *
 * TODO: how to determine whether we're host or guest?!
 *	PCI_FUNC(pdev->devfn) != 0 && !pdev->is_virtfn for guest VFs?
 *
 * TODO: does PCI_FUNC() need to be something different if ARI is active?
 */

int sriov_is_enabled(void)
{
#ifdef HFI_SRIOV_MOD_PARAMS
	return max_num_vfs > 0;
#else
	/* TODO: how to determine SRIOV is allowed */
	return 0;
#endif
}

/*
 * This initializes the host VF PCI device - not SRIOV from PF0.
 *
 * Normally, the VF devices will be pass-through to VMs, in which
 * case the host driver does not want to claim the device.
 * TODO: Does KVM (virtsh) tolerate the driver claiming the VF,
 * by calling the remove_one() function when assigning the device
 * to the guest? If so, we can go ahead and claim the device here,
 * however that will cause a complete setup (and tear-down) of a 'dd' for it.
 *
 * pdev is the VF. Only called from host driver.
 */
int hfi1_sriov_init(struct pci_dev *pdev)
{
	int ret;

#ifdef CONFIG_HFI_L8SIM
	ret = sim_sriov_fixup(pdev);
	if (ret)
		dev_warn(&pdev->dev, "SRIOV simpci fixup failed %d\n", ret);
		/* continue, even though it probably won't work */
#endif
#ifdef HFI_SRIOV_BRINGUP
	if (vf_test) {
		ret = pci_enable_device(pdev);
		if (ret) {
			dev_err(&pdev->dev, "SRIOV pci enable failed %d\n", ret);
			return ret;
		}
		pci_set_master(pdev);
	}
	ret = vf_claim ? 0 : -ENODEV;
#else
	ret = -ENODEV;
#endif
	/*
	 * If not claimed then remove_one()/hfi1_sriov_remove() will never be called.
	 */

	/* pci_num_vf(pdev->physfn) is not valid until later, so can't use it */
#ifdef HFI_SRIOV_DEBUG
	dev_info(&pdev->dev, "probing VF%d (%d)\n", pci_iov_vf_id(pdev) + 1, ret);
	dev_warn(&pdev->dev, "is_vm=%d is_vf=%d is_physfn=%d is_virtfn=%d physfn=%p\n",
#if defined(CONFIG_X86)
		 boot_cpu_has(X86_FEATURE_HYPERVISOR),
#else
		 -1,
#endif
		 !pdev->pm_cap, pdev->is_physfn, pdev->is_virtfn, pdev->physfn);
#endif

	return ret;
}

void hfi1_sriov_remove(struct pci_dev *pdev)
{
#ifdef HFI_SRIOV_DEBUG
	dev_info(&pdev->dev, "removing VF%d\n", pci_iov_vf_id(pdev) + 1);
#endif
}

/*
 * This disables SRIOV from PF0, if it was enabled.
 *
 * pdev is PF0. The driver is about to release this PF0.
 */
int hfi1_sriov_disable(struct pci_dev *pdev)
{
	pci_disable_sriov(pdev);
	return 0;
}

/*
 * Deconfigure SRIOV on PF0. The driver may continue to run on PF0.
 */
static int hfi1_sriov_deconfigure(struct hfi1_devdata *dd)
{
	/* TODO: do paranoid cleanup? */
	pci_disable_sriov(dd->pcidev);
	hfi1_pf0_cleanup(dd);
	return 0;
}

/* TODO: any setup required for RPMSG, etc.
 *
 * pdev is PF0.
 */
int hfi1_sriov_configure(struct pci_dev *pdev, int nvf)
{
	struct hfi1_devdata *dd = pci_get_drvdata(pdev);
	int ret;

	if (!nvf)
		return hfi1_sriov_deconfigure(dd);

	/* prepare VF resources (contexts) for creation of VFs */
	ret = vf2pf_prep(dd);
	if (ret)
		return ret;

	ret = pci_enable_sriov(pdev, nvf);
	if (ret < 0) {
		hfi1_sriov_deconfigure(dd);
		return ret;
	}
	return nvf;
}

/*
 * Enables SRIOV if max_num_vfs > 0.
 *
 * Called at the very end of PF0 initialization (init_one()).
 */
int hfi1_sriov_auto_conf(struct hfi1_devdata *dd)
{
	int ret = 0;

	if (!max_num_vfs)
		return ret;

	if (sriov_auto) {
		ret = hfi1_sriov_configure(dd->pcidev, max_num_vfs);
		if (ret)
			dd_dev_err(dd, "hfi1_sriov_configure(%d) failed (%d).\n",
				   max_num_vfs, ret);
	}
	return ret;
}
