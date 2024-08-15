# SPDX-License-Identifier: GPL-2.0
#
# HFI driver
#
#
#
# Called from the kernel module build system.
#
obj-$(CONFIG_INFINIBAND_HFI1) += hfi1.o

hfi1-y := \
	affinity.o \
	aspm.o \
	chip.o \
	device.o \
	diag.o \
	driver.o \
	efivar.o \
	eprom.o \
	exp_rcv.o \
	file_ops.o \
	firmware.o \
	init.o \
	intr.o \
	iowait.o \
	ipoib_main.o \
	ipoib_rx.o \
	ipoib_tx.o \
	mad.o \
	mmu_rb.o \
	msix.o \
	netdev_rx.o \
	opfn.o \
	pcie.o \
	pinning.o \
	pin_system.o \
	pio.o \
	pio_copy.o \
	platform.o \
	qp.o \
	qsfp.o \
	rc.o \
	ruc.o \
	sdma.o \
	sysfs.o \
	tid_rdma.o \
	tid_system.o \
	trace.o \
	uc.o \
	ud.o \
	user_exp_rcv.o \
	user_pages.o \
	user_sdma.o \
	verbs.o \
	verbs_txreq.o \
	vnic_main.o \
	vnic_sdma.o

ifdef CONFIG_DEBUG_FS
hfi1-y += debugfs.o
ifdef CONFIG_FAULT_INJECTION
ifdef CONFIG_FAULT_INJECTION_DEBUG_FS
hfi1-y += fault.o
endif
endif
endif

CFLAGS_trace.o = -I$(src)
ifdef MVERSION
CFLAGS_driver.o = -DHFI_DRIVER_VERSION_BASE=\"$(MVERSION)\"
endif

ifdef CONFIG_HFI1_NVIDIA
hfi1-y += pin_nvidia.o
ifndef NVIDIA_DRIVER_SOURCE
# E.g. from nvidia-driver:open-dkms
#   $ rpm -ql --whatprovides nvidia-kmod | grep 'nv-p2p.h'
#   /usr/src/nvidia-open-560.28.03/nvidia-peermem/nv-p2p.h
#   /usr/src/nvidia-open-560.28.03/nvidia/nv-p2p.h
# From nvidia-driver:latest-dkms
#   $ rpm -ql --whatprovides nvidia-kmod | grep 'nv-p2p.h'
#   /usr/src/nvidia-555.42.06/nvidia-peermem/nv-p2p.h
#   /usr/src/nvidia-555.42.06/nvidia/nv-p2p.h
NVIDIA_DRIVER_SOURCE := $(realpath $(dir $(shell rpm -ql --whatprovides nvidia-kmod | grep 'nvidia/nv-p2p.h'))/..)
endif
CFLAGS_pin_nvidia.o += -I$(NVIDIA_DRIVER_SOURCE)
endif

hfi1-$(CONFIG_HFI1_NVIDIA) += pin_nvidia.o tid_nvidia.o gdr_ops.o
ccflags-$(CONFIG_HFI1_NVIDIA) += -I$(NVIDIA_DRIVER_SOURCE) -DNVIDIA_GPU_DIRECT

ifdef CONFIG_HFI1_AMD
ifndef AMDGPU_DRIVER_SOURCE
AMDGPU_DRIVER_SOURCE := $(shell rpm -ql amdgpu-dkms | grep -E '/usr/src/amdgpu-[^/]+/include/drm/amd_rdma.h$$' | head -n1)
AMDGPU_DRIVER_SOURCE := $(subst /include/drm/amd_rdma.h,,$(AMDGPU_DRIVER_SOURCE))
endif
endif
hfi1-$(CONFIG_HFI1_AMD) += pin_amd.o tid_amd.o
ccflags-$(CONFIG_HFI1_AMD) += -I$(AMDGPU_DRIVER_SOURCE)/include
ccflags-$(CONFIG_HFI1_AMD) += -DCONFIG_HFI1_AMD
