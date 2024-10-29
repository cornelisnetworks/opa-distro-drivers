// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2015 - 2020 Intel Corporation.
 * Copyright(c) 2021-2024 Cornelis Networks.
 */

#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/xarray.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/hrtimer.h>
#include <linux/bitmap.h>
#include <linux/numa.h>
#include <rdma/rdma_vt.h>

#include "hfi.h"
#include "file_ops.h"
#include "device.h"
#include "common.h"
#include "trace.h"
#include "mad.h"
#include "sdma.h"
#include "debugfs.h"
#include "verbs.h"
#include "aspm.h"
#include "affinity.h"
#include "vnic.h"
#include "exp_rcv.h"
#include "netdev.h"
#include "chip_jkr.h"
#include "chip_gen.h"
#include "pinning.h"
#include "cport_traps.h"
#include "bulksvc.h"
#include "sriov.h"

#ifdef NVIDIA_GPU_DIRECT
#include "gdr_ops.h"
#endif

#undef pr_fmt
#define pr_fmt(fmt) DRIVER_NAME ": " fmt

#undef CPORT_TRAP_DEBUG	/* all MCTXT TRAP events from CPORT */
#define PDEV_SRIOV_DEBUG

/*
 * min buffers we want to have per context, after driver
 */
#define HFI1_MIN_USER_CTXT_BUFCNT 7

#define HFI1_MIN_EAGER_BUFFER_SIZE (4 * 1024) /* 4KB */
#define HFI1_MAX_EAGER_BUFFER_SIZE (256 * 1024) /* 256KB */

static void wfr_start_port(struct hfi1_pportdata *ppd);
static void wfr_stop_port(struct hfi1_pportdata *ppd);
static void destroy_workqueues(struct hfi1_devdata *dd);

/* parameters for the WFR ASIC */
static const struct chip_params wfr_params = {
	.chip_type = CHIP_WFR,
	.num_ports = 1,
	.dma_mask_bits = 48,

	/* BAR0 map: rcv array splits kreg1 and kreg2 */
	.bar0_size = TXE_PIO_SEND + TXE_PIO_SIZE,
	.kreg1_size = RCV_ARRAY,
	.kreg2_offset = RCV_ARRAY + RCV_ARRAY_SIZE,
	.kreg2_size = TXE_PIO_SEND - (RCV_ARRAY + RCV_ARRAY_SIZE),
	.rcv_array_offset = RCV_ARRAY,
	.rcv_array_size = RCV_ARRAY_SIZE,

	.link_speed_supported = OPA_LINK_SPEED_25G,
	.link_speed_active = OPA_LINK_SPEED_25G,
	.asic_cclock_ps = ASIC_CCLOCK_PS,
	.rsm_rule_size = WFR_RXE_NUM_RSM_INSTANCES,
	.rsm_rule_offset_shift = WFR_RCV_RSM_CFG_OFFSET_SHIFT,
	.rsm_map_table_entries = 256,
	.rsm_map_table_entries_per_csr = 8,
	.rsm_map_table_entry_mask = 0xff,
	.rsm_map_table_entry_shift = 8,
	.qp_map_table_entries = 256,
	.qp_map_table_entries_per_csr = 8,
	.qp_map_table_entry_mask = 0xff,
	.qp_map_table_entry_shift = 8,
	.pkey_table_size = WFR_MAX_PKEY_VALUES,
	.generic_boardname = "Cornelis Omni-Path Host Fabric Interface Adapter 100 Series",
	.max_eager_entries = WFR_MAX_EAGER_ENTRIES,
	.pio_base_bits = WFR_PIO_BASE_BITS,
	.pio_base_shift = WFR_SEND_CTXT_CTRL_CTXT_BASE_SHIFT,
	.egress_err_info_data = &wfr_egress_err_info_data,
	.send_ctrl_flush = 0, /* no flush flag available */
	.port_discard_egress_errs = WFR_PORT_DISCARD_EGRESS_ERRS,

	/* interrupt sources */
	.num_int_csrs = WFR_CCE_NUM_INT_CSRS,
	.num_int_map_csrs = WFR_CCE_NUM_INT_MAP_CSRS,
	.is_rcvavail_start = IS_RCVAVAIL_START,
	.is_rcvurgent_start = IS_RCVURGENT_START,
	.is_sdmaeng_err_start = IS_SDMAENG_ERR_START,
	.is_sdma_idle_start = IS_SDMA_IDLE_START,
	.is_sdma_progress_start = IS_SDMA_PROGRESS_START,
	.is_sdma_start = IS_SDMA_START,
	.is_last_source = IS_LAST_SOURCE,
	.is_table = is_table,
	.gi_enable_table = wfr_gi_enable_table,

	/* cce_interrupt registers */
	.cce_int_status_reg = WFR_CCE_INT_STATUS,
	.cce_int_mask_reg = WFR_CCE_INT_MASK,
	.cce_int_clear_reg = WFR_CCE_INT_CLEAR,
	.cce_int_force_reg = WFR_CCE_INT_FORCE,
	.cce_int_blocked_reg = WFR_CCE_INT_BLOCKED,

	/* counters */
	.chip_dev_cntrs = wfr_dev_cntrs,
	.chip_dev_cntr_first = WFR_DEV_CNTR_FIRST,
	.chip_num_dev_cntrs = WFR_NUM_DEV_CNTRS,
	.chip_port_cntrs = wfr_port_cntrs,
	.chip_port_cntr_first = WFR_PORT_CNTR_FIRST,
	.chip_num_port_cntrs = WFR_NUM_PORT_CNTRS,

	/* ingress port registers */
	.rxe_iport_stride = 0,
	.rcv_iport_ctrl_reg = WFR_RCV_CTRL,
	.rcv_iport_status_reg = WFR_RCV_STATUS,
	.rcv_bth_qp_reg = WFR_RCV_BTH_QP,
	.rcv_multicast_reg = WFR_RCV_MULTICAST,
	.rcv_bypass_reg = WFR_RCV_BYPASS,
	.rcv_vl15_reg = WFR_RCV_VL15,
	.rcv_err_info_reg = WFR_RCV_ERR_INFO,
	.rcv_err_status_reg = WFR_RCV_ERR_STATUS,
	.rcv_err_mask_reg = WFR_RCV_ERR_MASK,
	.rcv_err_clear_reg = WFR_RCV_ERR_CLEAR,
	.rcv_qp_map_table_reg = WFR_RCV_QP_MAP_TABLE,
	.rcv_partition_key_reg = WFR_RCV_PARTITION_KEY,
	.rcv_counter_array32_reg = WFR_RCV_COUNTER_ARRAY32,
	.rcv_counter_array64_reg = WFR_RCV_COUNTER_ARRAY64,

	/* ingress port receive context registers */
	.rxe_iprc_stride = WFR_RXE_IPRC_STRIDE,
	.rcv_jkey_ctrl_reg = WFR_RCV_KEY_CTRL,

	/* RXE restricted context registers */
	.rxe_rctxt_stride = WFR_RXE_RCTXT_STRIDE,
	.rcv_rctxt_ctrl_reg = WFR_RCV_CTXT_CTRL,
	.rcv_egr_ctrl_reg = WFR_RCV_EGR_CTRL,
	.rcv_tid_ctrl_reg = WFR_RCV_TID_CTRL,

	/* RXE kernel context registers */
	.rxe_kctxt_stride = WFR_RXE_KCTXT_STRIDE,
	.rcv_kctxt_ctrl_reg = WFR_RCV_CTXT_CTRL,
	.rcv_hdr_addr_reg = WFR_RCV_HDR_ADDR,
	.rcv_hdr_cnt_reg = WFR_RCV_HDR_CNT,
	.rcv_hdr_ent_size_reg = WFR_RCV_HDR_ENT_SIZE,
	.rcv_hdr_tail_addr_reg = WFR_RCV_HDR_TAIL_ADDR,
	.rcv_avail_time_out_reg = WFR_RCV_AVAIL_TIME_OUT,
	.rcv_hdr_ovfl_cnt_reg = WFR_RCV_HDR_OVFL_CNT,

	/* RXE kernel/user registers */
	.rxe_ku_stride = WFR_RXE_KCTXT_STRIDE,
	.rcv_ctxt_status_reg = WFR_RCV_CTXT_STATUS,

	/* RXE user registers */
	.rxe_uctxt_stride = WFR_RXE_UCTXT_STRIDE,
	.rcv_hdr_tail_reg = WFR_RCV_HDR_TAIL,
	.rcv_hdr_head_reg = WFR_RCV_HDR_HEAD,
	.rcv_egr_index_head_reg = WFR_RCV_EGR_INDEX_HEAD,
	.rcv_tid_flow_table_reg = WFR_RCV_TID_FLOW_TABLE,

	/* RXE RSM registers */
	.rcv_rsm_cfg_reg = WFR_RCV_RSM_CFG,
	.rcv_rsm_select_reg = WFR_RCV_RSM_SELECT,
	.rcv_rsm_match_reg = WFR_RCV_RSM_MATCH,
	.rcv_rsm_map_table_reg = WFR_RCV_RSM_MAP_TABLE,

	/* TXE kernel registers */
	.send_contexts_reg = SEND_CONTEXTS,
	.send_dma_engines_reg = WFR_SEND_DMA_ENGINES,
	.send_pio_mem_size_reg = WFR_SEND_PIO_MEM_SIZE,
	.send_dma_mem_size_reg = WFR_SEND_DMA_MEM_SIZE,
	.send_pio_init_ctxt_reg = WFR_SEND_PIO_INIT_CTXT,

	/* send context_registers */
	.txe_sctxt_stride = WFR_TXE_SCTXT_STRIDE,
	.send_ctxt_status_reg = WFR_SEND_CTXT_STATUS,
	.send_ctxt_credit_ctrl_reg = WFR_SEND_CTXT_CREDIT_CTRL,
	.send_ctxt_credit_status_reg = WFR_SEND_CTXT_CREDIT_STATUS,
	.send_ctxt_credit_return_addr_reg = WFR_SEND_CTXT_CREDIT_RETURN_ADDR,
	.send_ctxt_credit_force_reg = WFR_SEND_CTXT_CREDIT_FORCE,
	.send_ctxt_err_status_reg = WFR_SEND_CTXT_ERR_STATUS,
	.send_ctxt_err_mask_reg = WFR_SEND_CTXT_ERR_MASK,
	.send_ctxt_err_clear_reg = WFR_SEND_CTXT_ERR_CLEAR,

	/* TXE send context registers */
	.txe_tctxt_stride = WFR_TXE_TCTXT_STRIDE,
	.send_ctxt_ctrl_reg = WFR_SEND_CTXT_CTRL,

	/* SDMA registers */
	.txe_sdma_stride = WFR_TXE_SDMA_STRIDE,
	.send_dma_ctrl_reg = WFR_SEND_DMA_CTRL,
	.send_dma_status_reg = WFR_SEND_DMA_STATUS,
	.send_dma_base_addr_reg = WFR_SEND_DMA_BASE_ADDR,
	.send_dma_len_gen_reg = WFR_SEND_DMA_LEN_GEN,
	.send_dma_tail_reg = WFR_SEND_DMA_TAIL,
	.send_dma_head_reg = WFR_SEND_DMA_HEAD,
	.send_dma_head_addr_reg = WFR_SEND_DMA_HEAD_ADDR,
	.send_dma_priority_thld_reg = WFR_SEND_DMA_PRIORITY_THLD,
	.send_dma_idle_cnt_reg = WFR_SEND_DMA_IDLE_CNT,
	.send_dma_reload_cnt_reg = WFR_SEND_DMA_RELOAD_CNT,
	.send_dma_desc_cnt_reg = WFR_SEND_DMA_DESC_CNT,
	.send_dma_desc_fetched_cnt_reg = WFR_SEND_DMA_DESC_FETCHED_CNT,
	.send_dma_eng_err_status_reg = WFR_SEND_DMA_ENG_ERR_STATUS,
	.send_dma_eng_err_mask_reg = WFR_SEND_DMA_ENG_ERR_MASK,
	.send_dma_eng_err_clear_reg = WFR_SEND_DMA_ENG_ERR_CLEAR,

	/* SDMA Config registers */
	.txe_sdmacfg_stride = WFR_TXE_SDMACFG_STRIDE,
	.send_dma_cfg_memory_reg = WFR_SEND_DMA_MEMORY,

	/* egress port registers */
	.txe_eport_stride = 0,
	.send_ctrl_reg = SEND_CTRL,
	.send_high_priority_limit_reg = WFR_SEND_HIGH_PRIORITY_LIMIT,
	.send_egress_err_status_reg = WFR_SEND_EGRESS_ERR_STATUS,
	.send_egress_err_mask_reg = WFR_SEND_EGRESS_ERR_MASK,
	.send_egress_err_clear_reg = WFR_SEND_EGRESS_ERR_CLEAR,
	.send_bth_qp_reg = WFR_SEND_BTH_QP,
	.send_static_rate_control_reg = WFR_SEND_STATIC_RATE_CONTROL,
	.send_sc2vlt0_reg = WFR_SEND_SC2VLT0,
	.send_sc2vlt1_reg = WFR_SEND_SC2VLT1,
	.send_sc2vlt2_reg = WFR_SEND_SC2VLT2,
	.send_sc2vlt3_reg = WFR_SEND_SC2VLT3,
	.send_len_check0_reg = WFR_SEND_LEN_CHECK0,
	.send_len_check1_reg = WFR_SEND_LEN_CHECK1,
	.send_low_priority_list_reg = WFR_SEND_LOW_PRIORITY_LIST,
	.send_high_priority_list_reg = WFR_SEND_HIGH_PRIORITY_LIST,
	.send_counter_array32_reg = WFR_SEND_COUNTER_ARRAY32,
	.send_counter_array64_reg = WFR_SEND_COUNTER_ARRAY64,
	.send_cm_ctrl_reg = WFR_SEND_CM_CTRL,
	.send_cm_global_credit_reg = WFR_SEND_CM_GLOBAL_CREDIT,
	.send_cm_credit_used_status_reg = WFR_SEND_CM_CREDIT_USED_STATUS,
	.send_cm_timer_ctrl_reg = WFR_SEND_CM_TIMER_CTRL,
	.send_cm_local_au_table0_to3_reg = WFR_SEND_CM_LOCAL_AU_TABLE0_TO3,
	.send_cm_local_au_table4_to7_reg = WFR_SEND_CM_LOCAL_AU_TABLE4_TO7,
	.send_cm_remote_au_table0_to3_reg = WFR_SEND_CM_REMOTE_AU_TABLE0_TO3,
	.send_cm_remote_au_table4_to7_reg = WFR_SEND_CM_REMOTE_AU_TABLE4_TO7,
	.send_cm_credit_vl_reg = WFR_SEND_CM_CREDIT_VL,
	.send_cm_credit_vl15_reg = WFR_SEND_CM_CREDIT_VL15,
	.send_egress_err_info_reg = WFR_SEND_EGRESS_ERR_INFO,
	.send_egress_err_source_reg = WFR_SEND_EGRESS_ERR_SOURCE,
	.send_egress_ctxt_status_reg = WFR_SEND_EGRESS_CTXT_STATUS,
	.send_egress_send_dma_status_reg = WFR_SEND_EGRESS_SEND_DMA_STATUS,

	/* egress port send context registers */
	.txe_epsc_stride = WFR_TXE_EPSC_STRIDE,
	.send_ctxt_check_enable_reg = WFR_SEND_CTXT_CHECK_ENABLE,
	.send_ctxt_check_vl_reg = WFR_SEND_CTXT_CHECK_VL,
	.send_ctxt_check_job_key_reg = WFR_SEND_CTXT_CHECK_JOB_KEY,
	.send_ctxt_check_partition_key_reg = WFR_SEND_CTXT_CHECK_PARTITION_KEY,
	.send_ctxt_check_slid_reg = WFR_SEND_CTXT_CHECK_SLID,
	.send_ctxt_check_opcode_reg = WFR_SEND_CTXT_CHECK_OPCODE,

	/* SI registers */
	.cce_msix_int_map_vec_reg = WFR_CCE_INT_MAP,
	.send_pio_err_status_reg = WFR_SEND_PIO_ERR_STATUS,
	.send_pio_err_mask_reg = WFR_SEND_PIO_ERR_MASK,
	.send_pio_err_clear_reg = WFR_SEND_PIO_ERR_CLEAR,
	.send_dma_err_status_reg = WFR_SEND_DMA_ERR_STATUS,
	.send_dma_err_mask_reg = WFR_SEND_DMA_ERR_MASK,
	.send_dma_err_clear_reg = WFR_SEND_DMA_ERR_CLEAR,
	.csr_err_status_reg = WFR_SEND_ERR_STATUS,
	.csr_err_mask_reg = WFR_SEND_ERR_MASK,
	.csr_err_clear_reg = WFR_SEND_ERR_CLEAR,

	.setextled = setextled,
	.start_led_override = hfi1_start_led_override,
	.shutdown_led_override = shutdown_led_override,
	.read_guid = read_guid,
	.early_per_chip_init = wfr_early_per_chip_init,
	.mid_per_chip_init = wfr_mid_per_chip_init,
	.init_other = init_other,
	.late_per_chip_init = wfr_late_per_chip_init,
	.start_port = wfr_start_port,
	.stop_port = wfr_stop_port,
	.init_tids = wfr_init_tids,
	.put_tid = wfr_put_tid,
	.rcv_array_wc_fill = wfr_rcv_array_wc_fill,
	.set_port_tid_count = wfr_set_port_tid_count,
	.set_port_max_mtu = wfr_set_port_max_mtu,
	.update_rcv_hdr_size = wfr_update_rcv_hdr_size,
	.check_synth_status = wfr_check_synth_status,
	.update_synth_status = wfr_update_synth_status,
	.create_pbc = wfr_create_pbc,
	.set_pio_integrity = wfr_set_pio_integrity,
	.find_used_resources = wfr_find_used_resources,
	.read_link_quality = wfr_read_link_quality,
	.set_rheq_addr = NULL,
	.handle_link_bounce = wfr_handle_link_bounce,
	.enable_rcv_context = wfr_enable_rcv_context,
};

/* parameters for the JKR ASIC */
static const struct chip_params jkr_params = {
	.chip_type = CHIP_JKR,
	.num_ports = 2,
	.dma_mask_bits = 58,

	/* BAR0 map: see comments where KREG values are defined */
	.bar0_size = JKR_BAR0_SIZE,
	.kreg1_size = JKR_KREG1_SIZE,
	.kreg2_offset = JKR_KREG2_OFFSET,
	.kreg2_size = JKR_KREG2_SIZE,
	.rcv_array_offset = JKR_RCV_ARRAY,
	.rcv_array_size = JKR_RCV_ARRAY_SIZE,

	.link_speed_supported = OPA_LINK_SPEED_100G | OPA_LINK_SPEED_25G,
	.link_speed_active = OPA_LINK_SPEED_100G,
	.asic_cclock_ps = JKR_ASIC_CCLOCK_PS,
	.rsm_rule_size = JKR_C_RXE_NUM_RSM_INSTANCES,
	.rsm_rule_offset_shift = JKR_RCV_RSM_CFG_OFFSET_SHIFT,
	.rsm_map_table_entries = 256,
	.rsm_map_table_entries_per_csr = 8,
	.rsm_map_table_entry_mask = 0xff,
	.rsm_map_table_entry_shift = 8,
	.qp_map_table_entries = 256,
	.qp_map_table_entries_per_csr = 8,
	.qp_map_table_entry_mask = 0xff,
	.qp_map_table_entry_shift = 8,
	.pkey_table_size = JKR_MAX_PKEY_VALUES,
	.generic_boardname = "Cornelis Networks 5000 Host Fabric Interface Adapter",
	.max_eager_entries = JKR_MAX_EAGER_ENTRIES,
	.pio_base_bits = JKR_PIO_BASE_BITS,
	.pio_base_shift = JKR_SEND_CTXT_CTRL_CTXT_BASE_SHIFT,
	.egress_err_info_data = &jkr_egress_err_info_data,
	.send_ctrl_flush = JKR_SEND_CTRL_FLUSH_WRONG_LINK_STATE_SMASK,
	.port_discard_egress_errs = JKR_PORT_DISCARD_EGRESS_ERRS,

	/* interrupt sources */
	.num_int_csrs = JKR_C_CCE_NUM_INT_CSRS,
	.num_int_map_csrs = JKR_C_CCE_NUM_INT_MAP_CSRS,
	.is_cport_int = JKR_MCTXT_CPORT_TO_PCIE_INT,
	.is_rcvavail_start = JKR_IS_RCVAVAIL_START,
	.is_rcvurgent_start = JKR_IS_RCVURGENT_START,
	.is_sdmaeng_err_start = JKR_IS_SDMAENG_ERR_START,
	.is_sdma_idle_start = JKR_IS_SDMA_IDLE_START,
	.is_sdma_progress_start = JKR_IS_SDMA_PROGRESS_START,
	.is_sdma_start = JKR_IS_SDMA_START,
	.is_last_source = JKR_IS_LAST_SOURCE,
	.is_table = jkr_is_table,
	.gi_enable_table = jkr_gi_enable_table,

	/* cce_interrupt registers */
	.cce_int_status_reg = JKR_CCE_INT_STATUS,
	.cce_int_mask_reg = JKR_CCE_INT_MASK,
	.cce_int_clear_reg = JKR_CCE_INT_CLEAR,
	.cce_int_force_reg = JKR_CCE_INT_FORCE,
	.cce_int_blocked_reg = JKR_CCE_INT_BLOCKED,

	/* counters */
	.chip_dev_cntrs = jkr_dev_cntrs,
	.chip_dev_cntr_first = JKR_DEV_CNTR_FIRST,
	.chip_num_dev_cntrs = JKR_NUM_DEV_CNTRS,
	.chip_port_cntrs = jkr_port_cntrs,
	.chip_port_cntr_first = JKR_PORT_CNTR_FIRST,
	.chip_num_port_cntrs = JKR_NUM_PORT_CNTRS,

	/* ingress port registers */
	.rxe_iport_stride = JKR_C_RXE_IPORT_STRIDE,
	.rcv_iport_ctrl_reg = JKR_RCV_IPORT_CTRL,
	.rcv_iport_status_reg = JKR_RCV_IPORT_STATUS,
	.rcv_bth_qp_reg = JKR_RCV_BTH_QP,
	.rcv_multicast_reg = JKR_RCV_MULTICAST,
	.rcv_bypass_reg = JKR_RCV_BYPASS,
	.rcv_vl15_reg = JKR_RCV_VL15,
	.rcv_err_info_reg = JKR_RCV_ERR_INFO,
	.rcv_err_status_reg = JKR_RCV_ERR_STATUS,
	.rcv_err_mask_reg = JKR_RCV_ERR_MASK,
	.rcv_err_clear_reg = JKR_RCV_ERR_CLEAR,
	.rcv_qp_map_table_reg = JKR_RCV_QP_MAP_TABLE,
	.rcv_partition_key_reg = JKR_RCV_PARTITION_KEY,
	.rcv_counter_array32_reg = JKR_RCV_COUNTER_ARRAY32,
	.rcv_counter_array64_reg = JKR_RCV_COUNTER_ARRAY64,

	/* ingress port receive context registers */
	.rxe_iprc_stride = JKR_C_RXE_IPRC_STRIDE,
	.rcv_jkey_ctrl_reg = JKR_RCV_JKEY_CTRL,

	/* RXE restricted context registers */
	.rxe_rctxt_stride = JKR_C_RXE_RCTXT_STRIDE,
	.rcv_rctxt_ctrl_reg = JKR_RCV_RCTXT_CTRL,
	.rcv_egr_ctrl_reg = JKR_RCV_EGR_CTRL,
	.rcv_tid_ctrl_reg = JKR_RCV_TID_CTRL,

	/* RXE kernel context registers */
	.rxe_kctxt_stride = JKR_C_RXE_KCTXT_STRIDE,
	.rcv_kctxt_ctrl_reg = JKR_RCV_KCTXT_CTRL,
	.rcv_hdr_addr_reg = JKR_RCV_HDR_ADDR,
	.rcv_hdr_cnt_reg = JKR_RCV_HDR_CNT,
	.rcv_hdr_ent_size_reg = JKR_RCV_HDR_ENT_SIZE,
	.rcv_hdr_tail_addr_reg = JKR_RCV_HDR_TAIL_ADDR,
	.rcv_avail_time_out_reg = JKR_RCV_AVAIL_TIME_OUT,
	.rcv_hdr_ovfl_cnt_reg = JKR_RCV_HDR_OVFL_CNT,

	/* RXE kernel/user registers */
	.rxe_ku_stride = JKR_C_RXE_UCTXT_STRIDE,
	.rcv_ctxt_status_reg = JKR_RCV_CTXT_STATUS,

	/* RXE user registers */
	.rxe_uctxt_stride = JKR_C_RXE_UCTXT_STRIDE,
	.rcv_hdr_tail_reg = JKR_RCV_HDR_TAIL,
	.rcv_hdr_head_reg = JKR_RCV_HDR_HEAD,
	.rcv_egr_index_head_reg = JKR_RCV_EGR_INDEX_HEAD,
	.rcv_tid_flow_table_reg = JKR_RCV_TID_FLOW_TABLE,

	/* RXE RSM registers */
	.rcv_rsm_cfg_reg = JKR_RCV_RSM_CFG,
	.rcv_rsm_select_reg = JKR_RCV_RSM_SELECT,
	.rcv_rsm_match_reg = JKR_RCV_RSM_MATCH,
	.rcv_rsm_map_table_reg = JKR_RCV_RSM_MAP_TABLE,

	/* TXE kernel registers */
	.send_contexts_reg = JKR_SEND_CONTEXTS,
	.send_dma_engines_reg = JKR_SEND_DMA_ENGINES,
	.send_pio_mem_size_reg = JKR_SEND_PIO_MEM_SIZE,
	.send_dma_mem_size_reg = JKR_SEND_DMA_MEM_SIZE,
	.send_pio_init_ctxt_reg = JKR_SEND_PIO_INIT_CTXT,

	/* send context_registers */
	.txe_sctxt_stride = JKR_C_TXE_SCTXT_STRIDE,
	.send_ctxt_status_reg = JKR_SEND_CTXT_STATUS,
	.send_ctxt_credit_ctrl_reg = JKR_SEND_CTXT_CREDIT_CTRL,
	.send_ctxt_credit_status_reg = JKR_SEND_CTXT_CREDIT_STATUS,
	.send_ctxt_credit_return_addr_reg = JKR_SEND_CTXT_CREDIT_RETURN_ADDR,
	.send_ctxt_credit_force_reg = JKR_SEND_CTXT_CREDIT_FORCE,
	.send_ctxt_err_status_reg = JKR_SEND_CTXT_ERR_STATUS,
	.send_ctxt_err_mask_reg = JKR_SEND_CTXT_ERR_MASK,
	.send_ctxt_err_clear_reg = JKR_SEND_CTXT_ERR_CLEAR,

	/* TXE send context registers */
	.txe_tctxt_stride = JKR_C_TXE_TCTXT_STRIDE,
	.send_ctxt_ctrl_reg = JKR_SEND_CTXT_CTRL,

	/* SDMA registers */
	.txe_sdma_stride = JKR_C_TXE_SDMA_STRIDE,
	.send_dma_ctrl_reg = JKR_SEND_DMA_CTRL,
	.send_dma_status_reg = JKR_SEND_DMA_STATUS,
	.send_dma_base_addr_reg = JKR_SEND_DMA_BASE_ADDR,
	.send_dma_len_gen_reg = JKR_SEND_DMA_LEN_GEN,
	.send_dma_tail_reg = JKR_SEND_DMA_TAIL,
	.send_dma_head_reg = JKR_SEND_DMA_HEAD,
	.send_dma_head_addr_reg = JKR_SEND_DMA_HEAD_ADDR,
	.send_dma_priority_thld_reg = JKR_SEND_DMA_PRIORITY_THLD,
	.send_dma_idle_cnt_reg = JKR_SEND_DMA_IDLE_CNT,
	.send_dma_reload_cnt_reg = JKR_SEND_DMA_RELOAD_CNT,
	.send_dma_desc_cnt_reg = JKR_SEND_DMA_DESC_CNT,
	.send_dma_desc_fetched_cnt_reg = JKR_SEND_DMA_DESC_FETCHED_CNT,
	.send_dma_eng_err_status_reg = JKR_SEND_DMA_ENG_ERR_STATUS,
	.send_dma_eng_err_mask_reg = JKR_SEND_DMA_ENG_ERR_MASK,
	.send_dma_eng_err_clear_reg = JKR_SEND_DMA_ENG_ERR_CLEAR,

	/* SDMA Config registers */
	.txe_sdmacfg_stride = JKR_C_TXE_SDMACFG_STRIDE,
	.send_dma_cfg_memory_reg = JKR_SEND_DMA_CFG_MEMORY,

	/* egress port registers */
	.txe_eport_stride = JKR_C_TXE_EPORT_STRIDE,
	.send_ctrl_reg = JKR_SEND_CTRL,
	.send_high_priority_limit_reg = JKR_SEND_HIGH_PRIORITY_LIMIT,
	.send_egress_err_status_reg = JKR_SEND_EGRESS_ERR_STATUS,
	.send_egress_err_mask_reg = JKR_SEND_EGRESS_ERR_MASK,
	.send_egress_err_clear_reg = JKR_SEND_EGRESS_ERR_CLEAR,
	.send_bth_qp_reg = JKR_SEND_BTH_QP,
	.send_static_rate_control_reg = JKR_SEND_STATIC_RATE_CONTROL,
	.send_sc2vlt0_reg = JKR_SEND_SC2VLT0,
	.send_sc2vlt1_reg = JKR_SEND_SC2VLT1,
	.send_sc2vlt2_reg = JKR_SEND_SC2VLT2,
	.send_sc2vlt3_reg = JKR_SEND_SC2VLT3,
	.send_len_check0_reg = JKR_SEND_LEN_CHECK0,
	.send_len_check1_reg = JKR_SEND_LEN_CHECK1,
	.send_low_priority_list_reg = JKR_SEND_LOW_PRIORITY_LIST,
	.send_high_priority_list_reg = JKR_SEND_HIGH_PRIORITY_LIST,
	.send_counter_array32_reg = JKR_SEND_COUNTER_ARRAY32,
	.send_counter_array64_reg = JKR_SEND_COUNTER_ARRAY64,
	.send_cm_ctrl_reg = JKR_SEND_CM_CTRL,
	.send_cm_global_credit_reg = JKR_SEND_CM_GLOBAL_CREDIT,
	.send_cm_credit_used_status_reg = JKR_SEND_CM_CREDIT_USED_STATUS,
	.send_cm_timer_ctrl_reg = JKR_SEND_CM_TIMER_CTRL,
	.send_cm_local_au_table0_to3_reg = JKR_SEND_CM_LOCAL_AU_TABLE0_TO3,
	.send_cm_local_au_table4_to7_reg = JKR_SEND_CM_LOCAL_AU_TABLE4_TO7,
	.send_cm_remote_au_table0_to3_reg = JKR_SEND_CM_REMOTE_AU_TABLE0_TO3,
	.send_cm_remote_au_table4_to7_reg = JKR_SEND_CM_REMOTE_AU_TABLE4_TO7,
	.send_cm_credit_vl_reg = JKR_SEND_CM_CREDIT_VL,
	.send_cm_credit_vl15_reg = JKR_SEND_CM_CREDIT_VL15,
	.send_egress_err_info_reg = JKR_SEND_EGRESS_ERR_INFO,
	.send_egress_err_source_reg = JKR_SEND_EGRESS_ERR_SOURCE,
	.send_egress_ctxt_status_reg = JKR_SEND_EGRESS_CTXT_STATUS,
	.send_egress_send_dma_status_reg = JKR_SEND_EGRESS_SEND_DMA_STATUS,

	/* egress port send context registers */
	.txe_epsc_stride = JKR_C_TXE_EPSC_STRIDE,
	.send_ctxt_check_enable_reg = JKR_SEND_CTXT_CHECK_ENABLE,
	.send_ctxt_check_vl_reg = JKR_SEND_CTXT_CHECK_VL,
	.send_ctxt_check_job_key_reg = JKR_SEND_CTXT_CHECK_JOB_KEY,
	.send_ctxt_check_partition_key_reg = JKR_SEND_CTXT_CHECK_PARTITION_KEY,
	.send_ctxt_check_slid_reg = JKR_SEND_CTXT_CHECK_SLID,
	.send_ctxt_check_opcode_reg = JKR_SEND_CTXT_CHECK_OPCODE,

	/* SI registers */
	.cce_msix_int_map_vec_reg = JKR_CCE_MSIX_INT_MAP_VEC,
	.send_pio_err_status_reg = JKR_SEND_PIO_ERR_STATUS,
	.send_pio_err_mask_reg = JKR_SEND_PIO_ERR_MASK,
	.send_pio_err_clear_reg = JKR_SEND_PIO_ERR_CLEAR,
	.send_dma_err_status_reg = JKR_SEND_DMA_ERR_STATUS,
	.send_dma_err_mask_reg = JKR_SEND_DMA_ERR_MASK,
	.send_dma_err_clear_reg = JKR_SEND_DMA_ERR_CLEAR,
	.csr_err_status_reg = JKR_CSR_ERR_STATUS,
	.csr_err_mask_reg = JKR_CSR_ERR_MASK,
	.csr_err_clear_reg = JKR_CSR_ERR_CLEAR,

	.setextled = gen_setextled,
	.start_led_override = gen_start_led_override,
	.shutdown_led_override = gen_shutdown_led_override,
	.read_guid = jkr_read_guid,
	.early_per_chip_init = jkr_early_per_chip_init,
	.mid_per_chip_init = jkr_mid_per_chip_init,
	.init_other = jkr_init_other,
	.late_per_chip_init = gen_late_per_chip_init,
	.start_port = gen_start_port,
	.stop_port = gen_stop_port,
	.init_tids = jkr_init_tids,
	.put_tid = jkr_put_tid,
	.rcv_array_wc_fill = jkr_rcv_array_wc_fill,
	.set_port_tid_count = jkr_set_port_tid_count,
	.set_port_max_mtu = gen_set_port_max_mtu,
	.update_rcv_hdr_size = jkr_update_rcv_hdr_size,
	.check_synth_status = jkr_check_synth_status,
	.update_synth_status = jkr_update_synth_status,
	.create_pbc = gen_create_pbc,
	.set_pio_integrity = jkr_set_pio_integrity,
	.find_used_resources = jkr_find_used_resources,
	.read_link_quality = jkr_read_link_quality,
	.set_rheq_addr = jkr_set_rheq_addr,
	.handle_link_bounce = jkr_handle_link_bounce,
	.enable_rcv_context = jkr_enable_rcv_context,
};

/*
 * Number of user receive contexts each port configured to use (allow for more
 * pio buffers per ctxt, etc).
 */
static int num_user_contexts_array[32];
static int num_user_contexts_count;
module_param_array_named(num_user_contexts, num_user_contexts_array, int,
			 &num_user_contexts_count, 0444);
MODULE_PARM_DESC(num_user_contexts, "Set max number of user contexts to use per-hfi, per-port (unset or -1: use the real (non-HT) CPU count)");

uint krcvqs[RXE_NUM_DATA_VL];
int krcvqsset;
module_param_array(krcvqs, uint, &krcvqsset, S_IRUGO);
MODULE_PARM_DESC(krcvqs, "Array of the number of non-control kernel receive queues by VL");

/* computed based on above array */
unsigned long n_krcvqs;

static unsigned hfi1_rcvarr_split = 25;
module_param_named(rcvarr_split, hfi1_rcvarr_split, uint, S_IRUGO);
MODULE_PARM_DESC(rcvarr_split, "Percent of context's RcvArray entries used for Eager buffers");

static uint eager_buffer_size = (8 << 20); /* 8MB */
module_param(eager_buffer_size, uint, S_IRUGO);
MODULE_PARM_DESC(eager_buffer_size, "Size of the eager buffers, default: 8MB");

static uint rcvhdrcnt = 2048; /* 2x the max eager buffer count */
module_param_named(rcvhdrcnt, rcvhdrcnt, uint, S_IRUGO);
MODULE_PARM_DESC(rcvhdrcnt, "Receive header queue count (default 2048)");

static uint hfi1_hdrq_entsize = DEFAULT_HDRQ_ENTSIZE;
module_param_named(hdrq_entsize, hfi1_hdrq_entsize, uint, 0444);
MODULE_PARM_DESC(hdrq_entsize, "Size of header queue entries: 2 - 8B, 16 - 64B, 32 - 128B (default)");

unsigned int user_credit_return_threshold = 33;	/* default is 33% */
module_param(user_credit_return_threshold, uint, S_IRUGO);
MODULE_PARM_DESC(user_credit_return_threshold, "Credit return threshold for user send contexts, return when unreturned credits passes this many blocks (in percent of allocated blocks, 0 is off)");

int work_around_ASIC_6032 = 5000;
module_param_named(work_around_ASIC_6032, work_around_ASIC_6032, int, 0444);
MODULE_PARM_DESC(work_around_ASIC_6032, "DO NOT UPSTREAM: Increase wait for packet egress time for emulation (time in ms)");

/* use and give resources to rdmavt bulk service */
bool use_bulksvc = false;
module_param(use_bulksvc, bool, S_IRUGO);
MODULE_PARM_DESC(use_bulksvc, "Use and give resources to rdmavt bulk service");

DEFINE_XARRAY_FLAGS(hfi1_dev_table, XA_FLAGS_ALLOC | XA_FLAGS_LOCK_IRQ);

struct cport_trap_reg {
	u32 mask;
	cport_trap_handler func;
};

/* send, or resend, START message */
static int cport_start(struct hfi1_devdata *dd, int to_secs)
{
	struct cport_start_payload start = {0};
	union {
		struct cport_start_payload pl;
		u64 qw;
	} *resp = NULL;
	int resp_len = 0;
	int ret;

	start.opts_ena = dd->cport->opts;
	start.trap_ena = dd->cport->traps;

	ret = cport_send_req(dd, CH_OP_START, 0, &start, sizeof(start),
			     (void **)&resp, &resp_len, to_secs * HZ);
	if (ret) {
		dd_dev_err(dd, "CPORT start failed %d\n", ret);
	} else if (resp_len) {
		dd_dev_info(dd, "CPORT started %016llx\n", resp->qw);
		dd->cport->traps_act = resp->pl.trap_ena;
	} else {
		dd_dev_info(dd, "CPORT started\n");
	}
	kfree(resp);
	return ret;
}

int register_cport_trap(struct hfi1_devdata *dd, struct cport_trap_status traps,
			cport_trap_handler func)
{
	union {
		struct cport_trap_status traps;
		u32 dw;
	} trap_val, cur_traps;
	struct cport_trap_reg *entry;
	u32 index;
	int ret;

	if (!dd->cport)
		return 0;

	trap_val.traps = traps;
	cur_traps.traps = dd->cport->traps;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->mask = trap_val.dw;
	entry->func = func;
	ret = xa_alloc_irq(&dd->cport->trap_xa, &index, entry, xa_limit_32b, GFP_KERNEL);
	if (ret < 0) {
		kfree(entry);
		return ret;
	}

	trap_val.dw |= cur_traps.dw;
	if (trap_val.dw != cur_traps.dw) {
		dd->cport->traps = trap_val.traps;
		ret = cport_start(dd, cport_adm_to);
	}
	return ret;
}

int deregister_cport_trap(struct hfi1_devdata *dd, cport_trap_handler func)
{
	union {
		struct cport_trap_status traps;
		u32 dw;
	} trap_val, cur_traps;
	struct cport_trap_reg *entry;
	unsigned long index;

	if (!dd->cport)
		return 0;

	trap_val.dw = 0;
	xa_lock_irq(&dd->cport->trap_xa);
	xa_for_each(&dd->cport->trap_xa, index, entry) {
		if (entry->func == func) {
			__xa_erase(&dd->cport->trap_xa, index);
			kfree(entry);
		} else {
			trap_val.dw |= entry->mask;
		}
	}
	xa_unlock_irq(&dd->cport->trap_xa);
	cur_traps.traps = dd->cport->traps;
	if (trap_val.dw != cur_traps.dw) {
		dd->cport->traps = trap_val.traps;
		cport_start(dd, cport_adm_to);
	}

	return 0;
}

static void clearall_cport_trap(struct hfi1_devdata *dd)
{
	struct cport_trap_reg *entry;
	unsigned long index;
	struct cport_trap_status no_traps = {0};

	if (!dd->cport)
		return;

	dd->cport->traps = no_traps;
	cport_start(dd, cport_adm_to);
	cport_register_cb(dd, CH_OP_TRAP, CH_OP_TRAP, NULL);
	xa_lock_irq(&dd->cport->trap_xa);
	/* there should be none left, but make certain */
	xa_for_each(&dd->cport->trap_xa, index, entry) {
		__xa_erase(&dd->cport->trap_xa, index);
		dd_dev_info(dd, "removing latent TRAP handler %ps\n", entry->func);
		kfree(entry);
	}
	xa_unlock_irq(&dd->cport->trap_xa);
}

static int handle_cport_trap(struct hfi1_devdata *dd, u8 op, u8 sideband,
			     void *payload, int len, void *handle)
{
	struct cport_trap_payload *traps = payload;
	struct cport_trap_payload repress = {0};
	union {
		struct cport_trap_status traps;
		u32 dw;
	} trap_val;
	struct cport_trap_reg *entry;
	unsigned long index;
	int ret;

	trap_val.traps = traps->trap_sts;

	/* clear-down the traps we got */
	repress.trap_sts = traps->trap_sts;
	ret = cport_send_notif(dd, CH_OP_TRAP_REPRESS, 0, &repress, sizeof(repress),
			       cport_adm_to * HZ);
	if (ret)
		dd_dev_warn(dd, "CPORT TRAP_REPRESS failed: %d\n", ret);
#ifdef CPORT_TRAP_DEBUG
	pr_warn("hfi1_%d: %s: CPORT TRAP %08x\n", dd->unit, __func__, trap_val.dw);
#endif

	xa_lock_irq(&dd->cport->trap_xa);
	xa_for_each(&dd->cport->trap_xa, index, entry) {
		if (entry->mask & trap_val.dw)
			entry->func(dd, trap_val.traps);
	}
	xa_unlock_irq(&dd->cport->trap_xa);

	return 0;
}

static void cport_stop(struct hfi1_devdata *dd)
{
	struct cport_stop_payload stop = {0};
	u64 *resp = NULL;
	int resp_len = 0;
	int ret;

	if (!dd->cport)
		return;

	ret = cport_send_req(dd, CH_OP_STOP, 0, &stop, sizeof(stop),
			     (void **)&resp, &resp_len, cport_adm_to * HZ);
	if (ret)
		dd_dev_err(dd, "CPORT stop failed %d\n", ret);
	else if (resp_len)
		dd_dev_info(dd, "CPORT stopped %016llx\n", *resp);
	else
		dd_dev_info(dd, "CPORT stopped\n");
	kfree(resp);
}

int start_cport(struct hfi1_devdata *dd)
{
	int ret;

	ret = cport_init(dd);
	if (ret || !dd->cport)
		return ret;

	/*
	 * Do a STOP to ensure the device is properly cleaned up.
	 * This may cause firmware to be unresponsive for awhile,
	 * so increase the timeout for the subsequent START.
	 */
	cport_stop(dd);

	cport_register_cb(dd, CH_OP_TRAP, CH_OP_TRAP, handle_cport_trap);

	dd->cport->opts.bare_metal = 1;

	ret = cport_start(dd, 3 * cport_adm_to);
	if (ret)
		cport_exit(dd);
	return (ret > 0 ? -EIO : ret);
}

static void stop_cport(struct hfi1_devdata *dd)
{
	if (!dd->cport)
		return;

	cport_stop(dd);

	cport_exit(dd);
}

int hfi1_create_kctxt(struct hfi1_pportdata *ppd, u16 ctxt, bool is_bulksvc)
{
	struct hfi1_devdata *dd = ppd->dd;
	struct hfi1_ctxtdata *rcd;
	int ret;

	/* Control context has to be always 0 */
	BUILD_BUG_ON(HFI1_CTRL_CTXT != 0);

	ret = hfi1_create_ctxtdata(ppd, dd->node, ctxt, &rcd);
	if (ret < 0) {
		dd_dev_err(dd, "Kernel receive context allocation failed\n");
		return ret;
	}

	/*
	 * Set up the kernel context flags here and now because they use
	 * default values for all receive side memories.  User contexts will
	 * be handled as they are created.
	 */
	rcd->flags = HFI1_CAP_KGET(MULTI_PKT_EGR) |
		HFI1_CAP_KGET(NODROP_RHQ_FULL) |
		HFI1_CAP_KGET(NODROP_EGR_FULL) |
		HFI1_CAP_KGET(DMA_RTAIL);

	/* Control context must use DMA_RTAIL */
	if (is_control_context(rcd))
		rcd->flags |= HFI1_CAP_DMA_RTAIL;
	rcd->fast_handler = get_dma_rtail_setting(rcd) ?
				handle_receive_interrupt_dma_rtail :
				handle_receive_interrupt_nodma_rtail;

	hfi1_set_seq_cnt(rcd, 1);

	rcd->sc = sc_alloc(ppd, is_bulksvc ? SC_USER : SC_ACK,
			   rcd->rcvhdrqentsize, dd->node);
	if (!rcd->sc) {
		dd_dev_err(dd, "Kernel send context allocation failed\n");
		return -ENOMEM;
	}
	hfi1_init_ctxt(rcd->sc);

	return 0;
}

/*
 * Create the receive context array and one or more kernel contexts
 */
int hfi1_create_kctxts(struct hfi1_devdata *dd)
{
	struct hfi1_devrsrcs *dr = &dd->rsrcs;
	u16 i;
	u16 j;
	int ret;

	dd->num_rcd = chip_rcv_contexts(dd);
	dd->rcd = kcalloc_node(dd->num_rcd, sizeof(*dd->rcd),
			       GFP_KERNEL, dd->node);
	if (!dd->rcd) {
		dd->num_rcd = 0;
		return -ENOMEM;
	}

	for (i = 0; i < dd->num_pports; i++) {
		struct hfi1_pportdata *ppd = dd->pport + i;
		struct hfi1_portrsrcs *pr = &dr->ppr[i];

		for (j = 0; j < pr->n_krcv_queues; j++) {
			u16 ctxt = pr->rcv_context_base + j;

			ret = hfi1_create_kctxt(ppd, ctxt, false);
			if (ret)
				goto bail;
		}
	}

	return 0;
bail:
	for (i = 0; i < dd->num_pports; i++) {
		struct hfi1_portrsrcs *pr = &dr->ppr[i];

		for (j = 0; j < pr->n_krcv_queues; j++) {
			u16 ctxt = pr->rcv_context_base + j;

			hfi1_free_ctxt(dd->rcd[ctxt]);
		}
	}

	/* All the contexts should be freed, free the array */
	kfree(dd->rcd);
	dd->rcd = NULL;
	dd->num_rcd = 0;
	return ret;
}

/*
 * Helper routines for the receive context reference count (rcd and uctxt).
 */
static void hfi1_rcd_init(struct hfi1_ctxtdata *rcd)
{
	kref_init(&rcd->kref);
}

/**
 * hfi1_rcd_free - When reference is zero clean up.
 * @kref: pointer to an initialized rcd data structure
 *
 */
static void hfi1_rcd_free(struct kref *kref)
{
	unsigned long flags;
	struct hfi1_ctxtdata *rcd =
		container_of(kref, struct hfi1_ctxtdata, kref);

	spin_lock_irqsave(&rcd->dd->uctxt_lock, flags);
	rcd->dd->rcd[rcd->ctxt] = NULL;
	spin_unlock_irqrestore(&rcd->dd->uctxt_lock, flags);

	hfi1_free_ctxtdata(rcd->dd, rcd);

	kfree(rcd);
}

/**
 * hfi1_rcd_put - decrement reference for rcd
 * @rcd: pointer to an initialized rcd data structure
 *
 * Use this to put a reference after the init.
 */
int hfi1_rcd_put(struct hfi1_ctxtdata *rcd)
{
	if (rcd)
		return kref_put(&rcd->kref, hfi1_rcd_free);

	return 0;
}

/**
 * hfi1_rcd_get - increment reference for rcd
 * @rcd: pointer to an initialized rcd data structure
 *
 * Use this to get a reference after the init.
 *
 * Return : reflect kref_get_unless_zero(), which returns non-zero on
 * increment, otherwise 0.
 */
int hfi1_rcd_get(struct hfi1_ctxtdata *rcd)
{
	return kref_get_unless_zero(&rcd->kref);
}

/**
 * allocate_rcd_index - allocate an rcd index from the rcd array
 * @ppd: pointer to a valid port data structure
 * @rcd: rcd data structure to assign
 * @index[in,out]: in, suggested context number; out, selected context number
 *
 * Allocate an rcd index, either at the given context number or any within
 * a dynamic range.  If the fixed index is used or the dynamic range is full,
 * return -EBUSY.
 */
static int allocate_rcd_index(struct hfi1_pportdata *ppd,
			      struct hfi1_ctxtdata *rcd, u16 *index)
{
	struct hfi1_devdata *dd = ppd->dd;
	struct hfi1_portrsrcs *pr = &dd->rsrcs.ppr[ppd->hw_pidx];
	unsigned long flags;
	u16 ctxt = *index;
	bool found;

	spin_lock_irqsave(&dd->uctxt_lock, flags);
	found = false;
	if (ctxt == DYNAMIC_CONTEXT) {
		/* look for an unused dynamic context */
		for (ctxt = pr->first_dyn_alloc_ctxt;
		     ctxt < pr->rcv_context_base + pr->num_rcv_contexts;
		     ctxt++) {
			if (!dd->rcd[ctxt]) {
				found = true;
				break;
			}
		}
	} else {
		/* use the context number given */
		if (!dd->rcd[ctxt])
			found = true;
	}

	if (found) {
		rcd->ctxt = ctxt;
		dd->rcd[ctxt] = rcd;
		hfi1_rcd_init(rcd);
	}
	spin_unlock_irqrestore(&dd->uctxt_lock, flags);

	if (!found)
		return -EBUSY;

	*index = ctxt;

	return 0;
}

/**
 * hfi1_rcd_get_by_index - get rcd by index
 * @dd: pointer to a valid devdata structure
 * @ctxt: the index of a possible rcd
 *
 * Hold the protecting spinlock and increment the reference on the selected
 * rcd element.
 *
 * The caller is responsible for calling hfi1_rcd_put() on the returned
 * pointer.
 */
struct hfi1_ctxtdata *hfi1_rcd_get_by_index(struct hfi1_devdata *dd, u16 ctxt)
{
	unsigned long flags;
	struct hfi1_ctxtdata *rcd = NULL;

	spin_lock_irqsave(&dd->uctxt_lock, flags);
	if (ctxt < dd->num_rcd) {
		rcd = dd->rcd[ctxt];
		if (rcd && !hfi1_rcd_get(rcd))
			rcd = NULL;
	}
	spin_unlock_irqrestore(&dd->uctxt_lock, flags);

	return rcd;
}

/*
 * Common code for user and kernel context create and setup.
 * NOTE: the initial kref is done here (hf1_rcd_init()).
 */
int hfi1_create_ctxtdata(struct hfi1_pportdata *ppd, int numa, u16 ctxt,
			 struct hfi1_ctxtdata **context)
{
	struct hfi1_devdata *dd = ppd->dd;
	struct hfi1_devrsrcs *dr = &dd->rsrcs;
	struct hfi1_portrsrcs *pr = &dr->ppr[ppd->hw_pidx];
	struct hfi1_ctxtdata *rcd;

	rcd = kzalloc_node(sizeof(*rcd), GFP_KERNEL, numa);
	if (rcd) {
		u32 rcvtids, max_entries;
		int ret;

		ret = allocate_rcd_index(ppd, rcd, &ctxt);
		if (ret) {
			*context = NULL;
			kfree(rcd);
			return ret;
		}

		INIT_LIST_HEAD(&rcd->qp_wait_list);
		hfi1_exp_tid_group_init(rcd);
		rcd->ppd = ppd;
		rcd->dd = dd;
		rcd->numa_id = numa;
		rcd->rcv_array_groups = dd->rcv_entries.ngroups;
		rcd->rhf_rcv_function_map = normal_rhf_rcv_functions;
		rcd->slow_handler = handle_receive_interrupt;
		rcd->do_interrupt = rcd->slow_handler;
		rcd->msix_intr = CCE_NUM_MSIX_VECTORS;

		mutex_init(&rcd->exp_mutex);
		spin_lock_init(&rcd->exp_lock);
		INIT_LIST_HEAD(&rcd->flow_queue.queue_head);
		INIT_LIST_HEAD(&rcd->rarr_queue.queue_head);

		hfi1_cdbg(PROC, "setting up context %u", rcd->ctxt);

		/* calculate the context's RcvArray entry starting point */
		rcd->eager_base = pr->rcv_array_base +
				  ((ctxt - pr->rcv_context_base) *
				   dd->rcv_entries.ngroups *
				   dd->rcv_entries.group_size);

		rcd->rcvhdrq_cnt = rcvhdrcnt;
		rcd->rcvhdrqentsize = hfi1_hdrq_entsize;
		rcd->rhf_offset =
			rcd->rcvhdrqentsize - sizeof(u64) / sizeof(u32);
		rcd->kdeth_rcv_hdr = DEFAULT_RCVHDRSIZE;
		/*
		 * Simple Eager buffer allocation: we have already pre-allocated
		 * the number of RcvArray entry groups. Each ctxtdata structure
		 * holds the number of groups for that context.
		 *
		 * To follow CSR requirements and maintain cacheline alignment,
		 * make sure all sizes and bases are multiples of group_size.
		 *
		 * The expected entry count is what is left after assigning
		 * eager.
		 */
		max_entries = rcd->rcv_array_groups * dd->rcv_entries.group_size;
		rcvtids = ((max_entries * hfi1_rcvarr_split) / 100);
		rcd->egrbufs.count = round_down(rcvtids, dd->rcv_entries.group_size);
		if (rcd->egrbufs.count > dd->params->max_eager_entries) {
			dd_dev_err(dd, "ctxt%u: requested too many RcvArray entries.\n",
				   rcd->ctxt);
			rcd->egrbufs.count = dd->params->max_eager_entries;
		}
		hfi1_cdbg(PROC,
			  "ctxt%u: max Eager buffer RcvArray entries: %u",
			  rcd->ctxt, rcd->egrbufs.count);

		/*
		 * Allocate array that will hold the eager buffer accounting
		 * data.
		 * This will allocate the maximum possible buffer count based
		 * on the value of the RcvArray split parameter.
		 * The resulting value will be rounded down to the closest
		 * multiple of dd->rcv_entries.group_size.
		 */
		rcd->egrbufs.buffers =
			kcalloc_node(rcd->egrbufs.count,
				     sizeof(*rcd->egrbufs.buffers),
				     GFP_KERNEL, numa);
		if (!rcd->egrbufs.buffers)
			goto bail;
		rcd->egrbufs.rcvtids =
			kcalloc_node(rcd->egrbufs.count,
				     sizeof(*rcd->egrbufs.rcvtids),
				     GFP_KERNEL, numa);
		if (!rcd->egrbufs.rcvtids)
			goto bail;
		rcd->egrbufs.size = eager_buffer_size;
		/*
		 * The size of the buffers programmed into the RcvArray
		 * entries needs to be big enough to handle the highest
		 * MTU supported.
		 */
		if (rcd->egrbufs.size < hfi1_max_mtu) {
			rcd->egrbufs.size = __roundup_pow_of_two(hfi1_max_mtu);
			hfi1_cdbg(PROC,
				  "ctxt%u: eager bufs size too small. Adjusting to %u",
				    rcd->ctxt, rcd->egrbufs.size);
		}
		rcd->egrbufs.rcvtid_size = HFI1_MAX_EAGER_BUFFER_SIZE;

		/* Applicable only for statically created kernel contexts */
		if (ctxt < pr->first_dyn_alloc_ctxt) {
			rcd->opstats = kzalloc_node(sizeof(*rcd->opstats),
						    GFP_KERNEL, numa);
			if (!rcd->opstats)
				goto bail;

			/* Initialize TID flow generations for the context */
			hfi1_kern_init_ctxt_generations(rcd);
		}

		*context = rcd;
		return 0;
	}

bail:
	*context = NULL;
	hfi1_free_ctxt(rcd);
	return -ENOMEM;
}

/**
 * hfi1_free_ctxt - free context
 * @rcd: pointer to an initialized rcd data structure
 *
 * This wrapper is the free function that matches hfi1_create_ctxtdata().
 * When a context is done being used (kernel or user), this function is called
 * for the "final" put to match the kref init from hfi1_create_ctxtdata().
 * Other users of the context do a get/put sequence to make sure that the
 * structure isn't removed while in use.
 */
void hfi1_free_ctxt(struct hfi1_ctxtdata *rcd)
{
	hfi1_rcd_put(rcd);
}

/*
 * Select the largest ccti value over all SLs to determine the intra-
 * packet gap for the link.
 *
 * called with cca_timer_lock held (to protect access to cca_timer
 * array), and rcu_read_lock() (to protect access to cc_state).
 */
void set_link_ipg(struct hfi1_pportdata *ppd)
{
	struct hfi1_devdata *dd = ppd->dd;
	struct cc_state *cc_state;
	int i;
	u16 cce, ccti_limit, max_ccti = 0;
	u16 shift, mult;
	u64 src;
	u32 current_egress_rate; /* Mbits /sec */
	u64 max_pkt_time;
	/*
	 * max_pkt_time is the maximum packet egress time in units
	 * of the fabric clock period 1/(805 MHz).
	 */

	cc_state = get_cc_state(ppd);

	if (!cc_state)
		/*
		 * This should _never_ happen - rcu_read_lock() is held,
		 * and set_link_ipg() should not be called if cc_state
		 * is NULL.
		 */
		return;

	for (i = 0; i < OPA_MAX_SLS; i++) {
		u16 ccti = ppd->cca_timer[i].ccti;

		if (ccti > max_ccti)
			max_ccti = ccti;
	}

	ccti_limit = cc_state->cct.ccti_limit;
	if (max_ccti > ccti_limit)
		max_ccti = ccti_limit;

	cce = cc_state->cct.entries[max_ccti].entry;
	shift = (cce & 0xc000) >> 14;
	mult = (cce & 0x3fff);

	current_egress_rate = active_egress_rate(ppd);

	max_pkt_time = egress_cycles(ppd->ibmaxlen, current_egress_rate);

	src = (max_pkt_time >> shift) * mult;

	src &= SEND_STATIC_RATE_CONTROL_CSR_SRC_RELOAD_SMASK;
	src <<= SEND_STATIC_RATE_CONTROL_CSR_SRC_RELOAD_SHIFT;

	write_eport_csr(dd, ppd->hw_pidx, dd->params->send_static_rate_control_reg, src);
}

static enum hrtimer_restart cca_timer_fn(struct hrtimer *t)
{
	struct cca_timer *cca_timer;
	struct hfi1_pportdata *ppd;
	int sl;
	u16 ccti_timer, ccti_min;
	struct cc_state *cc_state;
	unsigned long flags;
	enum hrtimer_restart ret = HRTIMER_NORESTART;

	cca_timer = container_of(t, struct cca_timer, hrtimer);
	ppd = cca_timer->ppd;
	sl = cca_timer->sl;

	rcu_read_lock();

	cc_state = get_cc_state(ppd);

	if (!cc_state) {
		rcu_read_unlock();
		return HRTIMER_NORESTART;
	}

	/*
	 * 1) decrement ccti for SL
	 * 2) calculate IPG for link (set_link_ipg())
	 * 3) restart timer, unless ccti is at min value
	 */

	ccti_min = cc_state->cong_setting.entries[sl].ccti_min;
	ccti_timer = cc_state->cong_setting.entries[sl].ccti_timer;

	spin_lock_irqsave(&ppd->cca_timer_lock, flags);

	if (cca_timer->ccti > ccti_min) {
		cca_timer->ccti--;
		set_link_ipg(ppd);
	}

	if (cca_timer->ccti > ccti_min) {
		unsigned long nsec = 1024 * ccti_timer;
		/* ccti_timer is in units of 1.024 usec */
		hrtimer_forward_now(t, ns_to_ktime(nsec));
		ret = HRTIMER_RESTART;
	}

	spin_unlock_irqrestore(&ppd->cca_timer_lock, flags);
	rcu_read_unlock();
	return ret;
}

/*
 * Common code for initializing the physical port structure.
 */
void hfi1_init_pportdata(struct pci_dev *pdev, struct hfi1_pportdata *ppd,
			 struct hfi1_devdata *dd, u8 hw_pidx, u32 port)
{
	int i;
	uint default_pkey_idx;
	struct cc_state *cc_state;

	ppd->dd = dd;
	ppd->hw_pidx = hw_pidx;
	ppd->port = port; /* IB port number, not index */
	ppd->prev_link_width = LINK_WIDTH_DEFAULT;
	/*
	 * There are C_VL_COUNT number of PortVLXmitWait counters.
	 * Adding 1 to C_VL_COUNT to include the PortXmitWait counter.
	 */
	for (i = 0; i < C_VL_COUNT + 1; i++) {
		ppd->port_vl_xmit_wait_last[i] = 0;
		ppd->vl_xmit_flit_cnt[i] = 0;
	}

	default_pkey_idx = 1;

	ppd->pkeys[default_pkey_idx] = DEFAULT_P_KEY;
	ppd->part_enforce |= HFI1_PART_ENFORCE_IN;
	ppd->pkeys[0] = 0x8001;

	INIT_WORK(&ppd->link_vc_work, handle_verify_cap);
	INIT_WORK(&ppd->link_up_work, handle_link_up);
	INIT_WORK(&ppd->link_down_work, handle_link_down);
	INIT_WORK(&ppd->link_downgrade_work, handle_link_downgrade);
	INIT_WORK(&ppd->sma_message_work, handle_sma_message);
	INIT_WORK(&ppd->link_bounce_work, dd->params->handle_link_bounce);
	INIT_DELAYED_WORK(&ppd->start_link_work, handle_start_link);
	INIT_WORK(&ppd->linkstate_active_work, receive_interrupt_work);
	INIT_WORK(&ppd->qsfp_info.qsfp_work, qsfp_event);

	mutex_init(&ppd->hls_lock);
	spin_lock_init(&ppd->qsfp_info.qsfp_lock);
	seqlock_init(&ppd->sc2vl_lock);

	ppd->qsfp_info.ppd = ppd;
	ppd->sm_trap_qp = 0x0;
	ppd->sa_qp = 0x1;

	spin_lock_init(&ppd->cca_timer_lock);

	for (i = 0; i < OPA_MAX_SLS; i++) {
		hrtimer_init(&ppd->cca_timer[i].hrtimer, CLOCK_MONOTONIC,
			     HRTIMER_MODE_REL);
		ppd->cca_timer[i].ppd = ppd;
		ppd->cca_timer[i].sl = i;
		ppd->cca_timer[i].ccti = 0;
		ppd->cca_timer[i].hrtimer.function = cca_timer_fn;
	}

	ppd->cc_max_table_entries = IB_CC_TABLE_CAP_DEFAULT;

	spin_lock_init(&ppd->cc_state_lock);
	spin_lock_init(&ppd->cc_log_lock);
	cc_state = kzalloc(sizeof(*cc_state), GFP_KERNEL);
	RCU_INIT_POINTER(ppd->cc_state, cc_state);
	if (!cc_state)
		goto bail;
	atomic_set(&ppd->ipoib_rsm_usr_num, 0);
	atomic_set(&ppd->vnic_rsm_usr_num, 0);
	ppd->netdev_rsm_rule = -1;
	return;

bail:
	dd_dev_err(dd, "Congestion Control Agent disabled for port %d\n", port);
}

/*
 * Do initialization for device that is only needed on
 * first detect, not on resets.
 */
static int loadtime_init(struct hfi1_devdata *dd)
{
	return 0;
}

/**
 * init_after_reset - re-initialize after a reset
 * @dd: the hfi1_ib device
 *
 * sanity check at least some of the values after reset, and
 * ensure no receive or transmit (explicitly, in case reset
 * failed
 */
static int init_after_reset(struct hfi1_devdata *dd)
{
	struct hfi1_devrsrcs *dr = &dd->rsrcs;
	int i;
	int j;
	struct hfi1_ctxtdata *rcd;
	/*
	 * Ensure chip does no sends or receives, tail updates, or
	 * pioavail updates while we re-initialize.  This is mostly
	 * for the driver data structures, not chip registers.
	 */
	for (i = 0; i < dd->num_pports; i++) {
		struct hfi1_portrsrcs *pr = &dr->ppr[i];

		for (j = 0; j < pr->num_rcv_contexts; j++) {
			u16 ctxt = pr->rcv_context_base + j;

			rcd = hfi1_rcd_get_by_index(dd, ctxt);
			hfi1_rcvctrl(dd, HFI1_RCVCTRL_CTXT_DIS |
				     HFI1_RCVCTRL_INTRAVAIL_DIS |
				     HFI1_RCVCTRL_TAILUPD_DIS, rcd);
			hfi1_rcd_put(rcd);
		}
	}
	for (i = 0; i < dd->num_pports; i++)
		pio_send_control(&dd->pport[i], PSC_GLOBAL_DISABLE);
	for (i = 0; i < dd->num_send_contexts; i++)
		sc_disable(dd->send_contexts[i].sc);

	return 0;
}

void hfi1_enable_kctxt(struct hfi1_devdata *dd, struct hfi1_ctxtdata *rcd)
{
	u32 rcvmask;

	rcvmask = HFI1_RCVCTRL_CTXT_ENB
		  | HFI1_RCVCTRL_INTRAVAIL_ENB;
	if (HFI1_CAP_KGET_MASK(rcd->flags, DMA_RTAIL))
		rcvmask |= HFI1_RCVCTRL_TAILUPD_ENB;
	else
		rcvmask |= HFI1_RCVCTRL_TAILUPD_DIS;
	if (!HFI1_CAP_KGET_MASK(rcd->flags, MULTI_PKT_EGR))
		rcvmask |= HFI1_RCVCTRL_ONE_PKT_EGR_ENB;
	if (HFI1_CAP_KGET_MASK(rcd->flags, NODROP_RHQ_FULL))
		rcvmask |= HFI1_RCVCTRL_NO_RHQ_DROP_ENB;
	if (HFI1_CAP_KGET_MASK(rcd->flags, NODROP_EGR_FULL))
		rcvmask |= HFI1_RCVCTRL_NO_EGR_DROP_ENB;
	if (HFI1_CAP_IS_KSET(TID_RDMA))
		rcvmask |= HFI1_RCVCTRL_TIDFLOW_ENB;
	hfi1_rcvctrl(dd, rcvmask, rcd);
	sc_enable(rcd->sc);
}

static void enable_chip(struct hfi1_devdata *dd)
{
	struct hfi1_devrsrcs *dr = &dd->rsrcs;
	struct hfi1_ctxtdata *rcd;
	u16 i;
	u16 j;

	/* enable PIO send */
	for (i = 0; i < dd->num_pports; i++)
		pio_send_control(&dd->pport[i], PSC_GLOBAL_ENABLE);

	/*
	 * Enable kernel ctxts' receive and receive interrupt.
	 * Other ctxts done as user opens and initializes them.
	 */
	for (i = 0; i < dd->num_pports; i++) {
		struct hfi1_portrsrcs *pr = &dr->ppr[i];

		for (j = 0; j < pr->n_krcv_queues; j++) {
			u16 ctxt = pr->rcv_context_base + j;

			rcd = hfi1_rcd_get_by_index(dd, ctxt);
			if (!rcd)
				continue;
			hfi1_enable_kctxt(dd, rcd);
			hfi1_rcd_put(rcd);
		}
	}
}

/**
 * create_workqueues - create per port workqueues
 * @dd: the hfi1_ib device
 */
static int create_workqueues(struct hfi1_devdata *dd)
{
	int pidx;
	struct hfi1_pportdata *ppd;

	if (!dd->hfi1_wq) {
		dd->hfi1_wq = alloc_workqueue("hfi%d",
					      WQ_SYSFS | WQ_HIGHPRI |
					      WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM,
					      HFI1_MAX_ACTIVE_GEN_WQ_ENTRIES,
					      dd->unit);
		if (!dd->hfi1_wq)
			goto wq_error;
	}
	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;
		if (!ppd->link_wq) {
			/*
			 * Make the link workqueue single-threaded to enforce
			 * serialization.
			 */
			ppd->link_wq = alloc_workqueue("hfi_link_%d_%d",
						       WQ_SYSFS |
						       WQ_MEM_RECLAIM |
						       WQ_UNBOUND,
						       1, /* max_active */
						       dd->unit, pidx);
			if (!ppd->link_wq) {
				pr_err("alloc_workqueue failed for port %d\n",
				       pidx + 1);
				goto wq_error;
			}
		}
	}
	return 0;

wq_error:
	destroy_workqueues(dd);
	return -ENOMEM;
}

/**
 * destroy_workqueues - destroy per port workqueues
 * @dd: the hfi1_ib device
 */
static void destroy_workqueues(struct hfi1_devdata *dd)
{
	int pidx;
	struct hfi1_pportdata *ppd;

	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;

		if (ppd->link_wq) {
			destroy_workqueue(ppd->link_wq);
			ppd->link_wq = NULL;
		}
	}
	if (dd->hfi1_wq) {
		destroy_workqueue(dd->hfi1_wq);
		dd->hfi1_wq = NULL;
	}
}

/**
 * enable_general_intr() - Enable the IRQs that will be handled by the
 * general interrupt handler.
 * @dd: valid devdata
 *
 */
static void enable_general_intr(struct hfi1_devdata *dd)
{
	const struct gi_enable_entry *entry = dd->params->gi_enable_table;

	for (; entry->start <= entry->end; entry++)
		set_intr_bits(dd, entry->start, entry->end, true);
}

static void wfr_start_port(struct hfi1_pportdata *ppd)
{
	int ret;

	init_qsfp_int(ppd);

	/*
	 * start the serdes - must be after interrupts are
	 * enabled so we are notified when the link goes up
	 */
	ret = bringup_serdes(ppd);
	if (ret)
		ppd_dev_info(ppd, "Failed to bring up port\n");
}

static void wfr_stop_port(struct hfi1_pportdata *ppd)
{
	/*
	 * Clear SerdesEnable.
	 * We can't count on interrupts since we are stopping.
	 */
	hfi1_quiet_serdes(ppd);
	if (ppd->link_wq)
		flush_workqueue(ppd->link_wq);
}

/**
 * hfi1_init - do the actual initialization sequence on the chip
 * @dd: the hfi1_ib device
 * @reinit: re-initializing, so don't allocate new memory
 *
 * Do the actual initialization sequence on the chip.  This is done
 * both from the init routine called from the PCI infrastructure, and
 * when we reset the chip, or detect that it was reset internally,
 * or it's administratively re-enabled.
 *
 * Memory allocation here and in called routines is only done in
 * the first case (reinit == 0).  We have to be careful, because even
 * without memory allocation, we need to re-write all the chip registers
 * TIDs, etc. after the reset or enable has completed.
 */
int hfi1_init(struct hfi1_devdata *dd, int reinit)
{
	struct hfi1_devrsrcs *dr = &dd->rsrcs;
	int ret = 0, pidx, lastfail = 0;
	unsigned long len;
	u16 i;
	struct hfi1_ctxtdata *rcd;
	struct hfi1_pportdata *ppd;

	/* Set up send low level handlers */
	dd->process_pio_send = hfi1_verbs_send_pio;
	dd->process_dma_send = hfi1_verbs_send_dma;
	dd->pio_inline_send = pio_copy;
	dd->process_vnic_dma_send = hfi1_vnic_send_dma;

	if (is_ax(dd)) {
		atomic_set(&dd->drop_packet, DROP_PACKET_ON);
		dd->do_drop = true;
	} else {
		atomic_set(&dd->drop_packet, DROP_PACKET_OFF);
		dd->do_drop = false;
	}

	/* make sure the link is not "up" */
	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;
		ppd->linkup = 0;
	}

	if (reinit)
		ret = init_after_reset(dd);
	else
		ret = loadtime_init(dd);
	if (ret)
		goto done;

	/* dd->rcd can be NULL if early initialization failed */
	for (pidx = 0; dd->rcd && pidx < dd->num_pports; pidx++) {
		struct hfi1_portrsrcs *pr = &dr->ppr[pidx];

		for (i = 0; i < pr->n_krcv_queues; ++i) {
			u16 ctxt = pr->rcv_context_base + i;
			/*
			 * Set up the (kernel) rcvhdr queue and egr TIDs.  If
			 * doing re-init, the simplest way to handle this is
			 * to free existing, and re-allocate.
			 * Need to re-create rest of ctxt 0 ctxtdata as well.
			 */
			rcd = hfi1_rcd_get_by_index(dd, ctxt);
			if (!rcd)
				continue;

			lastfail = hfi1_create_rcvhdrq(dd, rcd);
			if (!lastfail)
				lastfail = hfi1_setup_eagerbufs(rcd);
			if (!lastfail)
				lastfail = hfi1_kern_exp_rcv_init(rcd, reinit);
			if (lastfail) {
				dd_dev_err(dd,
					   "failed to allocate kernel ctxt's rcvhdrq and/or egr bufs\n");
				ret = lastfail;
			}
			/* enable IRQ */
			hfi1_rcd_put(rcd);
		}
	}

	/* Allocate enough memory for user event notification. */
	len = PAGE_ALIGN(chip_rcv_contexts(dd) * HFI1_MAX_SHARED_CTXTS *
			 sizeof(*dd->events));
	dd->events = vmalloc_user(len);
	if (!dd->events)
		dd_dev_err(dd, "Failed to allocate user events page\n");
	/*
	 * Allocate a page for device and port status.
	 * Page will be shared amongst all user processes.
	 */
	dd->status = vmalloc_user(PAGE_SIZE);
	if (!dd->status)
		dd_dev_err(dd, "Failed to allocate dev status page\n");
	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;
		if (dd->status)
			ppd->statusp = &dd->status->ports[pidx];

		set_mtu(ppd);
	}

	/* enable chip even if we have an error, so we can debug cause */
	enable_chip(dd);

done:
	/*
	 * Set status even if port serdes is not initialized
	 * so that diags will work.
	 */
	if (dd->status)
		dd->status->dev |= HFI1_STATUS_CHIP_PRESENT |
			HFI1_STATUS_INITTED;
	if (!ret) {
		/* enable all interrupts from the chip */
		enable_general_intr(dd);

		/* chip is OK for user apps; mark it as initialized */
		for (pidx = 0; pidx < dd->num_pports; ++pidx) {
			ppd = dd->pport + pidx;

			dd->params->start_port(ppd);

			/*
			 * Set status even if port serdes is not initialized
			 * so that diags will work.
			 */
			if (ppd->statusp)
				*ppd->statusp |= HFI1_STATUS_CHIP_PRESENT |
							HFI1_STATUS_INITTED;
		}
	}

	/* if ret is non-zero, we probably should do some cleanup here... */
	return ret;
}

struct hfi1_devdata *hfi1_lookup(int unit)
{
	return xa_load(&hfi1_dev_table, unit);
}

/*
 * Stop the timers during unit shutdown, or after an error late
 * in initialization.
 */
static void stop_timers(struct hfi1_devdata *dd)
{
	struct hfi1_pportdata *ppd;
	int pidx;

	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;
		if (ppd->led_override_timer.function) {
			del_timer_sync(&ppd->led_override_timer);
			atomic_set(&ppd->led_override_timer_active, 0);
		}
		if (ppd->ibport_data.rvp.trap_timer.function) {
			del_timer_sync(&ppd->ibport_data.rvp.trap_timer);
		}
	}
}

/**
 * shutdown_device - shut down a device
 * @dd: the hfi1_ib device
 *
 * This is called to make the device quiet when we are about to
 * unload the driver, and also when the device is administratively
 * disabled.   It does not free any data structures.
 * Everything it does has to be setup again by hfi1_init(dd, 1)
 */
static void shutdown_device(struct hfi1_devdata *dd)
{
	struct hfi1_devrsrcs *dr = &dd->rsrcs;
	struct hfi1_pportdata *ppd;
	struct hfi1_ctxtdata *rcd;
	unsigned pidx;
	int i;

	if (dd->flags & HFI1_SHUTDOWN)
		return;
	dd->flags |= HFI1_SHUTDOWN;

	if (dd->bulksvc)
		hfi1_bulksvc_teardown(dd);

	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;

		ppd->linkup = 0;
		if (ppd->statusp)
			*ppd->statusp &= ~(HFI1_STATUS_IB_CONF |
					   HFI1_STATUS_IB_READY);
	}
	dd->flags &= ~HFI1_INITTED;

	/*
	 * Drop all traps.  After this point, there should be no more cport
	 * handlers that depend on driver state.
	 */
	clearall_cport_trap(dd);

	/* disable all interrupts except cport response */
	if (dd->params->chip_type == CHIP_WFR) {
		/* WFR has no cport */
		set_intr_bits(dd, 0, dd->params->is_last_source, false);
		msix_shut_down_interrupts(dd, false);
	} else {
		/* mask all but the cport interrupt source */
		set_intr_bits(dd, 0, dd->params->is_cport_int - 1, false);
		set_intr_bits(dd, dd->params->is_cport_int + 1,
			      dd->params->is_last_source, false);
		msix_shut_down_interrupts(dd, true);
	}

	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		struct hfi1_portrsrcs *pr = &dr->ppr[pidx];

		ppd = dd->pport + pidx;
		for (i = 0; i < pr->num_rcv_contexts; i++) {
			u16 ctxt = pr->rcv_context_base + i;

			rcd = hfi1_rcd_get_by_index(dd, ctxt);
			hfi1_rcvctrl(dd, HFI1_RCVCTRL_TAILUPD_DIS |
				     HFI1_RCVCTRL_CTXT_DIS |
				     HFI1_RCVCTRL_INTRAVAIL_DIS |
				     HFI1_RCVCTRL_PKEY_DIS |
				     HFI1_RCVCTRL_ONE_PKT_EGR_DIS, rcd);
			hfi1_rcd_put(rcd);
		}
	}
	/*
	 * Gracefully stop all sends allowing any in progress to
	 * trickle out first.
	 */
	for (i = 0; i < dd->num_send_contexts; i++)
		sc_flush(dd->send_contexts[i].sc);

	/*
	 * Enough for anything that's going to trickle out to have actually
	 * done so.
	 */
	udelay(20);

	/* disable all contexts */
	for (i = 0; i < dd->num_send_contexts; i++)
		sc_disable(dd->send_contexts[i].sc);

	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;

		/* disable the send device */
		pio_send_control(ppd, PSC_GLOBAL_DISABLE);

		dd->params->shutdown_led_override(ppd);

		dd->params->stop_port(ppd);
	}
	if (dd->hfi1_wq)
		flush_workqueue(dd->hfi1_wq);

	sdma_exit(dd);
}

/*
 * SRIOV has been disabled. Do any cleanup not handled by
 * VF remove_one() calls.
 */
void hfi1_pf0_cleanup(struct hfi1_devdata *dd)
{
	/* TODO: other cleanup */
}

/**
 * hfi1_free_ctxtdata - free a context's allocated data
 * @dd: the hfi1_ib device
 * @rcd: the ctxtdata structure
 *
 * free up any allocated data for a context
 * It should never change any chip state, or global driver state.
 */
void hfi1_free_ctxtdata(struct hfi1_devdata *dd, struct hfi1_ctxtdata *rcd)
{
	u32 e;

	if (!rcd)
		return;

	if (rcd->rcvhdrq) {
		dma_free_coherent(&dd->pcidev->dev, rcvhdrq_size(rcd),
				  rcd->rcvhdrq, rcd->rcvhdrq_dma);
		rcd->rcvhdrq = NULL;
		if (hfi1_rcvhdrtail_kvaddr(rcd)) {
			dma_free_coherent(&dd->pcidev->dev, PAGE_SIZE,
					  (void *)hfi1_rcvhdrtail_kvaddr(rcd),
					  rcd->rcvhdrqtailaddr_dma);
			rcd->rcvhdrtail_kvaddr = NULL;
		}
	}
	if (rcd->rheq) {
		dma_free_coherent(&dd->pcidev->dev, rheq_size(rcd),
				  rcd->rheq, rcd->rheq_dma);
		rcd->rheq = NULL;
	}

	/* all the RcvArray entries should have been cleared by now */
	kfree(rcd->egrbufs.rcvtids);
	rcd->egrbufs.rcvtids = NULL;

	for (e = 0; e < rcd->egrbufs.alloced; e++) {
		if (rcd->egrbufs.buffers[e].addr)
			dma_free_coherent(&dd->pcidev->dev,
					  rcd->egrbufs.buffers[e].len,
					  rcd->egrbufs.buffers[e].addr,
					  rcd->egrbufs.buffers[e].dma);
	}
	kfree(rcd->egrbufs.buffers);
	rcd->egrbufs.alloced = 0;
	rcd->egrbufs.buffers = NULL;

	sc_free(rcd->sc);
	rcd->sc = NULL;

	vfree(rcd->subctxt_uregbase);
	vfree(rcd->subctxt_rcvegrbuf);
	vfree(rcd->subctxt_rcvhdr_base);
	kfree(rcd->opstats);

	rcd->subctxt_uregbase = NULL;
	rcd->subctxt_rcvegrbuf = NULL;
	rcd->subctxt_rcvhdr_base = NULL;
	rcd->opstats = NULL;
}

/*
 * Release our hold on the shared asic data.  If we are the last one,
 * return the structure to be finalized outside the lock.  Must be
 * holding hfi1_dev_table lock.
 */
static struct hfi1_asic_data *release_asic_data(struct hfi1_devdata *dd)
{
	struct hfi1_asic_data *ad;
	int other;

	if (!dd->asic_data)
		return NULL;
	dd->asic_data->dds[dd->hfi1_id] = NULL;
	other = dd->hfi1_id ? 0 : 1;
	ad = dd->asic_data;
	dd->asic_data = NULL;
	/* return NULL if the other dd still has a link */
	return ad->dds[other] ? NULL : ad;
}

static void finalize_asic_data(struct hfi1_devdata *dd,
			       struct hfi1_asic_data *ad)
{
	clean_up_i2c(dd, ad);
	kfree(ad);
}

/**
 * hfi1_free_devdata - cleans up and frees per-unit data structure
 * @dd: pointer to a valid devdata structure
 *
 * It cleans up and frees all data structures set up by
 * by hfi1_alloc_devdata().
 */
static void hfi1_free_devdata(struct hfi1_devdata *dd)
{
	struct hfi1_asic_data *ad;
	unsigned long flags;

	xa_lock_irqsave(&hfi1_dev_table, flags);
	__xa_erase(&hfi1_dev_table, dd->unit);
	ad = release_asic_data(dd);
	xa_unlock_irqrestore(&hfi1_dev_table, flags);

	finalize_asic_data(dd, ad);
	free_platform_config(dd);
	rcu_barrier(); /* wait for rcu callbacks to complete */
	free_percpu(dd->int_counter);
	free_percpu(dd->rcv_limit);
	free_percpu(dd->send_schedule);
	free_percpu(dd->tx_opstats);
	dd->int_counter   = NULL;
	dd->rcv_limit     = NULL;
	dd->send_schedule = NULL;
	dd->tx_opstats    = NULL;
	kfree(dd->comp_vect);
	dd->comp_vect = NULL;
	if (dd->rcvhdrtail_dummy_kvaddr)
		dma_free_coherent(&dd->pcidev->dev, sizeof(u64),
				  (void *)dd->rcvhdrtail_dummy_kvaddr,
				  dd->rcvhdrtail_dummy_dma);
	dd->rcvhdrtail_dummy_kvaddr = NULL;
	sdma_clean(dd);
	hfi1_bulksvc_teardown(dd);
	hfi1_sriov_free_cfg(dd);
	/* dd is freed by the time this returns: */
	rvt_dealloc_device(&dd->verbs_dev.rdi);
}

/**
 * hfi1_alloc_devdata - Allocate our primary per-unit data structure.
 * @pdev: Valid PCI device
 * @extra: How many bytes to alloc past the default
 *
 * Must be done via verbs allocator, because the verbs cleanup process
 * both does cleanup and free of the data structure.
 * "extra" is for chip-specific data.
 */
static struct hfi1_devdata *hfi1_alloc_devdata(struct pci_dev *pdev,
					       const struct chip_params *params)
{
	struct hfi1_devdata *dd;
	size_t extra;
	int ret, nports;

	nports = params->num_ports;
	extra = nports * sizeof(struct hfi1_pportdata);
	dd = (struct hfi1_devdata *)rvt_alloc_device(sizeof(*dd) + extra,
						     nports);
	if (!dd)
		return ERR_PTR(-ENOMEM);
	dd->params = params;
	dd->num_pports = nports;
	dd->pport = (struct hfi1_pportdata *)(dd + 1);
	dd->pcidev = pdev;
	/*
	 * Check for PCI device being a VF in SRIOV.
	 * The VFs do not have a Power Management capability block.
	 */
	dd->is_vf = (params->chip_type != CHIP_WFR && !pdev->pm_cap);
	dd->is_sriov = (dd->is_vf || sriov_is_enabled());
#if defined(CONFIG_X86)
	dd->is_vm = boot_cpu_has(X86_FEATURE_HYPERVISOR);
#endif
#ifdef PDEV_SRIOV_DEBUG
	dev_warn(&pdev->dev, "is_vm=%d is_vf=%d is_physfn=%d is_virtfn=%d physfn=%p\n",
		dd->is_vm, dd->is_vf, pdev->is_physfn, pdev->is_virtfn, pdev->physfn);
#endif
	pci_set_drvdata(pdev, dd);

	/*
	 * Must set DMA mask for device before any dma_map*() or
	 * dma_alloc*() calls referring to pdev->dev. Otherwise
	 * those calls may return DMA addresses that are
	 * incompatible with the HFI.
	 */
	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(params->dma_mask_bits));
	if (ret) {
		dd_dev_warn(dd, "Failed to set %u-bit DMA mask ret %d; setting 32-bit DMA mask\n",
			    params->dma_mask_bits, ret);
		ret = dma_set_mask_and_coherent(&pdev->dev,
						DMA_BIT_MASK(32));
		if (ret) {
			dd_dev_err(dd, "Unable to set DMA mask: %d\n",
				   ret);
			goto bail;
		}
	}

	hfi1_snoop_init(dd);

	ret = xa_alloc_irq(&hfi1_dev_table, &dd->unit, dd, xa_limit_32b,
			GFP_KERNEL);
	if (ret < 0) {
		dev_err(&pdev->dev,
			"Could not allocate unit ID: error %d\n", -ret);
		goto bail;
	}
	rvt_set_ibdev_name(&dd->verbs_dev.rdi, "%s_%d", class_name(), dd->unit);
	/*
	 * If the BIOS does not have the NUMA node information set, select
	 * NUMA 0 so we get consistent performance.
	 */
	dd->node = pcibus_to_node(pdev->bus);
	if (dd->node == NUMA_NO_NODE) {
		dd_dev_err(dd, "Invalid PCI NUMA node. Performance may be affected\n");
		dd->node = 0;
	}

	/*
	 * Initialize all locks for the device. This needs to be as early as
	 * possible so locks are usable.
	 */
	spin_lock_init(&dd->sc_lock);
	spin_lock_init(&dd->sendctrl_lock);
	spin_lock_init(&dd->rcvctrl_lock);
	spin_lock_init(&dd->uctxt_lock);
	spin_lock_init(&dd->hfi1_diag_trans_lock);
	spin_lock_init(&dd->sc_init_lock);
	spin_lock_init(&dd->dc8051_memlock);
	spin_lock_init(&dd->sde_map_lock);
	spin_lock_init(&dd->pio_map_lock);
	mutex_init(&dd->dc8051_lock);
	init_waitqueue_head(&dd->event_queue);
	spin_lock_init(&dd->irq_src_lock);
	INIT_WORK(&dd->freeze_work, handle_freeze);

	dd->int_counter = alloc_percpu(u64);
	if (!dd->int_counter) {
		ret = -ENOMEM;
		goto bail;
	}

	dd->rcv_limit = alloc_percpu(u64);
	if (!dd->rcv_limit) {
		ret = -ENOMEM;
		goto bail;
	}

	dd->send_schedule = alloc_percpu(u64);
	if (!dd->send_schedule) {
		ret = -ENOMEM;
		goto bail;
	}

	dd->tx_opstats = alloc_percpu(struct hfi1_opcode_stats_perctx);
	if (!dd->tx_opstats) {
		ret = -ENOMEM;
		goto bail;
	}

	dd->comp_vect = kzalloc(sizeof(*dd->comp_vect), GFP_KERNEL);
	if (!dd->comp_vect) {
		ret = -ENOMEM;
		goto bail;
	}

	/* allocate dummy tail memory for all receive contexts */
	dd->rcvhdrtail_dummy_kvaddr =
		dma_alloc_coherent(&dd->pcidev->dev, sizeof(u64),
				   &dd->rcvhdrtail_dummy_dma, GFP_KERNEL);
	if (!dd->rcvhdrtail_dummy_kvaddr) {
		ret = -ENOMEM;
		goto bail;
	}

	/* If we are going to be loaning resources, find out which ones */
	dd->verbs_dev.rdi.use_bulksvc = false;
	if (use_bulksvc) {
		if (hfi1_max_sges > 255) {
			pr_err("When using bulksvc, only 255 sges may be used\n");
			goto bail;
		}

		if (dd->params->chip_type == CHIP_WFR)
			dd_dev_dbg(dd, "bulksvc not supported on WFR\n");
		else {
			ret = hfi1_bulksvc_init(dd);
			if (ret)
				goto bail;
		}
	}

	return dd;

bail:
	hfi1_free_devdata(dd);
	return ERR_PTR(ret);
}

/*
 * Called from freeze mode handlers, and from PCI error
 * reporting code.  Should be paranoid about state of
 * system and data structures.
 */
void hfi1_disable_after_error(struct hfi1_devdata *dd)
{
	if (dd->flags & HFI1_INITTED) {
		u32 pidx;

		dd->flags &= ~HFI1_INITTED;
		if (dd->pport)
			for (pidx = 0; pidx < dd->num_pports; ++pidx) {
				struct hfi1_pportdata *ppd;

				ppd = dd->pport + pidx;
				if (dd->flags & HFI1_PRESENT)
					set_link_state(ppd, HLS_DN_DISABLE);

				if (ppd->statusp)
					*ppd->statusp &= ~HFI1_STATUS_IB_READY;
			}
	}

	/*
	 * Mark as having had an error for driver, and also
	 * for /sys and status word mapped to user programs.
	 * This marks unit as not usable, until reset.
	 */
	if (dd->status)
		dd->status->dev |= HFI1_STATUS_HWERROR;
}

static void remove_one(struct pci_dev *);
static int init_one(struct pci_dev *, const struct pci_device_id *);
static void shutdown_one(struct pci_dev *);

#define DRIVER_LOAD_MSG "Cornelis " DRIVER_NAME " loaded: "
#define PFX DRIVER_NAME ": "

const struct pci_device_id hfi1_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL0) },
	{ PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL1) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CORNELIS, PCI_DEVICE_ID_CORNELIS_CN5000) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, hfi1_pci_tbl);

static struct pci_driver hfi1_pci_driver = {
	.name = DRIVER_NAME,
	.probe = init_one,
	.remove = remove_one,
	.shutdown = shutdown_one,
	.id_table = hfi1_pci_tbl,
	.err_handler = &hfi1_pci_err_handler,
	.sriov_configure = hfi1_sriov_configure,
};

static void __init compute_krcvqs(void)
{
	int i;

	for (i = 0; i < krcvqsset; i++)
		n_krcvqs += krcvqs[i];
}

/*
 * Do all the generic driver unit- and chip-independent memory
 * allocation and initialization.
 */
static int __init hfi1_mod_init(void)
{
	int ret;

	register_system_pinning_interface();
	register_system_tid_ops();
#ifdef CONFIG_HFI1_AMD
	ret = hfi1_pin_amd_init();
	if (ret)
		goto bail;
#endif

	ret = dev_init();
	if (ret)
		goto bail;

#ifdef CONFIG_HFI1_NVIDIA
	ret = hfi1_pin_nvidia_init();
	if (ret)
		goto bail_dev;
#endif

	ret = node_affinity_init();
	if (ret)
		goto bail;

	/* validate max MTU before any devices start */
	if (!valid_opa_max_mtu(hfi1_max_mtu)) {
		pr_err("Invalid max_mtu 0x%x, using 0x%x instead\n",
		       hfi1_max_mtu, HFI1_DEFAULT_MAX_MTU);
		hfi1_max_mtu = HFI1_DEFAULT_MAX_MTU;
	}
	/* valid CUs run from 1-128 in powers of 2 */
	if (hfi1_cu > 128 || !is_power_of_2(hfi1_cu))
		hfi1_cu = 1;
	/* valid credit return threshold is 0-100, variable is unsigned */
	if (user_credit_return_threshold > 100)
		user_credit_return_threshold = 100;

	compute_krcvqs();
	/*
	 * sanitize receive interrupt count, time must wait until after
	 * the hardware type is known
	 */
	if (rcv_intr_count > RCV_HDR_HEAD_COUNTER_MASK)
		rcv_intr_count = RCV_HDR_HEAD_COUNTER_MASK;
	/* reject invalid combinations */
	if (rcv_intr_count == 0 && rcv_intr_timeout == 0) {
		pr_err("Invalid mode: both receive interrupt count and available timeout are zero - setting interrupt count to 1\n");
		rcv_intr_count = 1;
	}
	if (rcv_intr_count > 1 && rcv_intr_timeout == 0) {
		/*
		 * Avoid indefinite packet delivery by requiring a timeout
		 * if count is > 1.
		 */
		pr_err("Invalid mode: receive interrupt count greater than 1 and available timeout is zero - setting available timeout to 1\n");
		rcv_intr_timeout = 1;
	}
	if (rcv_intr_dynamic && !(rcv_intr_count > 1 && rcv_intr_timeout > 0)) {
		/*
		 * The dynamic algorithm expects a non-zero timeout
		 * and a count > 1.
		 */
		pr_err("Invalid mode: dynamic receive interrupt mitigation with invalid count and timeout - turning dynamic off\n");
		rcv_intr_dynamic = 0;
	}

	/* sanitize link CRC options */
	link_crc_mask &= SUPPORTED_CRCS;

	ret = opfn_init();
	if (ret < 0) {
		pr_err("Failed to allocate opfn_wq");
		goto bail_dev;
	}

	/*
	 * These must be called before the driver is registered with
	 * the PCI subsystem.
	 */
	hfi1_dbg_init();
	ret = pci_register_driver(&hfi1_pci_driver);
	if (ret < 0) {
		pr_err("Unable to register driver: error %d\n", -ret);
		goto bail_dev;
	}

	return 0;
bail_dev:
	hfi1_dbg_exit();
#ifdef CONFIG_HFI1_NVIDIA
	hfi1_pin_nvidia_free();
#endif
	dev_cleanup();
bail:
#ifdef CONFIG_HFI1_AMD
	hfi1_pin_amd_free();
#endif
	deregister_system_tid_ops();
	deregister_system_pinning_interface();

	return ret;
}

module_init(hfi1_mod_init);

/*
 * Do the non-unit driver cleanup, memory free, etc. at unload.
 */
static void __exit hfi1_mod_cleanup(void)
{
	pci_unregister_driver(&hfi1_pci_driver);
	opfn_exit();
	node_affinity_destroy_all();
	hfi1_dbg_exit();

	WARN_ON(!xa_empty(&hfi1_dev_table));
	dispose_firmware();	/* asymmetric with obtain_firmware() */
	dev_cleanup();

#ifdef CONFIG_HFI1_NVIDIA
	hfi1_pin_nvidia_free();
#endif
#ifdef CONFIG_HFI1_AMD
	hfi1_pin_amd_free();
#endif
	deregister_system_tid_ops();
	deregister_system_pinning_interface();
}

module_exit(hfi1_mod_cleanup);

/* this can only be called after a successful initialization */
static void cleanup_device_data(struct hfi1_devdata *dd)
{
	int ctxt;
	int pidx;

	/* users can't do anything more with chip */
	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		struct hfi1_pportdata *ppd = &dd->pport[pidx];
		struct cc_state *cc_state;
		int i;

		if (ppd->statusp)
			*ppd->statusp &= ~HFI1_STATUS_CHIP_PRESENT;

		for (i = 0; i < OPA_MAX_SLS; i++)
			hrtimer_cancel(&ppd->cca_timer[i].hrtimer);

		spin_lock(&ppd->cc_state_lock);
		cc_state = get_cc_state_protected(ppd);
		RCU_INIT_POINTER(ppd->cc_state, NULL);
		spin_unlock(&ppd->cc_state_lock);

		if (cc_state)
			kfree_rcu(cc_state, rcu);
	}

	free_credit_return(dd);

	/*
	 * Free any receive resources still in use (usually just kernel
	 * contexts) at unload.
	 */
	for (ctxt = 0; dd->rcd && ctxt < dd->num_rcd; ctxt++) {
		struct hfi1_ctxtdata *rcd = dd->rcd[ctxt];

		if (rcd) {
			hfi1_free_ctxt_rcv_groups(rcd);
			hfi1_free_ctxt(rcd);
		}
	}

	kfree(dd->rcd);
	dd->rcd = NULL;
	dd->num_rcd = 0;

	free_pio_map(dd);
	/* must follow rcv context free - need to remove rcv's hooks */
	if (dd->send_contexts) {
		for (ctxt = 0; ctxt < dd->num_send_contexts; ctxt++)
			sc_free(dd->send_contexts[ctxt].sc);
	}
	dd->num_send_contexts = 0;
	kfree(dd->send_contexts);
	dd->send_contexts = NULL;
	kfree(dd->hw_to_sw);
	dd->hw_to_sw = NULL;
	/* free netdev data */
	hfi1_free_rx(dd);
	kfree(dd->boardname);
	vfree(dd->events);
	vfree(dd->status);

	/* finalize the cport - CSR perms revoked on PF0 */
	stop_cport(dd);
	/* release interrupts */
	msix_clean_up_interrupts(dd);

	/* CSR reads and writes are invalid after this call */
	hfi1_pcie_ddcleanup(dd);
}

/*
 * Clean up on unit shutdown, or error during unit load after
 * successful initialization.
 */
static void postinit_cleanup(struct hfi1_devdata *dd)
{
	hfi1_start_cleanup(dd);
	hfi1_comp_vectors_clean_up(dd);
	hfi1_dev_affinity_clean_up(dd);
	release_rsm_rules(dd);

	cleanup_device_data(dd);

	destroy_workqueues(dd);
	hfi1_pcie_cleanup(dd->pcidev);
	hfi1_free_devdata(dd);
}

static int init_one(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int ret = 0, j, pidx, initfail;
	struct hfi1_devdata *dd;
	const struct chip_params *params;

#ifdef CONFIG_HFI_L8SIM
	if (!(pdev->bus->bus_flags & PCI_BUS_FLAGS_SIMULATED)) {
		dev_warn(&pdev->dev, "Ignoring real hardware on simulator driver\n");
		return -ENODEV;
	}
#endif
	/* VF in host driver - leave for KVM */
	if (pdev->is_virtfn) {
		/* It is theoretically possible for the host driver to claim
		 * a VF, so there may need to be some decision made whether
		 * to claim the device or leave it for KVM.
		 */
		/* TODO: how do we avoid claiming the device without
		 * producing errors and possible SRIOV-enable failure.
		 */
		ret = hfi1_sriov_init(pdev); /* may do nothing */
		if (ret)
			return ret; /* do not claim device */
	}

	/* First, lock the non-writable module parameters */
	HFI1_CAP_LOCK();

	/* Validate dev ids */
	if (ent->vendor == PCI_VENDOR_ID_INTEL &&
	    (ent->device == PCI_DEVICE_ID_INTEL0 ||
	      ent->device == PCI_DEVICE_ID_INTEL1)) {
		params = &wfr_params;
	} else if (ent->vendor == PCI_VENDOR_ID_CORNELIS &&
		   ent->device == PCI_DEVICE_ID_CORNELIS_CN5000) {
		params = &jkr_params;
	} else {
		dev_err(&pdev->dev, "Failing on unknown device %04x:%04x\n",
			ent->vendor, ent->device);
		return -ENODEV;
	}

	/* verify arrays are large enough */
	if (params->num_int_csrs > LARGEST_NUM_INT_CSRS ||
	    params->num_ports > LARGEST_NUM_PORTS ||
	    params->pkey_table_size > MAX_PKEY_VALUES) {
		dev_err(&pdev->dev, "Source arrays are compiled too small\n");
		return -EINVAL;
	}

	/* Allocate the dd so we can get to work */
	dd = hfi1_alloc_devdata(pdev, params);
	if (IS_ERR(dd))
		return PTR_ERR(dd);

	/* Validate some global module parameters */
	ret = hfi1_validate_rcvhdrcnt(dd, rcvhdrcnt);
	if (ret)
		goto free_dd;

	/* use the encoding function as a sanitization check */
	if (!encode_rcv_header_entry_size(hfi1_hdrq_entsize)) {
		dd_dev_err(dd, "Invalid HdrQ Entry size %u\n",
			   hfi1_hdrq_entsize);
		ret = -EINVAL;
		goto free_dd;
	}

	/* The receive eager buffer size must be set before the receive
	 * contexts are created.
	 *
	 * Set the eager buffer size.  Validate that it falls in a range
	 * allowed by the hardware - all powers of 2 between the min and
	 * max.  The maximum valid MTU is within the eager buffer range
	 * so we do not need to cap the max_mtu by an eager buffer size
	 * setting.
	 */
	if (eager_buffer_size) {
		if (!is_power_of_2(eager_buffer_size))
			eager_buffer_size =
				roundup_pow_of_two(eager_buffer_size);
		eager_buffer_size =
			clamp_val(eager_buffer_size,
				  MIN_EAGER_BUFFER * 8,
				  MAX_EAGER_BUFFER_TOTAL);
		dd_dev_info(dd, "Eager buffer size %u\n",
			    eager_buffer_size);
	} else {
		dd_dev_err(dd, "Invalid Eager buffer size of 0\n");
		ret = -EINVAL;
		goto free_dd;
	}

	/* restrict value of hfi1_rcvarr_split */
	hfi1_rcvarr_split = clamp_val(hfi1_rcvarr_split, 0, 100);

	ret = hfi1_pcie_init(dd);
	if (ret)
		goto free_dd;

	/* TEMP: skip rest of init if SRIOV VF */
	if (dd->is_vf)
		goto sriov_skip;

	ret = create_workqueues(dd);
	if (ret)
		goto pcie_cleanup;

	/*
	 * Do device-specific initialization.  If hfi1_init_dd() fails, it
	 * cleans up after itself.
	 */
	ret = hfi1_init_dd(dd);
	if (ret)
		goto destroy_wqs; /* error already printed */

	/* do the generic initialization */
	if (!ret)
		initfail = hfi1_init(dd, 0);

	if (!initfail && !ret)
		ret = hfi1_mad_init(dd);

	if (!initfail && !ret)
		ret = hfi1_register_ib_device(dd);

	if (!initfail && !ret)
		ret = init_cport_trap128(dd); /* after IB device register */

	/*
	 * Now ready for use.  this should be cleared whenever we
	 * detect a reset, or initiate one.  If earlier failure,
	 * we still create devices, so diags, etc. can be used
	 * to determine cause of problem.
	 */
	if (!initfail && !ret) {
		dd->flags |= HFI1_INITTED;
		/* create debufs files after init and ib register */
		hfi1_dbg_ibdev_init(&dd->verbs_dev);
	}

	j = hfi1_device_create(dd);
	if (j)
		dd_dev_err(dd, "Failed to create /dev devices: %d\n", -j);

	if (initfail || ret) {
		stop_cport(dd);
		msix_clean_up_interrupts(dd);
		stop_timers(dd);
		flush_workqueue(ib_wq);
		for (pidx = 0; pidx < dd->num_pports; ++pidx)
			dd->params->stop_port(dd->pport + pidx);
		if (!j)
			hfi1_device_remove(dd);
		if (!ret) {
			hfi1_unregister_ib_device(dd);
			hfi1_mad_deinit(dd);
		}
		postinit_cleanup(dd);
		if (initfail)
			ret = initfail;
		goto bail;	/* everything already cleaned */
	}

	// take the engines we know we're going to borrow and
	// disable their generation checking logic later
	// because it gets set in an interrupt context
	// which may occur at a later time
	if (dd->bulksvc) {
		u32 last = dd->rsrcs.last_sdma_engine;
		u32 sdma_avail = last - dd->rsrcs.first_sdma_engine;
		u32 to_borrow = dd->bulksvc->prereqs.num_sdma;
		if (!to_borrow || to_borrow > sdma_avail) {
			dd_dev_err(dd, "bulksvc requires %u SDMA engines, but only %u available\n",
				   to_borrow, sdma_avail);
			ret = -ENOSPC;
			goto destroy_wqs;
		}

		for (u32 i = (last - to_borrow); i < last; i++) {
			struct sdma_engine *sde = &dd->per_sdma[i];
			sde->check_generation = SDMA_CHECK_GEN_DISABLE;
		}
	}

	sdma_start(dd);
	init_cport_overtemp(dd);

	if (dd->bulksvc) {
		ret = hfi1_bulksvc_loan_resources(dd);
		if (ret)
			goto destroy_wqs;
	}

	hfi1_sriov_auto_conf(dd);
sriov_skip:
	return 0;

destroy_wqs:
	destroy_workqueues(dd);
pcie_cleanup:
	hfi1_pcie_cleanup(pdev);
free_dd:
	hfi1_free_devdata(dd);
bail:
	return ret;
}

static void wait_for_clients(struct hfi1_devdata *dd)
{
	/*
	 * Remove the device init value and complete the device if there is
	 * no clients or wait for active clients to finish.
	 */
	if (refcount_dec_and_test(&dd->user_refcount))
		complete(&dd->user_comp);

	wait_for_completion(&dd->user_comp);
}

/*
 * This is called for rmmod or other driver-device unbinds.
 * (and now by shutdown_one() if not WFR)
 */
static void remove_one(struct pci_dev *pdev)
{
	struct hfi1_devdata *dd = pci_get_drvdata(pdev);

	if (pdev->is_virtfn) {
		/*
		 * Should only reach here if the VF was claimed by the driver,
		 * however, this cannot destroy device functionality.
		 */
		hfi1_sriov_remove(pdev); /* TODO: does this need to be last? */
	}

	/*
	 * If VFs are still active, must shut them down now,
	 * before PF0 becomes unusable.
	 */
	if (pdev->is_physfn)
		hfi1_sriov_disable(dd->pcidev);

	/* close debugfs files before ib unregister */
	hfi1_dbg_ibdev_exit(&dd->verbs_dev);

	/* remove the /dev hfi1 interface */
	hfi1_device_remove(dd);

	/* wait for existing user space clients to finish */
	wait_for_clients(dd);

	/* unregister from IB core */
	hfi1_unregister_ib_device(dd);

	/* stop handling LOCAL_MAD_ from CPORT */
	hfi1_mad_deinit(dd);

	/*
	 * Disable the IB link, disable interrupts on the device,
	 * clear dma engines, etc.
	 */
	shutdown_device(dd);

	stop_timers(dd);

	/* wait until all of our (qsfp) queue_work() calls complete */
	flush_workqueue(ib_wq);

	postinit_cleanup(dd);
}

/*
 * This is called during system reboot/shutdown/halt.
 */
static void shutdown_one(struct pci_dev *pdev)
{
	struct hfi1_devdata *dd = pci_get_drvdata(pdev);

	if (dd->params->chip_type == CHIP_WFR)
		shutdown_device(dd);
	else
		remove_one(pdev);
}

/* The device has reported over-temp and will shutdown soon (~500mS) */
void hfi1_overtemp(struct hfi1_devdata *dd)
{
	dd_dev_err(dd, "*** OVER TEMP *** device shutdown imminent!\n");
	/* take some action to gracefully shut down/quiesce */
}

/**
 * hfi1_create_rcvhdrq - create a receive header queue
 * @dd: the hfi1_ib device
 * @rcd: the context data
 *
 * This must be contiguous memory (from an i/o perspective), and must be
 * DMA'able (which means for some systems, it will go through an IOMMU,
 * or be forced into a low address range).
 */
int hfi1_create_rcvhdrq(struct hfi1_devdata *dd, struct hfi1_ctxtdata *rcd)
{
	u32 amt = rcvhdrq_size(rcd);

	if (!rcd->rcvhdrq) {
		rcd->rcvhdrq = dma_alloc_coherent(&dd->pcidev->dev, amt,
						  &rcd->rcvhdrq_dma,
						  GFP_KERNEL);

		if (!rcd->rcvhdrq) {
			dd_dev_err(dd,
				   "attempt to allocate %d bytes for ctxt %u rcvhdrq failed\n",
				   amt, rcd->ctxt);
			goto bail;
		}

		if (HFI1_CAP_KGET_MASK(rcd->flags, DMA_RTAIL) ||
		    HFI1_CAP_UGET_MASK(rcd->flags, DMA_RTAIL)) {
			rcd->rcvhdrtail_kvaddr = dma_alloc_coherent(&dd->pcidev->dev,
								    PAGE_SIZE,
								    &rcd->rcvhdrqtailaddr_dma,
								    GFP_KERNEL);
			if (!rcd->rcvhdrtail_kvaddr) {
				dd_dev_err(dd,
					   "attempt to allocate 1 page for ctxt %u rcvhdrqtailaddr failed\n",
					   rcd->ctxt);
				goto rhq_free;
			}
		}

		if (dd->params->chip_type != CHIP_WFR) {
			u32 rheq_amt = rheq_size(rcd);

			rcd->rheq = dma_alloc_coherent(&dd->pcidev->dev,
						       rheq_amt,
						       &rcd->rheq_dma,
						       GFP_KERNEL);
			if (!rcd->rheq) {
				dd_dev_err(dd,
					   "attempt to allocate %d bytes for ctxt %u rheq failed\n",
					   rheq_amt, rcd->ctxt);
				goto tail_free;
			}
		}
	}

	set_hdrq_regs(rcd->ppd, rcd->ctxt, rcd->rcvhdrqentsize,
		      rcd->rcvhdrq_cnt, rcd->kdeth_rcv_hdr);

	return 0;

tail_free:
	if (rcd->rcvhdrtail_kvaddr) {
		dma_free_coherent(&dd->pcidev->dev, PAGE_SIZE,
				  (void *)hfi1_rcvhdrtail_kvaddr(rcd),
				  rcd->rcvhdrqtailaddr_dma);
		rcd->rcvhdrtail_kvaddr = NULL;
	}
rhq_free:
	dma_free_coherent(&dd->pcidev->dev, amt, rcd->rcvhdrq,
			  rcd->rcvhdrq_dma);
	rcd->rcvhdrq = NULL;
bail:
	return -ENOMEM;
}

/**
 * hfi1_setup_eagerbufs - allocate eager buffers, both kernel and user
 * contexts.
 * @rcd: the context we are setting up.
 *
 * Allocate the eager TID buffers and program them into the chip.
 * They are no longer completely contiguous, we do multiple allocation
 * calls.  Otherwise we get the OOM code involved, by asking for too
 * much per call, with disastrous results on some kernels.
 */
int hfi1_setup_eagerbufs(struct hfi1_ctxtdata *rcd)
{
	struct hfi1_devdata *dd = rcd->dd;
	u32 max_entries, egrtop, alloced_bytes = 0;
	u16 order, idx = 0;
	int ret = 0;
	u16 round_mtu = roundup_pow_of_two(hfi1_max_mtu);

	/*
	 * The minimum size of the eager buffers is a groups of MTU-sized
	 * buffers.
	 * The global eager_buffer_size parameter is checked against the
	 * theoretical lower limit of the value. Here, we check against the
	 * MTU.
	 */
	if (rcd->egrbufs.size < (round_mtu * dd->rcv_entries.group_size))
		rcd->egrbufs.size = round_mtu * dd->rcv_entries.group_size;
	/*
	 * If using one-pkt-per-egr-buffer, lower the eager buffer
	 * size to the max MTU (page-aligned).
	 */
	if (!HFI1_CAP_KGET_MASK(rcd->flags, MULTI_PKT_EGR))
		rcd->egrbufs.rcvtid_size = round_mtu;

	/*
	 * Eager buffers sizes of 1MB or less require smaller TID sizes
	 * to satisfy the "multiple of 8 RcvArray entries" requirement.
	 */
	if (rcd->egrbufs.size <= (1 << 20))
		rcd->egrbufs.rcvtid_size = max((unsigned long)round_mtu,
			rounddown_pow_of_two(rcd->egrbufs.size / 8));

	while (alloced_bytes < rcd->egrbufs.size &&
	       rcd->egrbufs.alloced < rcd->egrbufs.count) {
		rcd->egrbufs.buffers[idx].addr =
			dma_alloc_coherent(&dd->pcidev->dev,
					   rcd->egrbufs.rcvtid_size,
					   &rcd->egrbufs.buffers[idx].dma,
					   GFP_KERNEL);
		if (rcd->egrbufs.buffers[idx].addr) {
			rcd->egrbufs.buffers[idx].len =
				rcd->egrbufs.rcvtid_size;
			rcd->egrbufs.rcvtids[rcd->egrbufs.alloced].addr =
				rcd->egrbufs.buffers[idx].addr;
			rcd->egrbufs.rcvtids[rcd->egrbufs.alloced].dma =
				rcd->egrbufs.buffers[idx].dma;
			rcd->egrbufs.alloced++;
			alloced_bytes += rcd->egrbufs.rcvtid_size;
			idx++;
		} else {
			u32 new_size, i, j;
			u64 offset = 0;

			/*
			 * Fail the eager buffer allocation if:
			 *   - we are already using the lowest acceptable size
			 *   - we are using one-pkt-per-egr-buffer (this implies
			 *     that we are accepting only one size)
			 */
			if (rcd->egrbufs.rcvtid_size == round_mtu ||
			    !HFI1_CAP_KGET_MASK(rcd->flags, MULTI_PKT_EGR)) {
				dd_dev_err(dd, "ctxt%u: Failed to allocate eager buffers\n",
					   rcd->ctxt);
				ret = -ENOMEM;
				goto bail_rcvegrbuf_phys;
			}

			new_size = rcd->egrbufs.rcvtid_size / 2;

			/*
			 * If the first attempt to allocate memory failed, don't
			 * fail everything but continue with the next lower
			 * size.
			 */
			if (idx == 0) {
				rcd->egrbufs.rcvtid_size = new_size;
				continue;
			}

			/*
			 * Re-partition already allocated buffers to a smaller
			 * size.
			 */
			rcd->egrbufs.alloced = 0;
			for (i = 0, j = 0, offset = 0; j < idx; i++) {
				if (i >= rcd->egrbufs.count)
					break;
				rcd->egrbufs.rcvtids[i].dma =
					rcd->egrbufs.buffers[j].dma + offset;
				rcd->egrbufs.rcvtids[i].addr =
					rcd->egrbufs.buffers[j].addr + offset;
				rcd->egrbufs.alloced++;
				if ((rcd->egrbufs.buffers[j].dma + offset +
				     new_size) ==
				    (rcd->egrbufs.buffers[j].dma +
				     rcd->egrbufs.buffers[j].len)) {
					j++;
					offset = 0;
				} else {
					offset += new_size;
				}
			}
			rcd->egrbufs.rcvtid_size = new_size;
		}
	}
	rcd->egrbufs.numbufs = idx;
	rcd->egrbufs.size = alloced_bytes;

	hfi1_cdbg(PROC,
		  "ctxt%u: Alloced %u rcv tid entries @ %uKB, total %uKB",
		  rcd->ctxt, rcd->egrbufs.alloced,
		  rcd->egrbufs.rcvtid_size / 1024, rcd->egrbufs.size / 1024);

	/*
	 * Set the contexts rcv array head update threshold to the closest
	 * power of 2 (so we can use a mask instead of modulo) below half
	 * the allocated entries.
	 */
	rcd->egrbufs.threshold =
		rounddown_pow_of_two(rcd->egrbufs.alloced / 2);
	/*
	 * Compute the expected RcvArray entry base. This is done after
	 * allocating the eager buffers in order to maximize the
	 * expected RcvArray entries for the context.
	 */
	max_entries = rcd->rcv_array_groups * dd->rcv_entries.group_size;
	egrtop = roundup(rcd->egrbufs.alloced, dd->rcv_entries.group_size);
	rcd->expected_count = max_entries - egrtop;
	if (rcd->expected_count > MAX_TID_PAIR_ENTRIES * 2)
		rcd->expected_count = MAX_TID_PAIR_ENTRIES * 2;

	rcd->expected_base = rcd->eager_base + egrtop;
	hfi1_cdbg(PROC, "ctxt%u: eager:%u, exp:%u, egrbase:%u, expbase:%u",
		  rcd->ctxt, rcd->egrbufs.alloced, rcd->expected_count,
		  rcd->eager_base, rcd->expected_base);

	if (!hfi1_rcvbuf_validate(rcd->egrbufs.rcvtid_size, PT_EAGER, &order)) {
		hfi1_cdbg(PROC,
			  "ctxt%u: current Eager buffer size is invalid %u",
			  rcd->ctxt, rcd->egrbufs.rcvtid_size);
		ret = -EINVAL;
		goto bail_rcvegrbuf_phys;
	}

	/*
	 * Enable RcvArray access on JKR and later by configuring RcvEgrCtrl and
	 * RcvTidCtrl before writing TIDs to the RcvArray.
	 *
	 * Call HFI1_RCVCTRL_TID_CONFIG only after eager_base, egrbufs.alloced,
	 * expected_count, and expected_base are initialized in rcd.  The last
	 * 3 of the 4 are initialized above in this function.
	 */
	hfi1_rcvctrl(dd, HFI1_RCVCTRL_TID_CONFIG, rcd);

	for (idx = 0; idx < rcd->egrbufs.alloced; idx++) {
		dd->params->put_tid(rcd, idx, PT_EAGER,
				    rcd->egrbufs.rcvtids[idx].dma, order,
				    false);
		cond_resched();
	}

	return 0;

bail_rcvegrbuf_phys:
	for (idx = 0; idx < rcd->egrbufs.alloced &&
	     rcd->egrbufs.buffers[idx].addr;
	     idx++) {
		dma_free_coherent(&dd->pcidev->dev,
				  rcd->egrbufs.buffers[idx].len,
				  rcd->egrbufs.buffers[idx].addr,
				  rcd->egrbufs.buffers[idx].dma);
		rcd->egrbufs.buffers[idx].addr = NULL;
		rcd->egrbufs.buffers[idx].dma = 0;
		rcd->egrbufs.buffers[idx].len = 0;
	}

	return ret;
}

/*
 * Return number of requested user contexts for the given unit and port based
 * on information given in the module parameter num_user_contexts.
 * Return -1 (use non-HT cores) if the corresponding entry is not set.
 */
int get_num_user_contexts(struct hfi1_devdata *dd, int pidx)
{
	struct hfi1_devdata *xdd;
	int start;
	int i;

	/* find the count of ports from earlier units */
	start = 0;
	for (i = 0; i < dd->unit; i++) {
		xdd = hfi1_lookup(i);
		/* previous units should exist - check anyway */
		if (!xdd) {
			dd_dev_err(dd, "%s: unit %d not found?\n", __func__, i);
			return -1;
		}
		start += xdd->num_pports;
	}

	/* adjust for the port on this unit */
	start += pidx;

	/* check if enough elements are set for this unit's port */
	if (start >= num_user_contexts_count)
		return -1;

	return num_user_contexts_array[start];
}
