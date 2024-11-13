// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2023 - Cornelis Networks, Inc.
 *
 * Generalized (parameterized) chip specific functions and variables.
 */

#include "hfi.h"
#include "chip_gen.h"
#include "cport_traps.h"
#include "chip_gen.h"
#include "vf2pf.h"

#undef DEBUG_CPORT_TRAP

/* TODO: this should not be defined in C files - needs common header */
#define SC(name) SEND_CTXT_##name

/*
 * Control the port LED state.  Cancel with gen_shutdown_led_override().
 */
void gen_setextled(struct hfi1_pportdata *ppd, u32 on)
{
	/* XXX Replace with a CPORT message */
	ppd_dev_warn(ppd, "%s: on %d, JKR TODO\n", __func__, on);
}

/*
 * Make the port LED blink in pattern.  Parameters timeon and timeoff are
 * in milliseconds.  Cancel with gen_shutdown_led_override().
 */
void gen_start_led_override(struct hfi1_pportdata *ppd, unsigned int timeon,
			    unsigned int timeoff)
{
	/* XXX Replace with a CPORT message */
	ppd_dev_warn(ppd, "%s: JKR TODO\n", __func__);

	/* used by the subnet manager to know if it set beaconing */
	atomic_set(&ppd->led_override_timer_active, 1);
	/* ensure the atomic_set is visible to all CPUs */
	smp_wmb();
}

/*
 * Return to normal LED operation.  This cancels overrides started with
 * gen_setextled() or gen_start_led_override().
 */
void gen_shutdown_led_override(struct hfi1_pportdata *ppd)
{
	/* XXX Replace with a CPORT message */
	ppd_dev_warn(ppd, "%s: JKR TODO\n", __func__);

	/* used by the subnet manager to know if it set beaconing */
	atomic_set(&ppd->led_override_timer_active, 0);
	/* ensure the atomic_set is visible to all CPUs */
	smp_wmb();
}

int gen_late_per_chip_init(struct hfi1_devdata *dd)
{
	/* XXX Fill in anything needed post interrupt and context init */
	return 0;
}

void gen_start_port(struct hfi1_pportdata *ppd)
{
	struct hfi1_devdata *dd = ppd->dd;
	u64 guid;

	// FIXME: this is copied from bringup_serdes().  However, I don't
	// see the point.  No one has set ppd->guids[] this early.
	guid = ppd->guids[HFI1_PORT_GUID_INDEX];
	if (!guid) {
		/* OPA spec says bits 34:32 are port number, 1-7 */
		if (dd->base_guid)
			guid = (dd->base_guid & ~(7ULL << 32)) | ((u64)ppd->port << 32);
		ppd->guids[HFI1_PORT_GUID_INDEX] = guid;
		pr_warn("%s: ppd->guids[HFI1_PORT_GUID_INDEX] = 0x%llx",
			__func__, guid);
	}
}

void gen_stop_port(struct hfi1_pportdata *ppd)
{
	/* XXX steps to start port serdes */
	ppd_dev_warn(ppd, "%s: pidx %d, JKR TODO\n", __func__, ppd->hw_pidx);
}

void gen_set_port_max_mtu(struct hfi1_pportdata *ppd, u32 maxvlmtu)
{
	/* XXX steps to set the port maximum MTU */
	ppd_dev_warn(ppd, "%s: pidx %d, JKR TODO\n", __func__, ppd->hw_pidx);
}

/**
 * gen_create_pbc - build a pbc for transmission
 * @ppd: info of physical Hfi port
 * @flags: special case flags or-ed in built pbc
 * @srate_mbs: static rate - unused
 * @vl: vl
 * @dw_len: dword length (header words + data words + pbc words)
 * @l2: L2 header field - determines type
 * @dlid: destination LID
 * @sctxt: send context number
 *
 * Create a PBC with the given flags, rate, VL, and length.
 *
 * NOTE: The PBC created will not insert any HCRC.
 */
u64 gen_create_pbc(struct hfi1_pportdata *ppd, u64 flags, int srate_mbs, u32 vl,
		   u32 dw_len, u32 l2, u32 dlid, u32 sctxt)
{
	/* always add ICRC for non 9B packets */
	if (l2 != PBC_L2_9B)
		flags |= PBC_INSERT_BYPASS_ICRC; /* AKA PbcInsertNon9bIcrc */

	return (u64)sctxt << PBC_SEND_CTXT_SHIFT |
	       (u64)dlid << PBC_DLID_SHIFT |
	       /* lower 32 bits */
	       flags |
	       PBC_IHCRC_NONE << PBC_INSERT_HCRC_SHIFT |
	       l2 << PBC_L2_TYPE_SHIFT |
	       ppd->hw_pidx << PBC_PORT_IDX_SHIFT |
	       (vl & PBC_VL_MASK) << PBC_VL_SHIFT |
	       (dw_len & PBC_LENGTH_DWS_MASK) << PBC_LENGTH_DWS_SHIFT;
}

/*
 * Construct a OPA MAD for sending to CPORT.
 */
static struct opa_smp *build_cport_mad(int meth, int attr)
{
	struct opa_smp *mad;

	mad = kzalloc(sizeof(*mad), GFP_KERNEL);
	if (!mad)
		return mad;
	mad->base_version = OPA_MGMT_BASE_VERSION;
	mad->mgmt_class = IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE;
	mad->class_version = OPA_SM_CLASS_VERSION;
	mad->method = meth;
	mad->attr_id = attr;
	/* XXX - what else */
	return mad;
}

/*
 * Send a GET PORT_INFO OPA MAD to CPORT to get details on port.
 * Caller must kfree() the buffer returned (if not IS_ERR()).
 */
static struct opa_smp *cport_get_portinfo(struct hfi1_devdata *dd, int port)
{
	u8 sb = port; /* 1.. */
	struct opa_smp *mad;
	struct opa_smp *rsp;
	size_t rsp_len;
	int ret;

	mad = build_cport_mad(IB_MGMT_METHOD_GET, IB_SMP_ATTR_PORT_INFO);
	if (!mad)
		return ERR_PTR(-ENOMEM);
	/*
	 * Set port in attribute modifier field, for PORT_INFO.
	 */
	mad->attr_mod = cpu_to_be32(0x1000000 | port);
	/* XXX - need to specify 9B vs 16B? */
#ifdef DEBUG_CPORT_TRAP
	pr_warn("hfi1_%d: %s: send: %02x %02x %02x %02x - %04x %04x %08x\n",
		dd->unit, __func__,
		mad->base_version, mad->mgmt_class, mad->class_version, mad->method,
		be16_to_cpu(mad->status), be16_to_cpu(mad->attr_id),
		be32_to_cpu(mad->attr_mod));
#endif
	rsp_len = sizeof(*rsp);
	rsp = kzalloc(rsp_len, GFP_KERNEL);
	if (!rsp) {
		kfree(mad);
		return ERR_PTR(-ENOMEM);
	}
	ret = cport_send_recv_mad(dd, sb, mad, sizeof(*mad) - OPA_SMP_DR_DATA_SIZE,
				  rsp, &rsp_len);
	kfree(mad);
	if (ret) {
		kfree(rsp);
		if (ret > 0)
			ret = -EINVAL;
		return ERR_PTR(ret);
	}
#ifdef DEBUG_CPORT_TRAP
	pr_warn("hfi1_%d: %s: resp: %02x %02x %02x %02x - %04x %04x %08x\n",
		dd->unit, __func__,
		rsp->base_version, rsp->mgmt_class, rsp->class_version, rsp->method,
		be16_to_cpu(rsp->status), be16_to_cpu(rsp->attr_id), be32_to_cpu(rsp->attr_mod));
#endif
	return rsp;
}

/*
 * Called on PF0 after all new VFs appear.
 */
int hfi1_sriov_sync_ports(struct hfi1_devdata *dd, int si_mask)
{
	int ret = 0;

	if (dd->is_vf)
		return -EINVAL;
	return ret;
}

#ifdef DEBUG_CPORT_TRAP
static const char *ps_state_name(struct opa_port_states *ps)
{
	static const char * const state_name[] = {
		[IB_PORT_NOP]		= "NOP",
		[IB_PORT_DOWN]		= "DOWN",
		[IB_PORT_INIT]		= "INIT",
		[IB_PORT_ARMED]		= "ARMED",
		[IB_PORT_ACTIVE]	= "ACTIVE",
		[IB_PORT_ACTIVE_DEFER]	= "ACTIVE_DEFER"
	};
	u8 ls = port_states_to_logical_state(ps);

	if (ls > IB_PORT_ACTIVE_DEFER)
		return "???";
	return state_name[ls];
}
#endif

static void check_cport_state(struct work_struct *work)
{
	struct hfi1_cport *cport = container_of(work, struct hfi1_cport, psc.work);
	struct hfi1_devdata *dd = cport->dd;
	struct opa_smp *mad;
	struct opa_port_info *pi;
	int ret;
	int pidx;

	/*
	 * There should be only one running. Others could abort except for
	 * the race between checking states and releasing semaphore.
	 */
	ret = down_killable(&dd->cport->psc.wait);
	if (ret) {
		atomic_dec(&dd->cport->psc.nq);
		return;
	}
#ifdef DEBUG_CPORT_TRAP
	pr_warn("hfi1_%d: %s: starting port_info loop\n", dd->unit, __func__);
#endif

	for (pidx = 0; pidx < dd->params->num_ports; ++pidx) {
		if (!port_available_pidx(dd, pidx)) {
			ppd_dev_info(&dd->pport[pidx], "Skipping port state check - port not available\n");
			continue;
		}
		mad = cport_get_portinfo(dd, pidx + 1);
		if (IS_ERR(mad)) {
			ret = PTR_ERR(mad);
		} else {
			pi = (struct opa_port_info *)opa_get_smp_data(mad);
#ifdef DEBUG_CPORT_TRAP
			pr_warn("hfi1_%d: %s: PORTINFO %d: %s %08x (%x)\n",
				dd->unit, __func__,
				pidx + 1, ps_state_name(&pi->port_states),
				be32_to_cpu(mad->attr_mod),
				be16_to_cpu(mad->status));
#endif
			ret = update_from_opa_portinfo(&dd->pport[pidx], mad, pi);
			kfree(mad);
		}
		/* XXX - queue up a retry on error? */
		if (ret)
			dd_dev_warn(dd, "Failed to update PORT_INFO on port %d (%d)\n",
				    pidx + 1, ret);
	}
#ifdef DEBUG_CPORT_TRAP
	pr_warn("hfi1_%d: %s: finished port_info loop\n", dd->unit, __func__);
#endif
	atomic_dec(&dd->cport->psc.nq);
	up(&dd->cport->psc.wait);
}

static void handle_cport_trap128(struct hfi1_devdata *dd, struct cport_trap_status traps)
{
	/* note: traps are already repressed */
#ifdef DEBUG_CPORT_TRAP
	pr_warn("hfi1_%d: %s: TRAP128 psc=%d\n", dd->unit, __func__, traps.psc);
#endif

	if (atomic_read(&dd->cport->psc.nq) > 1) {
#ifdef DEBUG_CPORT_TRAP
		pr_warn("hfi1_%d: %s: TRAP128(s) pending: %d\n",
			dd->unit, __func__, atomic_read(&dd->cport->psc.nq));
#endif
		return;
	}
	atomic_inc(&dd->cport->psc.nq);
	queue_work(dd->hfi1_wq, &dd->cport->psc.work);
}

/*
 * This initializes everything necessary to receive and process Port
 * State Change TRAPs from CPORT. It also kicks off the initial gathering
 * of port states from CPORT.
 */
int init_cport_trap128(struct hfi1_devdata *dd)
{
	struct cport_trap_status traps = {0};
	int ret = 0;

	if (!dd->cport)
		return 0;

	atomic_set(&dd->cport->psc.nq, 0);
	sema_init(&dd->cport->psc.wait, 1);
	INIT_WORK(&dd->cport->psc.work, check_cport_state);
	traps.psc = 1;	/* Trap 128 Port State Change */
	ret = register_cport_trap(dd, traps, handle_cport_trap128);
	if (ret)
		dd_dev_warn(dd, "Failed to register for CPORT TRAP 128: %d\n", ret);
	else if (!dd->cport->traps_act.psc)
		dd_dev_warn(dd, "CPORT TRAP128 not supported\n");
	/* Fake a TRAP-128 to gather initial port states even if register fails */
	handle_cport_trap128(dd, traps);
	return ret;
}

int deinit_cport_trap128(struct hfi1_devdata *dd)
{
	if (!dd->cport || !dd->cport->traps.psc)
		return 0;
	return deregister_cport_trap(dd, handle_cport_trap128);
}

static void handle_cport_overtemp(struct hfi1_devdata *dd, struct cport_trap_status traps)
{
	/* note: traps are already repressed */
	hfi1_overtemp(dd);
}

/* no deinit_ - clearall_cport_trap() unregisters this */
int init_cport_overtemp(struct hfi1_devdata *dd)
{
	struct cport_trap_status traps = {0};
	int ret = 0;

	if (!dd->cport)
		return 0;

	traps.ovtm = 1;	/* Over Temp emergency */
	ret = register_cport_trap(dd, traps, handle_cport_overtemp);
	if (ret)
		dd_dev_warn(dd, "Failed to register for CPORT Over Temp: %d\n", ret);
	else if (!dd->cport->traps_act.ovtm)
		dd_dev_warn(dd, "CPORT Over-Temp notification not supported\n");
	return ret;
}

static int cport_goto_offline(struct hfi1_pportdata *ppd, struct opa_port_info *pi,
			      u8 rem_reason)
{
	u32 previous_state;

	previous_state = ppd->host_link_state;
	ppd->host_link_state = HLS_GOING_OFFLINE;

	/* start offline transition */
	if (ppd->offline_disabled_reason ==
	    HFI1_ODR_MASK(OPA_LINKDOWN_REASON_NONE))
		ppd->offline_disabled_reason = HFI1_ODR_MASK(OPA_LINKDOWN_REASON_TRANSIENT);

	update_statusp(ppd, IB_PORT_DOWN);

	/*
	 * The state in CPORT is now offline.
	 *	- change our state
	 *	- notify others if we were previously in a linkup state
	 */
	ppd->host_link_state = HLS_DN_OFFLINE;
	if (previous_state & HLS_UP) {
		/* went down while link was up */
		cport_handle_linkup_change(ppd, pi, 0);
	}

	/* the active link width (downgrade) is 0 on link down */
	ppd->link_width_active = 0;
	ppd->link_width_downgrade_tx_active = 0;
	ppd->link_width_downgrade_rx_active = 0;
	ppd->current_egress_rate = 0;
	/* XXX - also clear speeds? */
	return 0;
}

/* set_link_state() for CPORT-based systems. Only update local data. */
int cport_set_link_state(struct hfi1_pportdata *ppd, struct opa_port_info *pi, u32 state)
{
	struct hfi1_devdata *dd = ppd->dd;
	int ret = 0;
	int orig_new_state, poll_bounce;

	mutex_lock(&ppd->hls_lock);

	orig_new_state = state;
	if (state == HLS_DN_DOWNDEF)
		state = HLS_DEFAULT;

	/* interpret poll -> poll as a link bounce */
	poll_bounce = ppd->host_link_state == HLS_DN_POLL &&
		      state == HLS_DN_POLL;

	ppd_dev_info(ppd, "%s: current %s, new %s %s%s\n", __func__,
		    link_state_name(ppd->host_link_state),
		    link_state_name(orig_new_state),
		    poll_bounce ? "(bounce) " : "",
		    link_state_reason_name(ppd, state));

	/*
	 * If we're going to a (HLS_*) link state that implies the logical
	 * link state is neither of (IB_PORT_ARMED, IB_PORT_ACTIVE), then
	 * reset is_sm_config_started to 0.
	 */
	if (!(state & (HLS_UP_ARMED | HLS_UP_ACTIVE)))
		ppd->is_sm_config_started = 0;

	/*
	 * Do nothing if the states match.  Let a poll to poll link bounce
	 * go through.
	 */
	if (ppd->host_link_state == state && !poll_bounce)
		goto done;

	switch (state) {
	case HLS_UP_INIT:
		log_state_transition(ppd, PLS_LINKUP);

		/* clear old transient LINKINIT_REASON code */
		if (ppd->linkinit_reason >= OPA_LINKINIT_REASON_CLEAR)
			ppd->linkinit_reason = OPA_LINKINIT_REASON_LINKUP;

		cport_handle_linkup_change(ppd, pi, 1);
		pio_kernel_linkup(ppd);

		/*
		 * After link up, a new link width will have been set.
		 * Update the xmit counters with regards to the new
		 * link width.
		 */
		/* XXX - still do this? */
		update_xmit_counters(ppd, ppd->link_width_active);

		ppd->host_link_state = HLS_UP_INIT;
		update_statusp(ppd, IB_PORT_INIT);
		break;
	case HLS_UP_ARMED:
		/* XXX - is this error check needed? */
		if (ppd->host_link_state != HLS_UP_INIT)
			dd_dev_err(dd, "%s %d: allowing unexpected state transition from %s to %s\n",
				   __func__, ppd->port,
				   link_state_name(ppd->host_link_state),
				   link_state_name(state));

		ppd->host_link_state = HLS_UP_ARMED;
		update_statusp(ppd, IB_PORT_ARMED);
		break;
	case HLS_UP_ACTIVE:
		/* XXX - is this error check needed? */
		if (ppd->host_link_state != HLS_UP_ARMED)
			dd_dev_err(dd, "%s %d: allowing unexpected state transition from %s to %s\n",
				   __func__, ppd->port,
				   link_state_name(ppd->host_link_state),
				   link_state_name(state));

		ppd->host_link_state = HLS_UP_ACTIVE;
		update_statusp(ppd, IB_PORT_ACTIVE);
		go_port_active(ppd);
		break;
	case HLS_DN_POLL:
		/* XXX - will we see this? do we need to synthesize it? */

		if (ppd->host_link_state != HLS_DN_OFFLINE) {
			u8 tmp = ppd->link_enabled;

			ret = cport_goto_offline(ppd, pi, ppd->remote_link_down_reason);
			if (ret) {
				ppd->link_enabled = tmp;
				break;
			}
			ppd->remote_link_down_reason = 0;

			if (ppd->driver_link_ready)
				ppd->link_enabled = 1;
		}

		/* XXX - alters *ALL* contexts... should not do this?
		 * At least only alter contexts for this port.
		 */
		set_all_slowpath(ppd);

		ppd->port_error_action = 0;

		ppd->host_link_state = HLS_DN_POLL;
		ppd->offline_disabled_reason =
			HFI1_ODR_MASK(OPA_LINKDOWN_REASON_NONE);
		log_state_transition(ppd, PLS_POLLING);
		break;
	case HLS_DN_DISABLE:
		/* link is disabled */
		ppd->link_enabled = 0;

		/* allow any state to transition to disabled */

		/* must transition to offline first */
		if (ppd->host_link_state != HLS_DN_OFFLINE) {
			ret = cport_goto_offline(ppd, pi, ppd->remote_link_down_reason);
			if (ret)
				break;
			ppd->remote_link_down_reason = 0;
		}

		ppd->host_link_state = HLS_DN_DISABLE;
		break;
	case HLS_DN_OFFLINE:
		/* allow any state to transition to offline */
		ret = cport_goto_offline(ppd, pi, ppd->remote_link_down_reason);
		if (!ret)
			ppd->remote_link_down_reason = 0;
		break;
	case HLS_GOING_UP:		/* never seen by driver */
	case HLS_VERIFY_CAP:		/* never seen by driver */
	case HLS_GOING_OFFLINE:		/* transient within goto_offline() */
	case HLS_LINK_COOLDOWN:		/* transient within goto_offline() */
	default:
		dd_dev_info(dd, "%s %d: state 0x%x: not supported\n",
			    __func__, ppd->port, state);
		ret = -EINVAL;
		break;
	}

done:
	mutex_unlock(&ppd->hls_lock);

	return ret;
}

int cport_start_link(struct hfi1_pportdata *ppd, struct opa_port_info *pi)
{
	/*
	 * FULL_MGMT_P_KEY is cleared from the pkey table, so that the
	 * pkey table can be configured properly if the HFI unit is connected
	 * to switch port with MgmtAllowed=NO
	 */
	/* this writes CSRs... clear_full_mgmt_pkey(ppd); so do: */
	if (ppd->pkeys[2] != 0) {
		ppd->pkeys[2] = 0;
		/* avoid hfi1_set_ib_cfg(HFI1_IB_CFG_PKEYS) */
		hfi1_event_pkey_change(ppd->dd, ppd->port);
	}

	return cport_set_link_state(ppd, pi, HLS_DN_POLL);
}

/**
 * Ask cport firmware for the temperature.
 *
 * @gen_temp: temperature output.
 *
 * Return: 0 on success, -EINVAL on invalid reply from CPORT,
 * -EOPNOTSUPP on reply from CPORT but ASIC temperature not
 * valid/supported.
 */
int cport_read_temp(struct hfi1_devdata *dd, struct cport_temp *gen_temp)
{
	struct cport_how_payload *how = NULL;
	int resp_len = 0;
	int ret;

	/* Don't trust the caller; assume invalid */
	gen_temp->asic_valid = 0;
	gen_temp->qsfp1_valid = 0;
	gen_temp->qsfp2_valid = 0;

	ret = cport_send_req(dd, CH_OP_HOW, 0, NULL, 0, (void **)&how, &resp_len,
			     cport_adm_to * HZ);
	if (ret) {
		dd_dev_err(dd, "CPORT how failed %d\n", ret);
		goto done;
	}
	if (resp_len != sizeof(*how)) {
		dd_dev_err(dd, "CPORT how invalid response length %d (expected %ld)\n",
			   resp_len, sizeof(*how));
		ret = -EINVAL;
		goto done;
	}
	if (!how->temp_valid) {
		ret = -EOPNOTSUPP;
		goto done;
	}
	gen_temp->asic_valid = 1;
	gen_temp->asic = (s16)how->temp;

	gen_temp->qsfp1_valid = how->qsfp1_temp_valid;
	if (how->qsfp1_temp_valid)
		gen_temp->qsfp1 = (s16)how->qsfp1_temp;

	gen_temp->qsfp2_valid = how->qsfp2_temp_valid;
	if (how->qsfp2_temp_valid)
		gen_temp->qsfp2 = (s16)how->qsfp2_temp;
done:
	kfree(how);
	return ret;
}

/*
 * Read a CSR based on type
 *
 * type - CSR_TYPE_*
 * off - base offset of CSR
 * ctxt - conext number, if type requires one
 * pidx_eng - port index or SDMA engine number, depending on type
 */
u64 read_csr_type(struct hfi1_devdata *dd, enum csr_type type, u32 off,
		  u16 ctxt, u8 pidx_eng)
{
	u64 reg = ~0ull;
	switch (type) {
	case CSR_TYPE_IPORT:
		reg = read_iport_csr(dd, pidx_eng, off);
		break;
	case CSR_TYPE_IPRC:
		reg = read_iprc_csr(dd, pidx_eng, ctxt, off);
		break;
	case CSR_TYPE_RCTXT:
		reg = read_rctxt_csr(dd, ctxt, off);
		break;
	case CSR_TYPE_KCTXT:
		reg = read_kctxt_csr(dd, ctxt, off);
		break;
	case CSR_TYPE_KU:
		reg = read_ku_csr(dd, ctxt, off);
		break;
	case CSR_TYPE_UCTXT:
		reg = read_uctxt_csr(dd, ctxt, off);
		break;
	case CSR_TYPE_SCTXT:
		reg = read_sctxt_csr(dd, ctxt, off);
		break;
	case CSR_TYPE_TCTXT:
		reg = read_tctxt_csr(dd, ctxt, off);
		break;
	case CSR_TYPE_SDMA:
		reg = read_sdma_csr(dd, pidx_eng, off);
		break;
	case CSR_TYPE_SDMACFG:
		reg = read_sdmacfg_csr(dd, pidx_eng, off);
		break;
	case CSR_TYPE_EPORT:
		reg = read_eport_csr(dd, pidx_eng, off);
		break;
	case CSR_TYPE_EPSC:
		reg = read_epsc_csr(dd, pidx_eng, ctxt, off);
		break;
	case CSR_TYPE_EPSCARR:
		reg = read_epsc_csr(dd, pidx_eng, ctxt, off);
		break;
	}
	return reg;
}

int priv_reg_op(struct hfi1_devdata *dd, int pidx, u32 ctxt, int type,
		enum preg_op op, u64 arg)
{
	u8 opval, opmask;
	u16 rctxt;
	u64 reg;
	int ret = 0;

	rctxt = ctxt >> 16;
	ctxt &= 0xffff;

	if (dd->is_vf) {
		ret = vf2pf_priv_reg_op(dd, pidx, ctxt, type, op, arg);
		if (ret)
			dd_dev_err(dd, "vf2pf_priv_reg_op(%d) failed %d\n", op, ret);
		return ret;
	}

	/* Only PF0 has access to these CSRs */
	switch (op) {
	case SC_CHK_ALLOC_OP: /* 'arg' is send_ctxt_ctrl_reg value */
		write_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg, arg);
		dd->params->set_pio_integrity(dd, pidx, ctxt, type, SPI_DEFAULT);
		/* set the default partition key */
		write_epsc_csr(dd, pidx, ctxt,
			       dd->params->send_ctxt_check_partition_key_reg,
			       (SC(CHECK_PARTITION_KEY_VALUE_MASK) &
			       DEFAULT_PKEY) <<
			       SC(CHECK_PARTITION_KEY_VALUE_SHIFT));
		/* per context type checks */
		if (type == SC_USER) {
			opval = USER_OPCODE_CHECK_VAL;
			opmask = USER_OPCODE_CHECK_MASK;
		} else {
			opval = OPCODE_CHECK_VAL_DISABLED;
			opmask = OPCODE_CHECK_MASK_DISABLED;
		}
		/* set the send context check opcode mask and value */
		write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_opcode_reg,
			       ((u64)opmask << SC(CHECK_OPCODE_MASK_SHIFT)) |
			       ((u64)opval << SC(CHECK_OPCODE_VALUE_SHIFT)));
		/* User send contexts should not allow sending on VL15 */
		if (type == SC_USER) {
			write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_vl_reg,
				       1ULL << 15);
		}
		break;
	case SC_CHK_FREE_OP: /* 'arg' not used */
		write_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg, 0);
		write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_enable_reg, 0);
		write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_partition_key_reg, 0);
		write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_opcode_reg, 0);
		break;
	case SC_CHK_VL_MASK_OP: /* 'arg' is send_ctxt_check_vl_reg value */
		write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_vl_reg, arg);
		break;
	case SC_CHK_SLID_OP: /* 'arg' is send_ctxt_check_slid_reg value */
		write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_slid_reg, arg);
		break;
	case SC_CHK_JKEY_OP: /* 'arg' is send_ctxt_check_job_key_reg val, 'ctxt' incl rcv */
		write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_job_key_reg, arg);
		if (!is_ax(dd)) {
			dd->params->set_pio_integrity(dd, pidx, ctxt, type,
				arg ? SPI_SET_JKEY : SPI_CLEAR_JKEY);
		}
		/* Enable/clear J_KEY check on receive context. */
		if (arg) {
			/* convert sctxt jkey to rctxt */
			arg = (arg >> SEND_CTXT_CHECK_JOB_KEY_VALUE_SHIFT) &
				SEND_CTXT_CHECK_JOB_KEY_VALUE_MASK;
			arg = RCV_KEY_CTRL_JOB_KEY_ENABLE_SMASK |
				((arg & RCV_KEY_CTRL_JOB_KEY_VALUE_MASK) <<
				 RCV_KEY_CTRL_JOB_KEY_VALUE_SHIFT);
		}
		write_iprc_csr(dd, pidx, rctxt, dd->params->rcv_jkey_ctrl_reg, arg);
		break;
	case SC_CHK_PKEY_OP: /* 'arg' is send_ctxt_check_partition_key_reg value */
		if (!arg)
			dd->params->set_pio_integrity(dd, pidx, ctxt, type, SPI_CLEAR_PKEY);
		write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_partition_key_reg, arg);
		if (arg)
			dd->params->set_pio_integrity(dd, pidx, ctxt, type, SPI_SET_PKEY);
		break;
	case SC_CHK_ADJ_OP: /* 'arg' is enable flag (do SC_CHK_INIT_OP also) */
		dd->params->set_pio_integrity(dd, pidx, ctxt, type, SPI_DEFAULT);
		if (!arg)
			break;
		fallthrough;
	case SC_CHK_INIT_OP: /* 'arg' not used */
		dd->params->set_pio_integrity(dd, pidx, ctxt, type, SPI_INIT);
		break;
	case SC_ENABLE_OP: /* 'arg' not used as input, 'pidx' not used */
		ret = pio_reset_one(dd, ctxt);
		if (ret)
			break;

		/*
		 * All is well. Enable the context.
		 */
		arg = read_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg);
		arg |= SC(CTRL_CTXT_ENABLE_SMASK);
		write_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg, arg);
		/*
		 * Read SendCtxtCtrl to force the write out and prevent a timing
		 * hazard where a PIO write may reach the context before the enable.
		 */
		read_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg);
		break;
	case SC_DISABLE_OP: /* 'arg' not used as input, 'pidx' not used */
		arg = read_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg);
		arg &= ~SC(CTRL_CTXT_ENABLE_SMASK);
		write_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg, arg);
		break;
	case RC_ENABLE_OP: /* 'arg' is enable flag */
		opval = arg; /* 'enable' */
		arg = JKR_RCV_PKT_CTRL_RCV_PORT_ENABLE_SMASK |
		      JKR_RCV_PKT_CTRL_CONTEXT_ENABLED_SMASK;
		reg = read_iprc_csr(dd, pidx, ctxt, JKR_RCV_PKT_CTRL);
		/* always clear the L2TypeEnable field */
		reg &= ~JKR_RCV_PKT_CTRL_L2_TYPE_ENABLE_MASK_SMASK;
		if (opval) {
			/* allow 16B and 9B L2 */
			reg |= arg |
			       (0xcull << JKR_RCV_PKT_CTRL_L2_TYPE_ENABLE_MASK_SHIFT);
		} else {
			reg &= ~arg;
		}
		write_iprc_csr(dd, pidx, ctxt, JKR_RCV_PKT_CTRL, reg);
		break;
	case RC_HEADER_OP: /* 'arg' is size */
		reg = read_iprc_csr(dd, pidx, ctxt, JKR_RCV_PKT_CTRL);
		reg &= ~JKR_RCV_PKT_CTRL_HDR_SIZE_SMASK;
		reg |= arg << JKR_RCV_PKT_CTRL_HDR_SIZE_SHIFT;
		write_iprc_csr(dd, pidx, ctxt, JKR_RCV_PKT_CTRL, reg);
		break;
	case LINK_BOUNCE_OP: /* 'arg' is not used */
		queue_work(dd->pport[pidx].link_wq, &dd->pport[pidx].link_bounce_work);
		break;
	}
	return ret;
}
