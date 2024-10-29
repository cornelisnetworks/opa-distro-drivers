/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2023 Cornelis Networks, Inc.
 *
 * Generalized (parameterized) chip specific declaractions.
 */

#ifndef _CHIP_GEN_H
#define _CHIP_GEN_H

void gen_setextled(struct hfi1_pportdata *ppd, u32 on);
void gen_start_led_override(struct hfi1_pportdata *ppd, unsigned int timeon,
			    unsigned int timeoff);
void gen_shutdown_led_override(struct hfi1_pportdata *ppd);
int gen_late_per_chip_init(struct hfi1_devdata *dd);
void gen_start_port(struct hfi1_pportdata *ppd);
void gen_stop_port(struct hfi1_pportdata *ppd);
void gen_set_port_max_mtu(struct hfi1_pportdata *ppd, u32 maxvlmtu);
u64 gen_create_pbc(struct hfi1_pportdata *ppd, u64 flags, int srate_mbs, u32 vl,
		   u32 dw_len, u32 l2, u32 dlid, u32 sctxt);

int cport_set_link_state(struct hfi1_pportdata *ppd, struct opa_port_info *pi, u32 state);
int cport_start_link(struct hfi1_pportdata *ppd, struct opa_port_info *pi);
int cport_read_temp(struct hfi1_devdata *dd, struct cport_temp *gen_temp);
int hfi1_sriov_sync_ports(struct hfi1_devdata *dd, int si_mask);

int init_cport_trap128(struct hfi1_devdata *dd);
int deinit_cport_trap128(struct hfi1_devdata *dd);
int init_cport_overtemp(struct hfi1_devdata *dd);

#endif /* _CHIP_GEN_H */
