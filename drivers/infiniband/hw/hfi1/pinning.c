// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2022 - Cornelis Networks, Inc.
 */

#include <linux/types.h>
#include <linux/string.h>

#include "pinning.h"

struct pinning_interface pinning_interfaces[PINNING_MAX_INTERFACES];

void register_pinning_interface(unsigned int type,
				struct pinning_interface *interface)
{
	pinning_interfaces[type] = *interface;
}

void deregister_pinning_interface(unsigned int type)
{
	memset(&pinning_interfaces[type], 0, sizeof(pinning_interfaces[type]));
}

int init_pinning_interfaces(struct hfi1_user_sdma_pkt_q *pq)
{
	int i;
	int ret;

	for (i = 0; i < PINNING_MAX_INTERFACES; i++) {
		if (pinning_interfaces[i].init) {
			ret = pinning_interfaces[i].init(pq);
			if (ret)
				goto fail;
		}
	}

	return 0;

fail:
	while (--i >= 0) {
		if (pinning_interfaces[i].free)
			pinning_interfaces[i].free(pq);
	}
	return ret;
}

void free_pinning_interfaces(struct hfi1_user_sdma_pkt_q *pq)
{
	unsigned int i;

	for (i = 0; i < PINNING_MAX_INTERFACES; i++) {
		if (pinning_interfaces[i].free)
			pinning_interfaces[i].free(pq);
	}
}
