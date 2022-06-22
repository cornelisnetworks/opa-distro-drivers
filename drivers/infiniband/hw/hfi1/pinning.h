/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2023 Cornelis Networks, Inc.
 */
#ifndef _HFI1_PINNING_H
#define _HFI1_PINNING_H

#include <linux/bits.h>
#include <rdma/hfi/hfi1_user.h>

struct hfi1_user_sdma_pkt_q;
struct user_sdma_request;
struct user_sdma_txreq;
struct user_sdma_iovec;

struct pinning_interface {
	int (*init)(struct hfi1_user_sdma_pkt_q *pq);
	void (*free)(struct hfi1_user_sdma_pkt_q *pq);

	/*
	 * Add up to pkt_data_remaining bytes to the txreq, starting at the
	 * current offset in the given iovec entry and continuing until all
	 * data has been added to the iovec or the iovec entry type changes.
	 * On success, prior to returning, the implementation must adjust
	 * pkt_data_remaining, req->iov_idx, and the offset value in
	 * req->iov[req->iov_idx] to reflect the data that has been
	 * consumed.
	 */
	int (*add_to_sdma_packet)(struct user_sdma_request *req,
				  struct user_sdma_txreq *tx,
				  struct user_sdma_iovec *iovec,
				  u32 *pkt_data_remaining);
};

#define PINNING_MAX_INTERFACES BIT(HFI1_MEMINFO_TYPE_ENTRY_BITS)

struct pinning_state {
	void *interface[PINNING_MAX_INTERFACES];
};

#define PINNING_STATE(pq, i) ((pq)->pinning_state.interface[(i)])

extern struct pinning_interface pinning_interfaces[PINNING_MAX_INTERFACES];

void register_pinning_interface(unsigned int type,
				struct pinning_interface *interface);
void deregister_pinning_interface(unsigned int type);

void register_system_pinning_interface(void);
void deregister_system_pinning_interface(void);

int init_pinning_interfaces(struct hfi1_user_sdma_pkt_q *pq);
void free_pinning_interfaces(struct hfi1_user_sdma_pkt_q *pq);

static inline bool pinning_type_supported(unsigned int type)
{
	return (type < PINNING_MAX_INTERFACES &&
		pinning_interfaces[type].add_to_sdma_packet);
}

static inline int add_to_sdma_packet(unsigned int type,
				     struct user_sdma_request *req,
				     struct user_sdma_txreq *tx,
				     struct user_sdma_iovec *iovec,
				     u32 *pkt_data_remaining)
{
	return pinning_interfaces[type].add_to_sdma_packet(req, tx, iovec,
							   pkt_data_remaining);
}

#endif /* _HFI1_PINNING_H */
