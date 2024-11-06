/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2023 Cornelis Networks.
 */

#ifndef _CPORT_H
#define _CPORT_H

/*****************************************************
 * "Public" software interfaces (inside driver only).
 */

/*
 * Op-codes for requests (and associated responses).
 * CPORT firmware must have the same definitions.
 */
#define CH_OP_PING		0	/* simple ping/echo command */
#define CH_OP_WHO		1
#define CH_OP_HOW		2
#define CH_OP_START		3	/* driver start/options */
#define CH_OP_STOP		4	/* driver stop (unload) */
#define CH_OP_TRAP		5	/* notification of TRAP condition */
#define CH_OP_TRAP_REPRESS	6	/* TRAP acknowledge */
#define CH_OP_MAD_9B		7	/* Local MAD packets 9B */
#define CH_OP_MAD_16B		8	/* Local MAD packets 16B */
#define CH_OP_UMAD_9B		9	/* User MAD packets 9B */
#define CH_OP_UMAD_16B		10	/* User MAD packets 16B */

/*
 * Error codes for responses.
 * CPORT firmware must have the same definitions.
 */
#define MSG_RSP_STATUS_OK			0
#define MSG_RSP_STATUS_SEQ_NO_ERROR		1
#define MSG_RSP_STATUS_OPCODE_UNSUPPORTED	2
#define MSG_RSP_STATUS_INVALID_STATE		3
#define MSG_RSP_STATUS_RETRY			4
#define MSG_RSP_STATUS_DENIED			5

struct cport_options {
	u16 bare_metal:1;
	u16 gsi:1;
	u16 flr:1;
	u16 spi_we:1;
	u16 local_mad:1;
	u16 _resv:11;
};

struct cport_trap_status {
	u32 psc:1;	/* Port State Change */
	u32 li:1;	/* Link Integrity */
	u32 bo:1;	/* Buffer Overrun */
	u32 fw:1;	/* Flow Watchdog */
	u32 cc:1;	/* Capability Change */
	u32 sic:1;	/* System Image Change */
	u32 bmk:1;	/* Bad M Key */
	u32 bqk:1;	/* Bad Q Key */
	u32 lwc:1;	/* Link Width Change */
	u32 qsfp:1;	/* QSFP Fault */
	u32 _resv:22;
};

/* Fields in 4-qword payload of WHO response */
struct cport_who_payload {
	/* qword 1 */
	u16 _resv1:8;
	u16 introp:8;	/* interop level */
	struct cport_options fixed;
	struct cport_options suppt;
	u16 max_msg;	/* max cport msg length */
	/* qword 2 */
	u64 vers_bld:32;
	u64 vers_pat:8;
	u64 vers_mnt:8;
	u64 vers_min:8;
	u64 vers_maj:8;
	/* qword 3 */
	u64 node_guid;
	/* qword 4 */
	struct cport_trap_status trap_sup;
	u16 _resv2;
	u16 max_aux;	/* max cport aux length */
};

/* Fields in 4-qword payload of HOW response */
struct cport_how_payload {
	/* qword 1 */
	u16 pt0_log_st:3;
	u16 _resv_q1_3:1;
	u16 pt1_log_st:3;
	u16 _resv_q1_7:1;
	u16 pt2_log_st:3;
	u16 _resv_q1_11:1;
	u16 pt3_log_st:3;
	u16 _resv_q1_15:1;
	struct cport_options opts_ena;
	u16 pt0_phy_st:8;
	u16 pt1_phy_st:8;
	u16 pt2_phy_st:8;
	u16 pt3_phy_st:8;
	/* qword 2 */
	struct cport_trap_status trap_ena;
	struct cport_trap_status trap_sts;
	/* qword 3 */
	u64 interoperability_level:8;
	u64 _resv1:56;
	/* qword 4 */
	u64 started:8;
	u64 temp_valid:1;
	u64 _resv_q4_9:7;
	u64 temp:16;
	u64 _resv2:32;
};

/* Fields in 1-qword payload of START request/response */
struct cport_start_payload {
	u16 sidx:3;
	u16 _resv1:5;
	u16 interop:8;
	struct cport_options opts_ena;
	struct cport_trap_status trap_ena;
};

/* Fields in 1-qword payload of STOP request/response */
struct cport_stop_payload {
	u64 sidx:3;
	u64 _resv1:61;
};

/* Fields in 1-qword payload of TRAP or TRAP_REPRESS request */
struct cport_trap_payload {
	struct cport_trap_status trap_sts;
	u32 _resv1;
};

/*
 * Non-blocking request interface.
 *
 * cport_send_req_nb() returns 'handle' (or IS_ERR(handle)).
 * Caller supplies 'wait' which will be "upped" when the matching response
 * is received.  Caller also supplies a timeout for the OUTBOX_EMPTY wait.
 * This is generally needed if the caller will be using a timeout when waiting
 * for completion, to ensure that the send kworker also times out and exits.
 * Timeouts, etc, use cport_send_cancel() to terminate without receiving response.
 *
 * Payload is always copied to internal buffer, so caller
 * may dispose of their buffer immediately on return.
 *
 * Timeout value of MAX_SCHEDULE_TIMEOUT causes infinite wait for OUTBOX_EMPTY.
 *
 * One of cport_send_comp() or cport_send_cancel() must be called in order
 * to fully release 'handle'.
 *
 * Response payload and length is provided in 'rsp_pld' and 'rsp_len',
 * which has been kalloc'ed and must be kfree'ed by caller.
 *
 * cport_send_comp() returns the status (error code) from the response.
 */
void *cport_send_req_nb(struct hfi1_devdata *dd, u8 op, u8 sideband,
			void *payload, int len, struct semaphore *wait, long timeout);
int cport_send_comp(struct hfi1_devdata *dd, void *handle,
		    void **rsp_pld, int *rsp_len);
void cport_send_cancel(struct hfi1_devdata *dd, void *handle);

/*
 * Blocking request interface with timeout.
 *
 * The caller may dispose of 'payload' immediately on return.
 * Response payload and length is provided in 'rsp_pld' and 'rsp_len',
 * which has been kalloc'ed and must be kfree'ed by caller.
 *
 * Timeout value of MAX_SCHEDULE_TIMEOUT causes infinite wait for response
 * and OUTBOX_EMPTY.
 *
 * Returns the status (error code) from the response.
 */
int cport_send_req(struct hfi1_devdata *dd, u8 op, u8 sideband, void *payload, int len,
		   void **rsp_pld, int *rsp_len, long timeout);

/*
 * CPORT Notification interface.
 *
 * A notification is defined as a request that has no response.
 * This is implicitly non-blocking.
 *
 * The caller may dispose of 'payload' immediately on return.
 *
 * Returns 0 if the request was successfully queued.
 */
int cport_send_notif(struct hfi1_devdata *dd, u8 op, u8 sideband, void *payload, int len);

/**************************************
 * API for notifications from CPORT
 */

/*
 * Handler prototype for callbacks.
 *
 * Returns response status (error) value. Must setup response payload
 * if appropriate. Whether or not a response is actually sent depends on
 * whether the request asked for one. Default is no payload (0 length).
 *
 * The semantics for responses are defined by the op-code. Error responses
 * may have different payloads than successful responses (or no payload at all).
 * Payloads may even be optional.
 */
typedef int (*cport_handler)(struct hfi1_devdata *dd, u8 op, u8 sideband,
			     void *payload, int len, void *handle);

/*
 * Register a callback for a range of op-codes. Only one callback may be
 * registered for a given op-code. Returns 0 on success (valid op-code range).
 */
int cport_register_cb(struct hfi1_devdata *dd, u8 op_start, u8 op_end, cport_handler func);

/*
 * Prepare a response payload for 'len' bytes of payload from callback.
 *
 * Returns NULL on error, including 'len' out of bounds. Returned pointer
 * is not disposable directly.
 */
void *cport_resp_alloc(void *handle, int len);

/*
 * Set static buffer for response payload of 'len' bytes from callback.
 *
 * Buffer may be disposed of immediately on return. If 'len' exceeds
 * maximum allowed, returns -EINVAL.
 */
int cport_resp_set(void *handle, void *payload, int len);

/*
 * Interrupt handler for MctxtCportToPcieInt
 */
void is_cport_int(struct hfi1_devdata *dd, unsigned int source);

/*
 * Start a CPORT ping for count iterations.
 */
int cport_ping_start(struct hfi1_devdata *dd, unsigned int count);

/*
 * Initialize the CPORT communication facility.
 *
 * If the device does not have a CPORT, this returns 0.
 */
int cport_init(struct hfi1_devdata *dd);

/*
 * Shutdown the CPORT communication facility.
 *
 * If the device has no CPORT, this does nothing.
 */
int cport_exit(struct hfi1_devdata *dd);

#endif /* _CPORT_H */
