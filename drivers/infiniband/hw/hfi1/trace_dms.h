/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2025 Cornelis Networks, Inc.
 * Copyright(c) 2017 Intel Corporation.
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * BSD LICENSE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  - Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  - Neither the name of Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#if !defined(__HFI1_TRACE_DMS_H) || defined(TRACE_HEADER_MULTI_READ)
#define __HFI1_TRACE_DMS_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>

const char *hfi1_memtype_str(unsigned int mt);

#undef TRACE_SYSTEM
#define TRACE_SYSTEM hfi1_dms

struct hfi1_dms;
struct hfi1_mem_region;
struct hfi1_dms_rx_tracker;
struct hfi1_dms_tx_tracker;
union hfi1_dms_16b_header;

TRACE_EVENT(dms_read_data,
	    TP_PROTO(struct hfi1_dms *dms, u32 src_lid, u64 mem_key, u64 offset, u64 size, struct hfi1_mem_region *rbuf, u64 rbuf_offset),
	    TP_ARGS(dms, src_lid, mem_key, offset, size, rbuf, rbuf_offset),
	    TP_STRUCT__entry(__field(struct hfi1_dms *, dms)
			     __field(u32, src_lid)
			     __field(u64, mem_key)
			     __field(u64, offset)
				 __field(u64, size)
				 __field(struct hfi1_mem_region *, rbuf)
				 __field(u64, rbuf_offset)),
	    TP_fast_assign(__entry->dms = dms;
			   __entry->src_lid = src_lid;
			   __entry->mem_key = mem_key;
			   __entry->offset = offset;
			   __entry->size = size;
			   __entry->rbuf = rbuf;
			   __entry->rbuf_offset = rbuf_offset;
	    ),
	    TP_printk("READ DATA - dms %p src_lid %u key %llx offset %llu size %llu rbuf %p rbuf_offset %llu ",
		      __entry->dms, __entry->src_lid, __entry->mem_key,
		      __entry->offset, __entry->size, __entry->rbuf,
			  __entry->rbuf_offset)
);

TRACE_EVENT(dms_make_read_request,
		TP_PROTO(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *tracker, u32 tid_set),
		TP_ARGS(dms, tracker, tid_set),
		TP_STRUCT__entry(__field(struct hfi1_dms *, dms)
				 __field(struct hfi1_dms_rx_tracker *, tracker)
				 __field(u32, tid_set)),
		TP_fast_assign(__entry->dms = dms;
			       __entry->tracker = tracker;
			       __entry->tid_set = tid_set;),
		TP_printk("MAKE READ REQUEST - dms %p tracker %p tid_set %u", 
			  __entry->dms, __entry->tracker, __entry->tid_set)
);

TRACE_EVENT(dms_make_fixup_read_request,
		TP_PROTO(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *tracker),
		TP_ARGS(dms, tracker),
		TP_STRUCT__entry(__field(struct hfi1_dms *, dms)
				 __field(struct hfi1_dms_rx_tracker *, tracker)),
		TP_fast_assign(__entry->dms = dms;
			       __entry->tracker = tracker;),
		TP_printk("MAKE READ REQUEST - dms %p tracker %p",
			  __entry->dms, __entry->tracker)
);

TRACE_EVENT(dms_map_tid_entries,
		TP_PROTO(struct hfi1_dms *dms, struct hfi1_dms_rx_tracker *tracker, u64 start_page_index, u64 npages, s32 tid_set),
		TP_ARGS(dms, tracker, start_page_index, npages, tid_set),
		TP_STRUCT__entry(__field(struct hfi1_dms *, dms)
				 __field(struct hfi1_dms_rx_tracker *, tracker)
				 __field(u64, start_page_index)
				 __field(u64, npages)
				 __field(s32, tid_set)),
		TP_fast_assign(__entry->dms = dms;
			       __entry->tracker = tracker;
			       __entry->start_page_index = start_page_index;
			       __entry->npages = npages;
			       __entry->tid_set = tid_set;),
		TP_printk("MAP TID ENTRIES - dms %p tracker %p start_page_index %llu npages %llu tid_set %d",
			  __entry->dms, __entry->tracker,
			  __entry->start_page_index, __entry->npages,
			  __entry->tid_set)
);

TRACE_EVENT(dms_poll,
		TP_PROTO(struct hfi1_dms *dms),
		TP_ARGS(dms),
		TP_STRUCT__entry(__field(struct hfi1_dms *, dms)),
		TP_fast_assign(__entry->dms = dms;),
		TP_printk("POLL - dms %p",
			  __entry->dms)
);

TRACE_EVENT(dms_handle_read_request,
		TP_PROTO(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr),
		TP_ARGS(dms, hdr),
		TP_STRUCT__entry(__field(struct hfi1_dms *, dms)
				 __field(union hfi1_dms_16b_header *, hdr)),
		TP_fast_assign(__entry->dms = dms;
			       __entry->hdr = hdr;),
		TP_printk("HANDLE READ REQUEST - dms %p hdr %p",
			  __entry->dms, __entry->hdr)
);

TRACE_EVENT(dms_handle_read_request_fixup,
		TP_PROTO(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr),
		TP_ARGS(dms, hdr),
		TP_STRUCT__entry(__field(struct hfi1_dms *, dms)
				 __field(union hfi1_dms_16b_header *, hdr)),
		TP_fast_assign(__entry->dms = dms;
			       __entry->hdr = hdr;),
		TP_printk("HANDLE READ REQUEST FIXUP - dms %p hdr %p",
			  __entry->dms, __entry->hdr)
);

TRACE_EVENT(dms_sdma_send,
		TP_PROTO(struct hfi1_dms *dms, struct hfi1_dms_tx_tracker *tracker, union hfi1_dms_16b_header *hdr),
		TP_ARGS(dms, tracker, hdr),
		TP_STRUCT__entry(__field(struct hfi1_dms *, dms)
				 __field(struct hfi1_dms_tx_tracker *, tracker)
				 __field(union hfi1_dms_16b_header *, hdr)),
		TP_fast_assign(__entry->dms = dms;
			       __entry->tracker = tracker;
			       __entry->hdr = hdr;),
		TP_printk("SDMA SEND - dms %p tracker %p hdr %p",
			  __entry->dms, __entry->tracker, __entry->hdr)
);

TRACE_EVENT(dms_handle_data,
		TP_PROTO(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr),
		TP_ARGS(dms, hdr),
		TP_STRUCT__entry(__field(struct hfi1_dms *, dms)
				 __field(union hfi1_dms_16b_header *, hdr)),
		TP_fast_assign(__entry->dms = dms;
			       __entry->hdr = hdr;),
		TP_printk("HANDLE DATA - dms %p hdr %p",
			  __entry->dms, __entry->hdr)
);

TRACE_EVENT(dms_handle_data_fixup,
		TP_PROTO(struct hfi1_dms *dms, union hfi1_dms_16b_header *hdr, u8 *data),
		TP_ARGS(dms, hdr, data),
		TP_STRUCT__entry(__field(struct hfi1_dms *, dms)
				 __field(union hfi1_dms_16b_header *, hdr)
				 __field(u8 *, data)),
		TP_fast_assign(__entry->dms = dms;
			       __entry->hdr = hdr;
			       __entry->data = data;),
		TP_printk("HANDLE DATA FIXUP - dms %p hdr %p data %p",
			  __entry->dms, __entry->hdr, __entry->data)
);






#endif /* __HFI1_TRACE_DMS_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_dms
#include <trace/define_trace.h>
