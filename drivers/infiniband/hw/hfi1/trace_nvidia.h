/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2023 Cornelis Networks, Inc.
 */
#if !defined(__HFI1_TRACE_NVIDIA_H) || defined(TRACE_HEADER_MULTI_READ)
#define __HFI1_TRACE_NVIDIA_H

#include <linux/tracepoint.h>

#include "pin_nvidia.h"

#undef TRACE_SYSTEM
#define TRACE_SYSTEM hfi1_pin

DECLARE_EVENT_CLASS(hfi1_nvidia_node_template,
		    TP_PROTO(struct nvidia_pintree_node *node, int rc),
		    TP_ARGS(node, rc),
		    TP_STRUCT__entry(DD_DEV_ENTRY(node->pintree->state->pq->dd)
				     __field(struct nvidia_pintree *, cache)
				     __field(struct nvidia_pintree_node *, node)
				     __field(u64, start)
				     __field(u64, last)
				     __field(void*, page_table)
				     __field(void*, mapping)
				     __field(int, rc)
			),
		    TP_fast_assign(DD_DEV_ASSIGN(node->pintree->state->pq->dd);
				   __entry->cache = node->pintree;
				   __entry->node = node;
				   __entry->start = node->node.start;
				   __entry->last = node->node.last;
				   __entry->page_table = node->page_table;
				   __entry->mapping = node->mapping;
				   __entry->rc = rc;
			),
		    TP_printk("[%s] cache %p node %p start %llx last %llx page_table %p mapping %p",
			      __get_str(dev),
			      __entry->cache,
			      __entry->node,
			      __entry->start,
			      __entry->last,
			      __entry->page_table,
			      __entry->mapping
			)
);

/*
 * Called in places where node->node.{start,last} are not assigned yet; must
 * pass start, last in separately.
 */
TRACE_EVENT(hfi1_nvidia_node_pin,
	    TP_PROTO(struct nvidia_pintree_node *node, u64 start, u64 last, int rc),
	    TP_ARGS(node, start, last, rc),
	    TP_STRUCT__entry(DD_DEV_ENTRY(node->pintree->state->pq->dd)
			     __field(struct nvidia_pintree *, cache)
			     __field(struct nvidia_pintree_node *, node)
			     __field(u64, start)
			     __field(u64, last)
			     __field(void*, page_table)
			     __field(void*, mapping)
			     __field(int, rc)
		),
	    TP_fast_assign(DD_DEV_ASSIGN(node->pintree->state->pq->dd);
			   __entry->cache = node->pintree;
			   __entry->node = node;
			   __entry->start = start;
			   __entry->last = last;
			   __entry->page_table = node->page_table;
			   __entry->mapping = node->mapping;
			   __entry->rc = rc;
		),
	    TP_printk("[%s] cache %p node %p start %llx last %llx page_table %p mapping %p rc %d",
		      __get_str(dev),
		      __entry->cache,
		      __entry->node,
		      __entry->start,
		      __entry->last,
		      __entry->page_table,
		      __entry->mapping,
		      __entry->rc
		)
);

DEFINE_EVENT_PRINT(hfi1_nvidia_node_template, hfi1_nvidia_node_insert,
		   TP_PROTO(struct nvidia_pintree_node *node, int rc),
		   TP_ARGS(node, rc),
		   TP_printk("[%s] cache %p node %p start %llx last %llx rc %d",
			     __get_str(dev),
			     __entry->cache,
			     __entry->node,
			     __entry->start,
			     __entry->last,
			     __entry->rc)
);

/* rc is ignored */
DEFINE_EVENT(hfi1_nvidia_node_template, hfi1_nvidia_node_invalidated,
	     TP_PROTO(struct nvidia_pintree_node *node, int rc),
	     TP_ARGS(node, 0));

/* rc is ignored */
DEFINE_EVENT(hfi1_nvidia_node_template, hfi1_nvidia_node_evict,
	     TP_PROTO(struct nvidia_pintree_node *node, int rc),
	     TP_ARGS(node, 0));

#endif /* __HFI1_TRACE_NVIDIA_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_nvidia
#include <trace/define_trace.h>
