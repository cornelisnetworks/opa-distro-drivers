/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2014 Mellanox Technologies. All rights reserved.
 */

#ifndef IB_UMEM_ODP_H
#define IB_UMEM_ODP_H

#include <rdma/ib_umem.h>
#include <rdma/ib_verbs.h>
#include <linux/interval_tree.h>

struct ib_umem_odp {
	struct ib_umem umem;
	struct ib_ucontext_per_mm *per_mm;

	/*
	 * An array of the pages included in the on-demand paging umem.
	 * Indices of pages that are currently not mapped into the device will
	 * contain NULL.
	 */
	struct page		**page_list;
	/*
	 * An array of the same size as page_list, with DMA addresses mapped
	 * for pages the pages in page_list. The lower two bits designate
	 * access permissions. See ODP_READ_ALLOWED_BIT and
	 * ODP_WRITE_ALLOWED_BIT.
	 */
	dma_addr_t		*dma_list;
	/*
	 * The umem_mutex protects the page_list and dma_list fields of an ODP
	 * umem, allowing only a single thread to map/unmap pages. The mutex
	 * also protects access to the mmu notifier counters.
	 */
	struct mutex		umem_mutex;
	void			*private; /* for the HW driver to use. */

	int notifiers_seq;
	int notifiers_count;
	int npages;

	/* Tree tracking */
	struct interval_tree_node interval_tree;

	/*
	 * An implicit odp umem cannot be DMA mapped, has 0 length, and serves
	 * only as an anchor for the driver to hold onto the per_mm. FIXME:
	 * This should be removed and drivers should work with the per_mm
	 * directly.
	 */
	bool is_implicit_odp;

	struct completion	notifier_completion;
	unsigned int		page_shift;
};

static inline struct ib_umem_odp *to_ib_umem_odp(struct ib_umem *umem)
{
	return container_of(umem, struct ib_umem_odp, umem);
}

/* Returns the first page of an ODP umem. */
static inline unsigned long ib_umem_start(struct ib_umem_odp *umem_odp)
{
	return umem_odp->interval_tree.start;
}

/* Returns the address of the page after the last one of an ODP umem. */
static inline unsigned long ib_umem_end(struct ib_umem_odp *umem_odp)
{
	return umem_odp->interval_tree.last + 1;
}

static inline size_t ib_umem_odp_num_pages(struct ib_umem_odp *umem_odp)
{
	return (ib_umem_end(umem_odp) - ib_umem_start(umem_odp)) >>
	       umem_odp->page_shift;
}

/*
 * The lower 2 bits of the DMA address signal the R/W permissions for
 * the entry. To upgrade the permissions, provide the appropriate
 * bitmask to the map_dma_pages function.
 *
 * Be aware that upgrading a mapped address might result in change of
 * the DMA address for the page.
 */
#define ODP_READ_ALLOWED_BIT  (1<<0ULL)
#define ODP_WRITE_ALLOWED_BIT (1<<1ULL)

#define ODP_DMA_ADDR_MASK (~(ODP_READ_ALLOWED_BIT | ODP_WRITE_ALLOWED_BIT))

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING

struct ib_ucontext_per_mm {
	struct ib_ucontext *context;
	struct mm_struct *mm;
	struct pid *tgid;
	bool active;

	struct rb_root_cached umem_tree;
	/* Protects umem_tree */
	struct rw_semaphore umem_rwsem;

	struct mmu_notifier mn;
	unsigned int odp_mrs_count;

	struct list_head ucontext_list;
	struct rcu_head rcu;
};

struct ib_umem_odp *ib_umem_odp_get(struct ib_udata *udata, unsigned long addr,
				    size_t size, int access);
struct ib_umem_odp *ib_umem_odp_alloc_implicit(struct ib_udata *udata,
					       int access);
struct ib_umem_odp *ib_umem_odp_alloc_child(struct ib_umem_odp *root_umem,
					    unsigned long addr, size_t size);
void ib_umem_odp_release(struct ib_umem_odp *umem_odp);

int ib_umem_odp_map_dma_pages(struct ib_umem_odp *umem_odp, u64 start_offset,
			      u64 bcnt, u64 access_mask,
			      unsigned long current_seq);

void ib_umem_odp_unmap_dma_pages(struct ib_umem_odp *umem_odp, u64 start_offset,
				 u64 bound);

typedef int (*umem_call_back)(struct ib_umem_odp *item, u64 start, u64 end,
			      void *cookie);
/*
 * Call the callback on each ib_umem in the range. Returns the logical or of
 * the return values of the functions called.
 */
int rbt_ib_umem_for_each_in_range(struct rb_root_cached *root,
				  u64 start, u64 end,
				  umem_call_back cb, void *cookie);

static inline int ib_umem_mmu_notifier_retry(struct ib_umem_odp *umem_odp,
					     unsigned long mmu_seq)
{
	/*
	 * This code is strongly based on the KVM code from
	 * mmu_notifier_retry. Should be called with
	 * the relevant locks taken (umem_odp->umem_mutex
	 * and the ucontext umem_mutex semaphore locked for read).
	 */

	if (unlikely(umem_odp->notifiers_count))
		return 1;
	if (umem_odp->notifiers_seq != mmu_seq)
		return 1;
	return 0;
}

#else /* CONFIG_INFINIBAND_ON_DEMAND_PAGING */

static inline struct ib_umem_odp *ib_umem_odp_get(struct ib_udata *udata,
						  unsigned long addr,
						  size_t size, int access)
{
	return ERR_PTR(-EINVAL);
}

static inline void ib_umem_odp_release(struct ib_umem_odp *umem_odp) {}

#endif /* CONFIG_INFINIBAND_ON_DEMAND_PAGING */

#endif /* IB_UMEM_ODP_H */
