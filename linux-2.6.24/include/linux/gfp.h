#ifndef __LINUX_GFP_H
#define __LINUX_GFP_H

#include <linux/mmzone.h>
#include <linux/stddef.h>
#include <linux/linkage.h>

struct vm_area_struct;

/*
 * GFP bitmasks..
 *
 * Zone modifiers (see linux/mmzone.h - low three bits)
 *
 * Do not put any conditional on these. If necessary modify the definitions
 * without the underscores and use the consistently. The definitions here may
 * be used in bit comparisons.
 */
#define __GFP_DMA	((__force gfp_t)0x01u)
#define __GFP_HIGHMEM	((__force gfp_t)0x02u)
#define __GFP_DMA32	((__force gfp_t)0x04u)

/*
 * Action modifiers - doesn't change the zoning
 *
 * __GFP_REPEAT: Try hard to allocate the memory, but the allocation attempt
 * _might_ fail.  This depends upon the particular VM implementation.
 *
 * __GFP_NOFAIL: The VM implementation _must_ retry infinitely: the caller
 * cannot handle allocation failures.
 *
 * __GFP_NORETRY: The VM implementation must not retry indefinitely.
 *
 * __GFP_MOVABLE: Flag that this page will be movable by the page migration
 * mechanism or reclaimed
 */
/* 允许内核对请求空闲页框块的当前进程进行阻塞 */
#define __GFP_WAIT	((__force gfp_t)0x10u)	/* Can wait and reschedule? */
/* 指明调用者是高优先级的，为了使系统能向前推进，必须准许这个请求 */
#define __GFP_HIGH	((__force gfp_t)0x20u)	/* Should access emergency pools? */
/* 允许读写存储设备 */
#define __GFP_IO	((__force gfp_t)0x40u)	/* Can start physical IO? */
/**
 * 允许向下调用底层文件系统
 *
 * 当文件系统申请页的时候，如果内存严重不足，直接回收页，把脏页写回存储设备，调用文件系统函数，可能导致四十
 * 为了避免死锁，文件系统申请页的时候应该清楚这个标志位
 */
#define __GFP_FS	((__force gfp_t)0x80u)	/* Can call down to low-level FS? */
/* 所请求的页可能为"冷"的，即不在CPU硬件高速缓存中 */
#define __GFP_COLD	((__force gfp_t)0x100u)	/* Cache-cold page required */
#define __GFP_NOWARN	((__force gfp_t)0x200u)	/* Suppress page allocation failure warning */
#define __GFP_REPEAT	((__force gfp_t)0x400u)	/* Retry the allocation.  Might fail */
#define __GFP_NOFAIL	((__force gfp_t)0x800u)	/* Retry for ever.  Cannot fail */
#define __GFP_NORETRY	((__force gfp_t)0x1000u)/* Do not retry.  Might fail */
#define __GFP_COMP	((__force gfp_t)0x4000u)/* Add compound page metadata */
#define __GFP_ZERO	((__force gfp_t)0x8000u)/* Return zeroed page on success */
/* 禁止访问紧急保留内存 */
#define __GFP_NOMEMALLOC ((__force gfp_t)0x10000u) /* Don't use emergency reserves */
/**
 * 实施cpuset内存分配策略
 * cpuset是控制组cgroup的一个子系统，提供把处理器和内存节点的集合分配给一组进程的机制
 * 即允许进程在哪些处理器上允许和从哪些内存节点申请页
 */
#define __GFP_HARDWALL   ((__force gfp_t)0x20000u) /* Enforce hardwall cpuset memory allocs */
#define __GFP_THISNODE	((__force gfp_t)0x40000u)/* No fallback, no policies */
#define __GFP_RECLAIMABLE ((__force gfp_t)0x80000u) /* Page is reclaimable */
#define __GFP_MOVABLE	((__force gfp_t)0x100000u)  /* Page is movable */

#define __GFP_BITS_SHIFT 21	/* Room for 21 __GFP_FOO bits */
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))

/* This equals 0, but use constants in case they ever change */
#define GFP_NOWAIT	(GFP_ATOMIC & ~__GFP_HIGH)
/* GFP_ATOMIC means both !wait (__GFP_WAIT not set) and use emergency pool */
#define GFP_ATOMIC	(__GFP_HIGH)
#define GFP_NOIO	(__GFP_WAIT)
#define GFP_NOFS	(__GFP_WAIT | __GFP_IO)
#define GFP_KERNEL	(__GFP_WAIT | __GFP_IO | __GFP_FS)
#define GFP_TEMPORARY	(__GFP_WAIT | __GFP_IO | __GFP_FS | \
			 __GFP_RECLAIMABLE)
#define GFP_USER	(__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
#define GFP_HIGHUSER	(__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_HARDWALL | \
			 __GFP_HIGHMEM)
#define GFP_HIGHUSER_MOVABLE	(__GFP_WAIT | __GFP_IO | __GFP_FS | \
				 __GFP_HARDWALL | __GFP_HIGHMEM | \
				 __GFP_MOVABLE)
#define GFP_NOFS_PAGECACHE	(__GFP_WAIT | __GFP_IO | __GFP_MOVABLE)
#define GFP_USER_PAGECACHE	(__GFP_WAIT | __GFP_IO | __GFP_FS | \
				 __GFP_HARDWALL | __GFP_MOVABLE)
#define GFP_HIGHUSER_PAGECACHE	(__GFP_WAIT | __GFP_IO | __GFP_FS | \
				 __GFP_HARDWALL | __GFP_HIGHMEM | \
				 __GFP_MOVABLE)

#ifdef CONFIG_NUMA
#define GFP_THISNODE	(__GFP_THISNODE | __GFP_NOWARN | __GFP_NORETRY)
#else
#define GFP_THISNODE	((__force gfp_t)0)
#endif

/* This mask makes up all the page movable related flags */
#define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)

/* Control page allocator reclaim behavior */
#define GFP_RECLAIM_MASK (__GFP_WAIT|__GFP_HIGH|__GFP_IO|__GFP_FS|\
			__GFP_NOWARN|__GFP_REPEAT|__GFP_NOFAIL|\
			__GFP_NORETRY|__GFP_NOMEMALLOC)

/* Control allocation constraints */
#define GFP_CONSTRAINT_MASK (__GFP_HARDWALL|__GFP_THISNODE)

/* Do not use these with a slab allocator */
#define GFP_SLAB_BUG_MASK (__GFP_DMA32|__GFP_HIGHMEM|~__GFP_BITS_MASK)

/* Flag - indicates that the buffer will be suitable for DMA.  Ignored on some
   platforms, used as appropriate on others */

#define GFP_DMA		__GFP_DMA

/* 4GB DMA on some platforms */
#define GFP_DMA32	__GFP_DMA32

/* Convert GFP flags to their corresponding migrate type */
static inline int allocflags_to_migratetype(gfp_t gfp_flags)
{
	/* __GFP_MOVABLE 和 __GFP_RECLAIMABLE不可同时存在 */
	WARN_ON((gfp_flags & GFP_MOVABLE_MASK) == GFP_MOVABLE_MASK);

	/* 内存可移动功能未开启时，空闲内存块的可移动类型均为MIGRATE_UNMOVABLE不可移动 */
	if (unlikely(page_group_by_mobility_disabled))
		return MIGRATE_UNMOVABLE;

	/* Group based on mobility */
	return (((gfp_flags & __GFP_MOVABLE) != 0) << 1) |
		((gfp_flags & __GFP_RECLAIMABLE) != 0);
}

/*
 * 根据内存分配掩码确定备选管理区列表
 * __GFP_THISNODE:表示只在当前结点的管理区内分配内存，对于备选列表[MAX_NR_ZONES~MAX_ZONELISTS-1]
 */
static inline enum zone_type gfp_zone(gfp_t flags)
{
	int base = 0;

#ifdef CONFIG_NUMA
	if (flags & __GFP_THISNODE)
		base = MAX_NR_ZONES;
#endif

#ifdef CONFIG_ZONE_DMA
	if (flags & __GFP_DMA)
		return base + ZONE_DMA;
#endif
#ifdef CONFIG_ZONE_DMA32
	if (flags & __GFP_DMA32)
		return base + ZONE_DMA32;
#endif
	if ((flags & (__GFP_HIGHMEM | __GFP_MOVABLE)) ==
			(__GFP_HIGHMEM | __GFP_MOVABLE))
		return base + ZONE_MOVABLE;
#ifdef CONFIG_HIGHMEM
	if (flags & __GFP_HIGHMEM)
		return base + ZONE_HIGHMEM;
#endif
	return base + ZONE_NORMAL;
}

static inline gfp_t set_migrateflags(gfp_t gfp, gfp_t migrate_flags)
{
	BUG_ON((gfp & GFP_MOVABLE_MASK) == GFP_MOVABLE_MASK);
	return (gfp & ~(GFP_MOVABLE_MASK)) | migrate_flags;
}

/*
 * There is only one page-allocator function, and two main namespaces to
 * it. The alloc_page*() variants return 'struct page *' and as such
 * can allocate highmem pages, the *get*page*() variants return
 * virtual kernel addresses to the allocated page(s).
 */

/*
 * We get the zone list from the current node and the gfp_mask.
 * This zone list contains a maximum of MAXNODES*MAX_NR_ZONES zones.
 *
 * For the normal case of non-DISCONTIGMEM systems the NODE_DATA() gets
 * optimized to &contig_page_data at compile-time.
 */

#ifndef HAVE_ARCH_FREE_PAGE
static inline void arch_free_page(struct page *page, int order) { }
#endif
#ifndef HAVE_ARCH_ALLOC_PAGE
static inline void arch_alloc_page(struct page *page, int order) { }
#endif

extern struct page *
FASTCALL(__alloc_pages(gfp_t, unsigned int, struct zonelist *));

static inline struct page *alloc_pages_node(int nid, gfp_t gfp_mask,
						unsigned int order)
{
	if (unlikely(order >= MAX_ORDER))
		return NULL;

	/* Unknown node is current node */
	if (nid < 0)
		nid = numa_node_id();

	return __alloc_pages(gfp_mask, order,
		NODE_DATA(nid)->node_zonelists + gfp_zone(gfp_mask));
}

#ifdef CONFIG_NUMA
extern struct page *alloc_pages_current(gfp_t gfp_mask, unsigned order);

/*
 * 分配2^order个连续的页框
 * 返回所分配第一个页框描述符的地址，如果失败，则返回NULL
 */
static inline struct page *
alloc_pages(gfp_t gfp_mask, unsigned int order)
{
	if (unlikely(order >= MAX_ORDER))
		return NULL;

	/*
	 * 根据当前进程的内存分配策略选择符合要求的结点
	 * 并根据内存分配掩码选择该结点的备选管理区列表
	 * 最后从备选管理区列表分配阶为order的空闲内存块
	 */
	return alloc_pages_current(gfp_mask, order);
}
extern struct page *alloc_page_vma(gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr);
#else
/*
 * 分配2^order个连续的页框
 * 返回所分配第一个页框描述符的地址，如果失败，则返回NULL
 */
#define alloc_pages(gfp_mask, order) \
		alloc_pages_node(numa_node_id(), gfp_mask, order)
#define alloc_page_vma(gfp_mask, vma, addr) alloc_pages(gfp_mask, 0)
#endif
/*
 * 请求一个单独页框
 * 返回所分配页框描述符的地址，如果失败，则返回NULL
 */
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

extern unsigned long FASTCALL(__get_free_pages(gfp_t gfp_mask, unsigned int order));
extern unsigned long FASTCALL(get_zeroed_page(gfp_t gfp_mask));

#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask),0)

#define __get_dma_pages(gfp_mask, order) \
		__get_free_pages((gfp_mask) | GFP_DMA,(order))

extern void FASTCALL(__free_pages(struct page *page, unsigned int order));
extern void FASTCALL(free_pages(unsigned long addr, unsigned int order));
extern void FASTCALL(free_hot_page(struct page *page));
extern void FASTCALL(free_cold_page(struct page *page));

#define __free_page(page) __free_pages((page), 0)
#define free_page(addr) free_pages((addr),0)

void page_alloc_init(void);
void drain_zone_pages(struct zone *zone, struct per_cpu_pages *pcp);

#endif /* __LINUX_GFP_H */
