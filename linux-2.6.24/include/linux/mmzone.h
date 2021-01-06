#ifndef _LINUX_MMZONE_H
#define _LINUX_MMZONE_H

#ifdef __KERNEL__
#ifndef __ASSEMBLY__

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <linux/numa.h>
#include <linux/init.h>
#include <linux/seqlock.h>
#include <linux/nodemask.h>
#include <linux/pageblock-flags.h>
#include <asm/atomic.h>
#include <asm/page.h>

/* Free memory management - zoned buddy allocator.  */
#ifndef CONFIG_FORCE_MAX_ZONEORDER
#define MAX_ORDER 11
#else
#define MAX_ORDER CONFIG_FORCE_MAX_ZONEORDER
#endif
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))

/*
 * PAGE_ALLOC_COSTLY_ORDER is the order at which allocations are deemed
 * costly to service.  That is between allocation orders which should
 * coelesce naturally under reasonable reclaim pressure and those which
 * will not.
 */
#define PAGE_ALLOC_COSTLY_ORDER 3

#define MIGRATE_UNMOVABLE     0
#define MIGRATE_RECLAIMABLE   1
#define MIGRATE_MOVABLE       2
#define MIGRATE_RESERVE       3
#define MIGRATE_ISOLATE       4 /* can't allocate from here */
#define MIGRATE_TYPES         5

#define for_each_migratetype_order(order, type) \
	for (order = 0; order < MAX_ORDER; order++) \
		for (type = 0; type < MIGRATE_TYPES; type++)

extern int page_group_by_mobility_disabled;

static inline int get_pageblock_migratetype(struct page *page)
{
	if (unlikely(page_group_by_mobility_disabled))
		return MIGRATE_UNMOVABLE;

	return get_pageblock_flags_group(page, PB_migrate, PB_migrate_end);
}

/*
 * 伙伴系统特定order的空闲页框块链表
 * 链表内空闲页框块大小相同，且为2的倍数
 *
 * Linux 内核2.6.24之前，free_area只采用一个链表管理空闲页框块
 * 但由于，伙伴系统仅仅寄托于内存释放时的合并操作而不考虑分配时的策略，
 * 即伙伴系统的碎片防止机制寄托于内存使用者会及时释放掉内存的情况，
 * 当系统长期运行，或使用者长期不释放内存时，物理内存依然会产生很多碎片。
 *
 * 为解决上述问题，Linux内核引入反碎片(anti-gragmentation)技术——内存分类
 * 将相同order的空闲页框块按可移动属性分成不同的类别(MIGRATE_TYPES)，每个类别对应一个链表单独维护
 * 当出现碎片时，可移动页面将会迁移，为申请者腾出所需的连续页面空间
 * 由此避免空闲页面空间过于零碎而无法申请大块连续内存的情况
 */
struct free_area {
	/* 不同类别的子空闲内存块链表 */
	struct list_head	free_list[MIGRATE_TYPES];
	/* 空闲页框块总个数 */
	unsigned long		nr_free;
};

struct pglist_data;

/*
 * zone->lock and zone->lru_lock are two of the hottest locks in the kernel.
 * So add a wild amount of padding here to ensure that they fall into separate
 * cachelines.  There are very few zone structures in the machine, so space
 * consumption is not a concern here.
 */
#if defined(CONFIG_SMP)
struct zone_padding {
	char x[0];
} ____cacheline_internodealigned_in_smp;
#define ZONE_PADDING(name)	struct zone_padding name;
#else
#define ZONE_PADDING(name)
#endif

enum zone_stat_item {
	/* First 128 byte cacheline (assuming 64 bit words) */
	NR_FREE_PAGES,
	NR_INACTIVE,
	NR_ACTIVE,
	NR_ANON_PAGES,	/* Mapped anonymous pages */
	NR_FILE_MAPPED,	/* pagecache pages mapped into pagetables.
			   only modified from process context */
	NR_FILE_PAGES,
	NR_FILE_DIRTY,
	NR_WRITEBACK,
	/* Second 128 byte cacheline */
	NR_SLAB_RECLAIMABLE,
	NR_SLAB_UNRECLAIMABLE,
	NR_PAGETABLE,		/* used for pagetables */
	NR_UNSTABLE_NFS,	/* NFS unstable pages */
	NR_BOUNCE,
	NR_VMSCAN_WRITE,
#ifdef CONFIG_NUMA
	NUMA_HIT,		/* allocated in intended node */
	NUMA_MISS,		/* allocated in non intended node */
	NUMA_FOREIGN,		/* was intended here, hit elsewhere */
	NUMA_INTERLEAVE_HIT,	/* interleaver preferred this zone */
	NUMA_LOCAL,		/* allocation from local node */
	NUMA_OTHER,		/* allocation from other node */
#endif
	NR_VM_ZONE_STAT_ITEMS };

struct per_cpu_pages {
	int count;		/* number of pages in the list */
	int high;		/* high watermark, emptying needed */
	int batch;		/* chunk size for buddy add/remove */
	struct list_head list;	/* the list of pages */
};

struct per_cpu_pageset {
	struct per_cpu_pages pcp[2];	/* 0: hot.  1: cold */
#ifdef CONFIG_NUMA
	s8 expire;
#endif
#ifdef CONFIG_SMP
	s8 stat_threshold;
	s8 vm_stat_diff[NR_VM_ZONE_STAT_ITEMS];
#endif
} ____cacheline_aligned_in_smp;

#ifdef CONFIG_NUMA
#define zone_pcp(__z, __cpu) ((__z)->pageset[(__cpu)])
#else
#define zone_pcp(__z, __cpu) (&(__z)->pageset[(__cpu)])
#endif

/* 管理区类型，不同管理区类型适合不同类型的用途 */
enum zone_type {
#ifdef CONFIG_ZONE_DMA
	/*
	 * ZONE_DMA is used when there are devices that are not able
	 * to do DMA to all of addressable memory (ZONE_NORMAL). Then we
	 * carve out the portion of memory that is needed for these devices.
	 * The range is arch specific.
	 *
	 * Some examples
	 *
	 * Architecture		Limit
	 * ---------------------------
	 * parisc, ia64, sparc	<4G
	 * s390			<2G
	 * arm			Various
	 * alpha		Unlimited or 0-16MB.
	 *
	 * i386, x86_64 and multiple other arches
	 * 			<16M.
	 */
	/*
	 * 一些设备无法使用DMA访问所有物理内存地址
	 * 因此特定划分出该内存区域专门用于特殊DMA访问
	 */
	ZONE_DMA,
#endif
#ifdef CONFIG_ZONE_DMA32
	/*
	 * x86_64 needs two ZONE_DMAs because it supports devices that are
	 * only able to do DMA to the lower 16M but also 32 bit devices that
	 * can only do DMA areas below 4G.
	 */
	/* 服务于x86_64体系结构的第二个DMA直接内存寻址区域 */
	ZONE_DMA32,
#endif
	/*
	 * Normal addressable memory is in ZONE_NORMAL. DMA operations can be
	 * performed on pages in ZONE_NORMAL if the DMA devices support
	 * transfers to all addressable memory.
	 */
	/* 可直接线性映射到内核地址空间，内核可直接访问 */
	ZONE_NORMAL,
#ifdef CONFIG_HIGHMEM
	/*
	 * A memory area that is only addressable by the kernel through
	 * mapping portions into its own address space. This is for example
	 * used by i386 to allow the kernel to address the memory beyond
	 * 900MB. The kernel will set up special mappings (page
	 * table entries on i386) for each page that the kernel needs to
	 * access.
	 */
	/*
	 * 高端内存管理区，需要内核进行map之后才能访问
	 * 对于64位体系结构，地址空间足够线性映射所有物理内存，因此一般不需要高端内存
	 */
	ZONE_HIGHMEM,
#endif
	/*
	 * 可迁移内存管理区，一般是从高端内存管理区划分而来的虚拟管理区，不额外占用内存空间
	 * 引入该区域的目的是减少内存碎片，优化内存迁移场景，将Non-Movable和Movable的内存分区管理
	 */
	ZONE_MOVABLE,
	MAX_NR_ZONES
};

/*
 * When a memory allocation must conform to specific limitations (such
 * as being suitable for DMA) the caller will pass in hints to the
 * allocator in the gfp_mask, in the zone modifier bits.  These bits
 * are used to select a priority ordered list of memory zones which
 * match the requested limits. See gfp_zone() in include/linux/gfp.h
 */

/*
 * Count the active zones.  Note that the use of defined(X) outside
 * #if and family is not necessarily defined so ensure we cannot use
 * it later.  Use __ZONE_COUNT to work out how many shift bits we need.
 */
#define __ZONE_COUNT (			\
	  defined(CONFIG_ZONE_DMA)	\
	+ defined(CONFIG_ZONE_DMA32)	\
	+ 1				\
	+ defined(CONFIG_HIGHMEM)	\
	+ 1				\
)
#if __ZONE_COUNT < 2
#define ZONES_SHIFT 0
#elif __ZONE_COUNT <= 2
#define ZONES_SHIFT 1
#elif __ZONE_COUNT <= 4
#define ZONES_SHIFT 2
#else
#error ZONES_SHIFT -- too many zones configured adjust calculation
#endif
#undef __ZONE_COUNT

/* 内存管理区描述符 */
struct zone {
	/* Fields commonly accessed by the page allocator */
	unsigned long		pages_min, pages_low, pages_high;
	/*
	 * We don't know if the memory that we're going to allocate will be freeable
	 * or/and it will be released eventually, so to avoid totally wasting several
	 * GB of ram we must reserve some of the lower zone memory (otherwise we risk
	 * to run OOM on the lower zones despite there's tons of freeable ram
	 * on the higher zones). This array is recalculated at runtime if the
	 * sysctl_lowmem_reserve_ratio sysctl changes.
	 */
	unsigned long		lowmem_reserve[MAX_NR_ZONES];

#ifdef CONFIG_NUMA
	/* NUMA系统中，管理区所属的节点id */
	int node;
	/*
	 * zone reclaim becomes active if more unmapped pages exist.
	 */
	unsigned long		min_unmapped_pages;
	unsigned long		min_slab_pages;
	struct per_cpu_pageset	*pageset[NR_CPUS];
#else
	struct per_cpu_pageset	pageset[NR_CPUS];
#endif
	/*
	 * free areas of different sizes
	 */
	spinlock_t		lock;
#ifdef CONFIG_MEMORY_HOTPLUG
	/* see spanned/present_pages for more description */
	seqlock_t		span_seqlock;
#endif
	/*
	 * 伙伴系统-管理内存分区空闲内存
	 * 伙伴系统把所有空闲页框分组为MAX_ORDER(默认值为11)个块链表
	 * 每个链表分别包含大小为2^0、2^1、2^2、2^3、2^4、...、2^(MAX_ORDER)个连续的页框
	 *
	 * 分配策略：
	 * 请求内存时，使用最小连续内存页框块满足内存分配
	 * 当所请求的最小连续内存块链表无空闲块满足分配时，则依次向上遍历
	 * 直到能满足分配为止，并将满足分配请求后剩余的块按order划分插入到对应空闲链表内
	 *
	 * 释放策略：
	 * 释放内存时，插入到对应order的空闲链表时，尝试将一对空闲伙伴块合并为一个两倍大小的单独块
	 * 并将合并后的单独块插入到高一级的空闲链表内，继续执行上述合并动作，直到无法合并为止
	 *
	 * ????????为什么要引入伙伴系统机制管理空闲内存????????
	 */
	struct free_area	free_area[MAX_ORDER];

#ifndef CONFIG_SPARSEMEM
	/*
	 * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
	 * In SPARSEMEM, this map is stored in struct mem_section
	 */
	unsigned long		*pageblock_flags;
#endif /* CONFIG_SPARSEMEM */


	ZONE_PADDING(_pad1_)

	/* Fields commonly accessed by the page reclaim scanner */
	spinlock_t		lru_lock;	
	struct list_head	active_list;
	struct list_head	inactive_list;
	unsigned long		nr_scan_active;
	unsigned long		nr_scan_inactive;
	unsigned long		pages_scanned;	   /* since last reclaim */
	unsigned long		flags;		   /* zone flags, see below */

	/* Zone statistics */
	atomic_long_t		vm_stat[NR_VM_ZONE_STAT_ITEMS];

	/*
	 * prev_priority holds the scanning priority for this zone.  It is
	 * defined as the scanning priority at which we achieved our reclaim
	 * target at the previous try_to_free_pages() or balance_pgdat()
	 * invokation.
	 *
	 * We use prev_priority as a measure of how much stress page reclaim is
	 * under - it drives the swappiness decision: whether to unmap mapped
	 * pages.
	 *
	 * Access to both this field is quite racy even on uniprocessor.  But
	 * it is expected to average out OK.
	 */
	int prev_priority;


	ZONE_PADDING(_pad2_)
	/* Rarely used or read-mostly fields */

	/*
	 * wait_table		-- the array holding the hash table
	 * wait_table_hash_nr_entries	-- the size of the hash table array
	 * wait_table_bits	-- wait_table_size == (1 << wait_table_bits)
	 *
	 * The purpose of all these is to keep track of the people
	 * waiting for a page to become available and make them
	 * runnable again when possible. The trouble is that this
	 * consumes a lot of space, especially when so few things
	 * wait on pages at a given time. So instead of using
	 * per-page waitqueues, we use a waitqueue hash table.
	 *
	 * The bucket discipline is to sleep on the same queue when
	 * colliding and wake all in that wait queue when removing.
	 * When something wakes, it must check to be sure its page is
	 * truly available, a la thundering herd. The cost of a
	 * collision is great, but given the expected load of the
	 * table, they should be so rare as to be outweighed by the
	 * benefits from the saved space.
	 *
	 * __wait_on_page_locked() and unlock_page() in mm/filemap.c, are the
	 * primary users of these fields, and in mm/page_alloc.c
	 * free_area_init_core() performs the initialization of them.
	 */
	wait_queue_head_t	* wait_table;
	unsigned long		wait_table_hash_nr_entries;
	unsigned long		wait_table_bits;

	/*
	 * Discontig memory support fields.
	 */
	struct pglist_data	*zone_pgdat;
	/* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
	unsigned long		zone_start_pfn;

	/*
	 * zone_start_pfn, spanned_pages and present_pages are all
	 * protected by span_seqlock.  It is a seqlock because it has
	 * to be read outside of zone->lock, and it is done in the main
	 * allocator path.  But, it is written quite infrequently.
	 *
	 * The lock is declared along with zone->lock because it is
	 * frequently read in proximity to zone->lock.  It's good to
	 * give them a chance of being in the same cacheline.
	 */
	unsigned long		spanned_pages;	/* total size, including holes */
	unsigned long		present_pages;	/* amount of memory (excluding holes) */

	/*
	 * rarely used fields:
	 */
	const char		*name;
} ____cacheline_internodealigned_in_smp;

typedef enum {
	ZONE_ALL_UNRECLAIMABLE,		/* all pages pinned */
	ZONE_RECLAIM_LOCKED,		/* prevents concurrent reclaim */
	ZONE_OOM_LOCKED,		/* zone is in OOM killer zonelist */
} zone_flags_t;

static inline void zone_set_flag(struct zone *zone, zone_flags_t flag)
{
	set_bit(flag, &zone->flags);
}

static inline int zone_test_and_set_flag(struct zone *zone, zone_flags_t flag)
{
	return test_and_set_bit(flag, &zone->flags);
}

static inline void zone_clear_flag(struct zone *zone, zone_flags_t flag)
{
	clear_bit(flag, &zone->flags);
}

static inline int zone_is_all_unreclaimable(const struct zone *zone)
{
	return test_bit(ZONE_ALL_UNRECLAIMABLE, &zone->flags);
}

static inline int zone_is_reclaim_locked(const struct zone *zone)
{
	return test_bit(ZONE_RECLAIM_LOCKED, &zone->flags);
}

static inline int zone_is_oom_locked(const struct zone *zone)
{
	return test_bit(ZONE_OOM_LOCKED, &zone->flags);
}

/*
 * The "priority" of VM scanning is how much of the queues we will scan in one
 * go. A value of 12 for DEF_PRIORITY implies that we will scan 1/4096th of the
 * queues ("queue_length >> 12") during an aging round.
 */
#define DEF_PRIORITY 12

/* Maximum number of zones on a zonelist */
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)

#ifdef CONFIG_NUMA

/*
 * The NUMA zonelists are doubled becausse we need zonelists that restrict the
 * allocations to a single node for GFP_THISNODE.
 *
 * [0 .. MAX_NR_ZONES -1] 		: Zonelists with fallback
 * [MAZ_NR_ZONES ... MAZ_ZONELISTS -1]  : No fallback (GFP_THISNODE)
 */
/*
 * 非一致性内存访问NUMA中，MAX_ZONELISTS值为2*MAX_NR_ZONES
 * NUMA的node_zonelists由两部分组成
 * 前半部分指备选结点管理区列表，当自身管理区不满足分配时从备选列表尝试分配
 * 后半部分指自身结点管理区列表
 */
#define MAX_ZONELISTS (2 * MAX_NR_ZONES)


/*
 * We cache key information from each zonelist for smaller cache
 * footprint when scanning for free pages in get_page_from_freelist().
 *
 * 1) The BITMAP fullzones tracks which zones in a zonelist have come
 *    up short of free memory since the last time (last_fullzone_zap)
 *    we zero'd fullzones.
 * 2) The array z_to_n[] maps each zone in the zonelist to its node
 *    id, so that we can efficiently evaluate whether that node is
 *    set in the current tasks mems_allowed.
 *
 * Both fullzones and z_to_n[] are one-to-one with the zonelist,
 * indexed by a zones offset in the zonelist zones[] array.
 *
 * The get_page_from_freelist() routine does two scans.  During the
 * first scan, we skip zones whose corresponding bit in 'fullzones'
 * is set or whose corresponding node in current->mems_allowed (which
 * comes from cpusets) is not set.  During the second scan, we bypass
 * this zonelist_cache, to ensure we look methodically at each zone.
 *
 * Once per second, we zero out (zap) fullzones, forcing us to
 * reconsider nodes that might have regained more free memory.
 * The field last_full_zap is the time we last zapped fullzones.
 *
 * This mechanism reduces the amount of time we waste repeatedly
 * reexaming zones for free memory when they just came up low on
 * memory momentarilly ago.
 *
 * The zonelist_cache struct members logically belong in struct
 * zonelist.  However, the mempolicy zonelists constructed for
 * MPOL_BIND are intentionally variable length (and usually much
 * shorter).  A general purpose mechanism for handling structs with
 * multiple variable length members is more mechanism than we want
 * here.  We resort to some special case hackery instead.
 *
 * The MPOL_BIND zonelists don't need this zonelist_cache (in good
 * part because they are shorter), so we put the fixed length stuff
 * at the front of the zonelist struct, ending in a variable length
 * zones[], as is needed by MPOL_BIND.
 *
 * Then we put the optional zonelist cache on the end of the zonelist
 * struct.  This optional stuff is found by a 'zlcache_ptr' pointer in
 * the fixed length portion at the front of the struct.  This pointer
 * both enables us to find the zonelist cache, and in the case of
 * MPOL_BIND zonelists, (which will just set the zlcache_ptr to NULL)
 * to know that the zonelist cache is not there.
 *
 * The end result is that struct zonelists come in two flavors:
 *  1) The full, fixed length version, shown below, and
 *  2) The custom zonelists for MPOL_BIND.
 * The custom MPOL_BIND zonelists have a NULL zlcache_ptr and no zlcache.
 *
 * Even though there may be multiple CPU cores on a node modifying
 * fullzones or last_full_zap in the same zonelist_cache at the same
 * time, we don't lock it.  This is just hint data - if it is wrong now
 * and then, the allocator will still function, perhaps a bit slower.
 */


struct zonelist_cache {
	unsigned short z_to_n[MAX_ZONES_PER_ZONELIST];		/* zone->nid */
	DECLARE_BITMAP(fullzones, MAX_ZONES_PER_ZONELIST);	/* zone full? */
	unsigned long last_full_zap;		/* when last zap'd (jiffies) */
};
#else
/*
 * 一致性内存访问UMA中，MAX_ZONELISTS值则为MAX_NR_ZONES
 * UMA的node_zonelists只包含自身结点管理区
 */
#define MAX_ZONELISTS MAX_NR_ZONES
struct zonelist_cache;
#endif

/*
 * One allocation request operates on a zonelist. A zonelist
 * is a list of zones, the first one is the 'goal' of the
 * allocation, the other zones are fallback zones, in decreasing
 * priority.
 *
 * If zlcache_ptr is not NULL, then it is just the address of zlcache,
 * as explained above.  If zlcache_ptr is NULL, there is no zlcache.
 */
/* 内存结点的备选管理区列表，分配内存时按zones管理区依次遍历，直到满足分配为止 */
struct zonelist {
	struct zonelist_cache *zlcache_ptr;		     // NULL or &zlcache
	struct zone *zones[MAX_ZONES_PER_ZONELIST + 1];      // NULL delimited
#ifdef CONFIG_NUMA
	struct zonelist_cache zlcache;			     // optional ...
#endif
};

#ifdef CONFIG_NUMA
/*
 * Only custom zonelists like MPOL_BIND need to be filtered as part of
 * policies. As described in the comment for struct zonelist_cache, these
 * zonelists will not have a zlcache so zlcache_ptr will not be set. Use
 * that to determine if the zonelists needs to be filtered or not.
 */
static inline int alloc_should_filter_zonelist(struct zonelist *zonelist)
{
	return !zonelist->zlcache_ptr;
}
#else
static inline int alloc_should_filter_zonelist(struct zonelist *zonelist)
{
	return 0;
}
#endif /* CONFIG_NUMA */

#ifdef CONFIG_ARCH_POPULATES_NODE_MAP
struct node_active_region {
	unsigned long start_pfn;
	unsigned long end_pfn;
	int nid;
};
#endif /* CONFIG_ARCH_POPULATES_NODE_MAP */

#ifndef CONFIG_DISCONTIGMEM
/* The array of struct pages - for discontigmem use pgdat->lmem_map */
extern struct page *mem_map;
#endif

/*
 * The pg_data_t structure is used in machines with CONFIG_DISCONTIGMEM
 * (mostly NUMA machines?) to denote a higher-level memory zone than the
 * zone denotes.
 *
 * On NUMA machines, each NUMA node would have a pg_data_t to describe
 * it's memory layout.
 *
 * Memory statistics and page replacement data structures are maintained on a
 * per-zone basis.
 */
struct bootmem_data;
/*
 * 非一致性内存访问NUMA中，内存被分成许多簇
 * 依据簇与处理器“距离”的不同，访问不同的簇花费代价也不同
 * 每个簇又被认为是一个结点，对应struct pglist_data结构
 */
typedef struct pglist_data {
	/*
	 * 实际计算机体系结构存在诸多限制
	 * 1、ISA总线的直接内存寻址DMA只能对RAM的前16MB寻址
	 * 2、在具有大容量RAM的32位计算机中CPU无法直接通过逻辑地址线性映射到所有的物理地址
	 *
	 * 因此，Linux内核需对不同内存区域采用不同管理方法和映射机制
	 * 每个内存结点又被分成管理区，对应struct zone结构
	 */
	struct zone node_zones[MAX_NR_ZONES];
	/*
	 * 一致性内存访问UMA中，只存在一个结点，所有zone成员均在node_zones中存放
	 * 而对于非一致性内存访问UNMA而言，除本地结点，还可能存在多个远端内存结点
	 * 本地内存结点并不会存放远端内存结点得管理区zone信息，但当本段结点分配内存失败时，
	 * 其实可通过其他多端结点分配，因此引入zonelists概念将远端内存结点和本地内存结点统一挂在zonelist链表上
	 *
	 * NUMA中，MAX_ZONELISTS值为2*MAX_NR_ZONES，node_zonelists由两部分组成
	 * 前半部分[0~MAX_NR_ZONES-1]只包含各个远端结点管理区列表，当自身管理区不满足分配时可从备选列表尝试分配
	 * 后半部分[MAX_NR_ZONES~MAX_ZONELISTS]只包含自身结点管理区列表
	 *
	 * UMA中，MAX_ZONELISTS值则为MAX_NR_ZONES，node_zonelists只包含自身结点管理区
	 */
	struct zonelist node_zonelists[MAX_ZONELISTS];
	/* 该结点划分的管理区个数 */
	int nr_zones;
#ifdef CONFIG_FLAT_NODE_MEM_MAP
	struct page *node_mem_map;
#endif
	struct bootmem_data *bdata;
#ifdef CONFIG_MEMORY_HOTPLUG
	/*
	 * Must be held any time you expect node_start_pfn, node_present_pages
	 * or node_spanned_pages stay constant.  Holding this will also
	 * guarantee that any pfn_valid() stays that way.
	 *
	 * Nests above zone->lock and zone->size_seqlock.
	 */
	spinlock_t node_size_lock;
#endif
	/* 当前结点管理的物理内存起始页面号 */
	unsigned long node_start_pfn;
	/* 除开内存空洞之外的物理页面数 */
	unsigned long node_present_pages; /* total number of physical pages */
	/* 最大和最小页面号的差值，包含内存空洞的总的物理页面数 */
	unsigned long node_spanned_pages; /* total size of physical page
					     range, including holes */
	/* 当前结点唯一标识id */
	int node_id;
	wait_queue_head_t kswapd_wait;
	struct task_struct *kswapd;
	int kswapd_max_order;
} pg_data_t;

#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#ifdef CONFIG_FLAT_NODE_MEM_MAP
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#else
#define pgdat_page_nr(pgdat, pagenr)	pfn_to_page((pgdat)->node_start_pfn + (pagenr))
#endif
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))

#include <linux/memory_hotplug.h>

void get_zone_counts(unsigned long *active, unsigned long *inactive,
			unsigned long *free);
void build_all_zonelists(void);
void wakeup_kswapd(struct zone *zone, int order);
int zone_watermark_ok(struct zone *z, int order, unsigned long mark,
		int classzone_idx, int alloc_flags);
enum memmap_context {
	MEMMAP_EARLY,
	MEMMAP_HOTPLUG,
};
extern int init_currently_empty_zone(struct zone *zone, unsigned long start_pfn,
				     unsigned long size,
				     enum memmap_context context);

#ifdef CONFIG_HAVE_MEMORY_PRESENT
void memory_present(int nid, unsigned long start, unsigned long end);
#else
static inline void memory_present(int nid, unsigned long start, unsigned long end) {}
#endif

#ifdef CONFIG_NEED_NODE_MEMMAP_SIZE
unsigned long __init node_memmap_size_bytes(int, unsigned long, unsigned long);
#endif

/*
 * zone_idx() returns 0 for the ZONE_DMA zone, 1 for the ZONE_NORMAL zone, etc.
 */
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)

static inline int populated_zone(struct zone *zone)
{
	return (!!zone->present_pages);
}

extern int movable_zone;

static inline int zone_movable_is_highmem(void)
{
#if defined(CONFIG_HIGHMEM) && defined(CONFIG_ARCH_POPULATES_NODE_MAP)
	return movable_zone == ZONE_HIGHMEM;
#else
	return 0;
#endif
}

static inline int is_highmem_idx(enum zone_type idx)
{
#ifdef CONFIG_HIGHMEM
	return (idx == ZONE_HIGHMEM ||
		(idx == ZONE_MOVABLE && zone_movable_is_highmem()));
#else
	return 0;
#endif
}

static inline int is_normal_idx(enum zone_type idx)
{
	return (idx == ZONE_NORMAL);
}

/**
 * is_highmem - helper function to quickly check if a struct zone is a 
 *              highmem zone or not.  This is an attempt to keep references
 *              to ZONE_{DMA/NORMAL/HIGHMEM/etc} in general code to a minimum.
 * @zone - pointer to struct zone variable
 */
static inline int is_highmem(struct zone *zone)
{
#ifdef CONFIG_HIGHMEM
	int zone_idx = zone - zone->zone_pgdat->node_zones;
	return zone_idx == ZONE_HIGHMEM ||
		(zone_idx == ZONE_MOVABLE && zone_movable_is_highmem());
#else
	return 0;
#endif
}

static inline int is_normal(struct zone *zone)
{
	return zone == zone->zone_pgdat->node_zones + ZONE_NORMAL;
}

static inline int is_dma32(struct zone *zone)
{
#ifdef CONFIG_ZONE_DMA32
	return zone == zone->zone_pgdat->node_zones + ZONE_DMA32;
#else
	return 0;
#endif
}

static inline int is_dma(struct zone *zone)
{
#ifdef CONFIG_ZONE_DMA
	return zone == zone->zone_pgdat->node_zones + ZONE_DMA;
#else
	return 0;
#endif
}

/* These two functions are used to setup the per zone pages min values */
struct ctl_table;
struct file;
int min_free_kbytes_sysctl_handler(struct ctl_table *, int, struct file *, 
					void __user *, size_t *, loff_t *);
extern int sysctl_lowmem_reserve_ratio[MAX_NR_ZONES-1];
int lowmem_reserve_ratio_sysctl_handler(struct ctl_table *, int, struct file *,
					void __user *, size_t *, loff_t *);
int percpu_pagelist_fraction_sysctl_handler(struct ctl_table *, int, struct file *,
					void __user *, size_t *, loff_t *);
int sysctl_min_unmapped_ratio_sysctl_handler(struct ctl_table *, int,
			struct file *, void __user *, size_t *, loff_t *);
int sysctl_min_slab_ratio_sysctl_handler(struct ctl_table *, int,
			struct file *, void __user *, size_t *, loff_t *);

extern int numa_zonelist_order_handler(struct ctl_table *, int,
			struct file *, void __user *, size_t *, loff_t *);
extern char numa_zonelist_order[];
#define NUMA_ZONELIST_ORDER_LEN 16	/* string buffer size */

#include <linux/topology.h>
/* Returns the number of the current Node. */
#ifndef numa_node_id
#define numa_node_id()		(cpu_to_node(raw_smp_processor_id()))
#endif

#ifndef CONFIG_NEED_MULTIPLE_NODES

/*
 * 对于一致性内存访问UMA，只存在一个内存结点
 * 使用静态变量contig_page_data表示结点结构
 */
extern struct pglist_data contig_page_data;
/* NODE_DATA宏获取指定id结点时，直接返回contig_page_data */
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map
#define MAX_NODES_SHIFT		1

#else /* CONFIG_NEED_MULTIPLE_NODES */

#include <asm/mmzone.h>

#endif /* !CONFIG_NEED_MULTIPLE_NODES */

extern struct pglist_data *first_online_pgdat(void);
extern struct pglist_data *next_online_pgdat(struct pglist_data *pgdat);
extern struct zone *next_zone(struct zone *zone);

/**
 * for_each_pgdat - helper macro to iterate over all nodes
 * @pgdat - pointer to a pg_data_t variable
 */
#define for_each_online_pgdat(pgdat)			\
	for (pgdat = first_online_pgdat();		\
	     pgdat;					\
	     pgdat = next_online_pgdat(pgdat))
/**
 * for_each_zone - helper macro to iterate over all memory zones
 * @zone - pointer to struct zone variable
 *
 * The user only needs to declare the zone variable, for_each_zone
 * fills it in.
 */
#define for_each_zone(zone)			        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))

#ifdef CONFIG_SPARSEMEM
#include <asm/sparsemem.h>
#endif

#if BITS_PER_LONG == 32
/*
 * with 32 bit page->flags field, we reserve 9 bits for node/zone info.
 * there are 4 zones (3 bits) and this leaves 9-3=6 bits for nodes.
 */
#define FLAGS_RESERVED		9

#elif BITS_PER_LONG == 64
/*
 * with 64 bit flags field, there's plenty of room.
 */
#define FLAGS_RESERVED		32

#else

#error BITS_PER_LONG not defined

#endif

#if !defined(CONFIG_HAVE_ARCH_EARLY_PFN_TO_NID) && \
	!defined(CONFIG_ARCH_POPULATES_NODE_MAP)
#define early_pfn_to_nid(nid)  (0UL)
#endif

#ifdef CONFIG_FLATMEM
#define pfn_to_nid(pfn)		(0)
#endif

#define pfn_to_section_nr(pfn) ((pfn) >> PFN_SECTION_SHIFT)
#define section_nr_to_pfn(sec) ((sec) << PFN_SECTION_SHIFT)

#ifdef CONFIG_SPARSEMEM

/*
 * SECTION_SHIFT    		#bits space required to store a section #
 *
 * PA_SECTION_SHIFT		physical address to/from section number
 * PFN_SECTION_SHIFT		pfn to/from section number
 */
#define SECTIONS_SHIFT		(MAX_PHYSMEM_BITS - SECTION_SIZE_BITS)

#define PA_SECTION_SHIFT	(SECTION_SIZE_BITS)
#define PFN_SECTION_SHIFT	(SECTION_SIZE_BITS - PAGE_SHIFT)

#define NR_MEM_SECTIONS		(1UL << SECTIONS_SHIFT)

#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define PAGE_SECTION_MASK	(~(PAGES_PER_SECTION-1))

#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)

#if (MAX_ORDER - 1 + PAGE_SHIFT) > SECTION_SIZE_BITS
#error Allocator MAX_ORDER exceeds SECTION_SIZE
#endif

struct page;
struct mem_section {
	/*
	 * This is, logically, a pointer to an array of struct
	 * pages.  However, it is stored with some other magic.
	 * (see sparse.c::sparse_init_one_section())
	 *
	 * Additionally during early boot we encode node id of
	 * the location of the section here to guide allocation.
	 * (see sparse.c::memory_present())
	 *
	 * Making it a UL at least makes someone do a cast
	 * before using it wrong.
	 */
	unsigned long section_mem_map;

	/* See declaration of similar field in struct zone */
	unsigned long *pageblock_flags;
};

#ifdef CONFIG_SPARSEMEM_EXTREME
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#else
#define SECTIONS_PER_ROOT	1
#endif

#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define NR_SECTION_ROOTS	(NR_MEM_SECTIONS / SECTIONS_PER_ROOT)
#define SECTION_ROOT_MASK	(SECTIONS_PER_ROOT - 1)

#ifdef CONFIG_SPARSEMEM_EXTREME
extern struct mem_section *mem_section[NR_SECTION_ROOTS];
#else
extern struct mem_section mem_section[NR_SECTION_ROOTS][SECTIONS_PER_ROOT];
#endif

static inline struct mem_section *__nr_to_section(unsigned long nr)
{
	if (!mem_section[SECTION_NR_TO_ROOT(nr)])
		return NULL;
	return &mem_section[SECTION_NR_TO_ROOT(nr)][nr & SECTION_ROOT_MASK];
}
extern int __section_nr(struct mem_section* ms);

/*
 * We use the lower bits of the mem_map pointer to store
 * a little bit of information.  There should be at least
 * 3 bits here due to 32-bit alignment.
 */
#define	SECTION_MARKED_PRESENT	(1UL<<0)
#define SECTION_HAS_MEM_MAP	(1UL<<1)
#define SECTION_MAP_LAST_BIT	(1UL<<2)
#define SECTION_MAP_MASK	(~(SECTION_MAP_LAST_BIT-1))
#define SECTION_NID_SHIFT	2

static inline struct page *__section_mem_map_addr(struct mem_section *section)
{
	unsigned long map = section->section_mem_map;
	map &= SECTION_MAP_MASK;
	return (struct page *)map;
}

static inline int present_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_MARKED_PRESENT));
}

static inline int present_section_nr(unsigned long nr)
{
	return present_section(__nr_to_section(nr));
}

static inline int valid_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_HAS_MEM_MAP));
}

static inline int valid_section_nr(unsigned long nr)
{
	return valid_section(__nr_to_section(nr));
}

static inline struct mem_section *__pfn_to_section(unsigned long pfn)
{
	return __nr_to_section(pfn_to_section_nr(pfn));
}

static inline int pfn_valid(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return valid_section(__nr_to_section(pfn_to_section_nr(pfn)));
}

static inline int pfn_present(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return present_section(__nr_to_section(pfn_to_section_nr(pfn)));
}

/*
 * These are _only_ used during initialisation, therefore they
 * can use __initdata ...  They could have names to indicate
 * this restriction.
 */
#ifdef CONFIG_NUMA
#define pfn_to_nid(pfn)							\
({									\
	unsigned long __pfn_to_nid_pfn = (pfn);				\
	page_to_nid(pfn_to_page(__pfn_to_nid_pfn));			\
})
#else
#define pfn_to_nid(pfn)		(0)
#endif

#define early_pfn_valid(pfn)	pfn_valid(pfn)
void sparse_init(void);
#else
#define sparse_init()	do {} while (0)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#endif /* CONFIG_SPARSEMEM */

#ifdef CONFIG_NODES_SPAN_OTHER_NODES
#define early_pfn_in_nid(pfn, nid)	(early_pfn_to_nid(pfn) == (nid))
#else
#define early_pfn_in_nid(pfn, nid)	(1)
#endif

#ifndef early_pfn_valid
#define early_pfn_valid(pfn)	(1)
#endif

void memory_present(int nid, unsigned long start, unsigned long end);
unsigned long __init node_memmap_size_bytes(int, unsigned long, unsigned long);

/*
 * If it is possible to have holes within a MAX_ORDER_NR_PAGES, then we
 * need to check pfn validility within that MAX_ORDER_NR_PAGES block.
 * pfn_valid_within() should be used in this case; we optimise this away
 * when we have no holes within a MAX_ORDER_NR_PAGES block.
 */
#ifdef CONFIG_HOLES_IN_ZONE
#define pfn_valid_within(pfn) pfn_valid(pfn)
#else
#define pfn_valid_within(pfn) (1)
#endif

#endif /* !__ASSEMBLY__ */
#endif /* __KERNEL__ */
#endif /* _LINUX_MMZONE_H */
