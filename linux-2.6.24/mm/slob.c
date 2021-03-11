/*
 * SLOB Allocator: Simple List Of Blocks
 * 传统K&R风格堆分配器，比SLAB分配器更简单，且更有效率。
 * 但比SLAB分配器更容易产生内存碎片，仅应用于小系统，特别是嵌入式系统。
 *
 * Matt Mackall <mpm@selenic.com> 12/30/03
 *
 * NUMA support by Paul Mundt, 2007.
 *
 * How SLOB works:
 *
 * The core of SLOB is a traditional K&R style heap allocator, with
 * support for returning aligned objects. The granularity of this
 * allocator is as little as 2 bytes, however typically most architectures
 * will require 4 bytes on 32-bit and 8 bytes on 64-bit.
 *
 * The slob heap is a linked list of pages from alloc_pages(), and
 * within each page, there is a singly-linked list of free blocks (slob_t).
 * The heap is grown on demand and allocation from the heap is currently
 * first-fit.
 *
 * Above this is an implementation of kmalloc/kfree. Blocks returned
 * from kmalloc are prepended with a 4-byte header with the kmalloc size.
 * If kmalloc is asked for objects of PAGE_SIZE or larger, it calls
 * alloc_pages() directly, allocating compound pages so the page order
 * does not have to be separately tracked, and also stores the exact
 * allocation size in page->private so that it can be used to accurately
 * provide ksize(). These objects are detected in kfree() because slob_page()
 * is false for them.
 *
 * SLAB is emulated on top of SLOB by simply calling constructors and
 * destructors for every SLAB allocation. Objects are returned with the
 * 4-byte alignment unless the SLAB_HWCACHE_ALIGN flag is set, in which
 * case the low-level allocator will fragment blocks to create the proper
 * alignment. Again, objects of page-size or greater are allocated by
 * calling alloc_pages(). As SLAB objects know their size, no separate
 * size bookkeeping is necessary and there is essentially no allocation
 * space overhead, and compound pages aren't needed for multi-page
 * allocations.
 *
 * NUMA support in SLOB is fairly simplistic, pushing most of the real
 * logic down to the page allocator, and simply doing the node accounting
 * on the upper levels. In the event that a node id is explicitly
 * provided, alloc_pages_node() with the specified node id is used
 * instead. The common case (or when the node id isn't explicitly provided)
 * will default to the current node, as per numa_node_id().
 *
 * Node aware pages are still inserted in to the global freelist, and
 * these are scanned for by matching against the node id encoded in the
 * page flags. As a result, block allocations that can be satisfied from
 * the freelist will only be done so on pages residing on the same node,
 * in order to prevent random node placement.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <asm/atomic.h>

/*
 * slob_block has a field 'units', which indicates size of block if +ve,
 * or offset of next block if -ve (in SLOB_UNITs).
 *
 * Free blocks of size 1 unit simply contain the offset of the next block.
 * Those with larger size contain their size in the first SLOB_UNIT of
 * memory, and the offset of the next free block in the second SLOB_UNIT.
 */
/* slob缓存基于单元管理，单元大小根据PAGE_SIZE的不同而不同，通常情况为2字节 */
#if PAGE_SIZE <= (32767 * 2)
typedef s16 slobidx_t;
#else
typedef s32 slobidx_t;
#endif

struct slob_block {
	slobidx_t units;
};
typedef struct slob_block slob_t;

/*
 * We use struct page fields to manage some slob allocation aspects,
 * however to avoid the horrible mess in include/linux/mm_types.h, we'll
 * just define our own struct page type variant here.
 */
struct slob_page {
	union {
		struct {
			unsigned long flags;	/* mandatory */
			atomic_t _count;	/* mandatory */
			/* slob缓存内空闲单元数 */
			slobidx_t units;	/* free units left in page */
			unsigned long pad[2];
			/* slob缓存首个空闲内存块地址 */
			slob_t *free;		/* first free slob_t in page */
			/* 链接空闲slob缓存 */
			struct list_head list;	/* linked list of free pages */
		};
		struct page page;
	};
};
static inline void struct_slob_page_wrong_size(void)
{ BUILD_BUG_ON(sizeof(struct slob_page) != sizeof(struct page)); }

/*
 * free_slob_page: call before a slob_page is returned to the page allocator.
 */
static inline void free_slob_page(struct slob_page *sp)
{
	reset_page_mapcount(&sp->page);
	sp->page.mapping = NULL;
}

/*
 * All (partially) free slob pages go on this list.
 */
static LIST_HEAD(free_slob_pages);

/*
 * slob_page: True for all slob pages (false for bigblock pages)
 */
static inline int slob_page(struct slob_page *sp)
{
	return test_bit(PG_active, &sp->flags);
}

static inline void set_slob_page(struct slob_page *sp)
{
	__set_bit(PG_active, &sp->flags);
}

static inline void clear_slob_page(struct slob_page *sp)
{
	__clear_bit(PG_active, &sp->flags);
}

/*
 * slob_page_free: true for pages on free_slob_pages list.
 */
static inline int slob_page_free(struct slob_page *sp)
{
	return test_bit(PG_private, &sp->flags);
}

static inline void set_slob_page_free(struct slob_page *sp)
{
	list_add(&sp->list, &free_slob_pages);
	__set_bit(PG_private, &sp->flags);
}

static inline void clear_slob_page_free(struct slob_page *sp)
{
	list_del(&sp->list);
	__clear_bit(PG_private, &sp->flags);
}

#define SLOB_UNIT sizeof(slob_t)
#define SLOB_UNITS(size) (((size) + SLOB_UNIT - 1)/SLOB_UNIT)
#define SLOB_ALIGN L1_CACHE_BYTES

/*
 * struct slob_rcu is inserted at the tail of allocated slob blocks, which
 * were created with a SLAB_DESTROY_BY_RCU slab. slob_rcu is used to free
 * the block using call_rcu.
 */
struct slob_rcu {
	struct rcu_head head;
	int size;
};

/*
 * slob_lock protects all slob allocator structures.
 */
static DEFINE_SPINLOCK(slob_lock);

/*
 * Encode the given size and next info into a free slob block s.
 */
/*
 * 一个slob中可以有多种大小不同的块，对于任何一个快来说都必须拥有自己的管理数据
 * 在slob中，空闲块总是按地址顺序链式连接的
 */
static void set_slob(slob_t *s, slobidx_t size, slob_t *next)
{
	slob_t *base = (slob_t *)((unsigned long)s & PAGE_MASK);
	slobidx_t offset = next - base;

	/* 对于占用单元数大于1的空闲块，第一个单元保存块的大小，第二个块保存下一个空闲块的偏移 */
	if (size > 1) {
		s[0].units = size;
		s[1].units = offset;
	/* 对于只占用一个单元的空闲块，该单元保存下一个空闲对象偏移的相反数 */
	} else
		s[0].units = -offset;
}

/*
 * Return the size of a slob block.
 */
static slobidx_t slob_units(slob_t *s)
{
	if (s->units > 0)
		return s->units;
	return 1;
}

/*
 * Return the next free slob block pointer after this one.
 */
static slob_t *slob_next(slob_t *s)
{
	slob_t *base = (slob_t *)((unsigned long)s & PAGE_MASK);
	slobidx_t next;

	if (s[0].units < 0)
		next = -s[0].units;
	else
		next = s[1].units;
	return base+next;
}

/*
 * Returns true if s is the last free block in its page.
 */
static int slob_last(slob_t *s)
{
	return !((unsigned long)slob_next(s) & ~PAGE_MASK);
}

/* 当通过SLOB分配超过一页大小的对象时，直接从伙伴系统分配阶为order的连续页 */
static void *slob_new_page(gfp_t gfp, int order, int node)
{
	void *page;

#ifdef CONFIG_NUMA
	if (node != -1)
		page = alloc_pages_node(node, gfp, order);
	else
#endif
		page = alloc_pages(gfp, order);

	if (!page)
		return NULL;

	return page_address(page);
}

/*
 * Allocate a slob block within a given slob_page sp.
 */
static void *slob_page_alloc(struct slob_page *sp, size_t size, int align)
{
	slob_t *prev, *cur, *aligned = 0;
	int delta = 0, units = SLOB_UNITS(size);

	/* 遍历slob缓存内的空闲内存块 */
	for (prev = NULL, cur = sp->free; ; prev = cur, cur = slob_next(cur)) {
		/* 获取当前空闲内存块的单元数 */
		slobidx_t avail = slob_units(cur);

		if (align) {
			aligned = (slob_t *)ALIGN((unsigned long)cur, align);
			delta = aligned - cur;
		}
		/* 若当前空闲内存块按align地址对齐后剩余的空闲单元数依旧能满足分配 */
		if (avail >= units + delta) { /* room enough? */
			slob_t *next;

			/*
			 * 若空闲块地址对齐后，首地址产生偏移，则将空闲块划分成两块
			 * 一块范围为[cur,aligned)，offset未aligned
			 * 另一块范围为[aligned,avail - delta + 1]，offset为next
			 */
			if (delta) { /* need to fragment head to align? */
				next = slob_next(cur);
				set_slob(aligned, avail - delta, next);
				set_slob(cur, delta, aligned);
				prev = cur;
				cur = aligned;
				avail = slob_units(cur);
			}

			next = slob_next(cur);
			/* 若空闲内存块刚好满足分配时，将该空闲内存块从空闲链表中直接剔除用于分配 */
			if (avail == units) { /* exact fit? unlink. */
				/* 满足分配的空闲内存块前还存在其他空闲内存块 */
				if (prev)
					set_slob(prev, slob_units(prev), next);
				/* 满足分配的空闲内存块前没有其他空闲内存块，将sp->free直接指向next */
				else
					sp->free = next;
			/* 若空闲内存块满足分配后，还有空闲单元剩余，则将满足分配后的剩余单元重新划成一个空闲内存块 */
			} else { /* fragment */
				if (prev)
					set_slob(prev, slob_units(prev), cur + units);
				else
					sp->free = cur + units;
				set_slob(cur + units, avail - units, next);
			}

			/* 更新slob缓存剩余空闲单元数 */
			sp->units -= units;
			/*
			 * 当slob缓存空闲单元数为0时，将slob缓存从空闲slob链表移除
			 * 后续当该slob缓存的对象被释放时，会重新将该slob缓存插入空闲slob链表
			 */
			if (!sp->units)
				clear_slob_page_free(sp);
			return cur;
		}
		if (slob_last(cur))
			return NULL;
	}
}

/*
 * slob_alloc: entry point into the slob allocator.
 */
static void *slob_alloc(size_t size, gfp_t gfp, int align, int node)
{
	struct slob_page *sp;
	struct list_head *prev;
	slob_t *b = NULL;
	unsigned long flags;

	spin_lock_irqsave(&slob_lock, flags);
	/* Iterate through each partially free page, try to find room */
	/* 遍历所有存在空闲单元的slob缓存 */
	list_for_each_entry(sp, &free_slob_pages, list) {
#ifdef CONFIG_NUMA
		/*
		 * If there's a node specification, search for a partial
		 * page with a matching node id in the freelist.
		 */
		/* NUMA开启时，用于对象分配的slob缓存所属节点必须与请求节点一致 */
		if (node != -1 && page_to_nid(&sp->page) != node)
			continue;
#endif
		/* Enough room on this page? */
		/* slob缓存内可用单元数小于对象实际所需单元数，不满足分配 */
		if (sp->units < SLOB_UNITS(size))
			continue;

		/* Attempt to alloc */
		prev = sp->list.prev;
		/* 从slob缓存中分配对象 */
		b = slob_page_alloc(sp, size, align);
		if (!b)
			continue;

		/* Improve fragment distribution and reduce our average
		 * search time by starting our next search here. (see
		 * Knuth vol 1, sec 2.5, pg 449) */
		if (prev != free_slob_pages.prev &&
				free_slob_pages.next != prev->next)
			list_move_tail(&free_slob_pages, prev->next);
		break;
	}
	spin_unlock_irqrestore(&slob_lock, flags);

	/* Not enough space: must allocate a new page */
	/* 当所有空闲slob缓存均不满足分配时，则从伙伴系统中分配单页补充slob缓存 */
	if (!b) {
		b = slob_new_page(gfp & ~__GFP_ZERO, 0, node);
		if (!b)
			return 0;
		/*
		 * Slob分配器将描述slob的变量打包成一个结构
		 * 然后和页描述符struct page一起组成一个联合体
		 * 这样就可以直接利用页描述符已占有的空间
		 * 将页描述符中无关紧要的字段填充为slob的有效描述字段
		 */
		sp = (struct slob_page *)virt_to_page(b);
		set_slob_page(sp);

		spin_lock_irqsave(&slob_lock, flags);
		/* slob缓存初始分配后可用单元数 */
		sp->units = SLOB_UNITS(PAGE_SIZE);
		/* sp->free指向slob中首个空闲块，初始分配时指向slob页首地址 */
		sp->free = b;
		INIT_LIST_HEAD(&sp->list);
		/* slob缓存初始分配后，只包含一个大小为SLOB_UNITS(PAGE_SIZE)的空闲块 */
		set_slob(b, SLOB_UNITS(PAGE_SIZE), b + SLOB_UNITS(PAGE_SIZE));
		/* 将分配的slob缓存连接到全局空闲slob链表free_slob_pages */
		set_slob_page_free(sp);
		/* 从刚分配的slob缓存分配大小为size的空闲块，用于满足对象分配 */
		b = slob_page_alloc(sp, size, align);
		BUG_ON(!b);
		spin_unlock_irqrestore(&slob_lock, flags);
	}
	if (unlikely((gfp & __GFP_ZERO) && b))
		memset(b, 0, size);
	return b;
}

/*
 * slob_free: entry point into the slob allocator.
 */
static void slob_free(void *block, int size)
{
	struct slob_page *sp;
	slob_t *prev, *next, *b = (slob_t *)block;
	slobidx_t units;
	unsigned long flags;

	if (unlikely(ZERO_OR_NULL_PTR(block)))
		return;
	BUG_ON(!size);

	sp = (struct slob_page *)virt_to_page(block);
	units = SLOB_UNITS(size);

	spin_lock_irqsave(&slob_lock, flags);

	if (sp->units + units == SLOB_UNITS(PAGE_SIZE)) {
		/* Go directly to page allocator. Do not pass slob allocator */
		if (slob_page_free(sp))
			clear_slob_page_free(sp);
		clear_slob_page(sp);
		free_slob_page(sp);
		free_page((unsigned long)b);
		goto out;
	}

	if (!slob_page_free(sp)) {
		/* This slob page is about to become partially free. Easy! */
		sp->units = units;
		sp->free = b;
		set_slob(b, units,
			(void *)((unsigned long)(b +
					SLOB_UNITS(PAGE_SIZE)) & PAGE_MASK));
		set_slob_page_free(sp);
		goto out;
	}

	/*
	 * Otherwise the page is already partially free, so find reinsertion
	 * point.
	 */
	sp->units += units;

	if (b < sp->free) {
		set_slob(b, units, sp->free);
		sp->free = b;
	} else {
		prev = sp->free;
		next = slob_next(prev);
		while (b > next) {
			prev = next;
			next = slob_next(prev);
		}

		if (!slob_last(prev) && b + units == next) {
			units += slob_units(next);
			set_slob(b, units, slob_next(next));
		} else
			set_slob(b, units, next);

		if (prev + slob_units(prev) == b) {
			units = slob_units(b) + slob_units(prev);
			set_slob(prev, units, slob_next(b));
		} else
			set_slob(prev, slob_units(prev), b);
	}
out:
	spin_unlock_irqrestore(&slob_lock, flags);
}

/*
 * End of slob allocator proper. Begin kmem_cache_alloc and kmalloc frontend.
 */

#ifndef ARCH_KMALLOC_MINALIGN
#define ARCH_KMALLOC_MINALIGN __alignof__(unsigned long)
#endif

#ifndef ARCH_SLAB_MINALIGN
#define ARCH_SLAB_MINALIGN __alignof__(unsigned long)
#endif

void *__kmalloc_node(size_t size, gfp_t gfp, int node)
{
	unsigned int *m;
	int align = max(ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);

	if (size < PAGE_SIZE - align) {
		if (!size)
			return ZERO_SIZE_PTR;

		m = slob_alloc(size + align, gfp, align, node);
		if (m)
			*m = size;
		return (void *)m + align;
	} else {
		void *ret;

		ret = slob_new_page(gfp | __GFP_COMP, get_order(size), node);
		if (ret) {
			struct page *page;
			page = virt_to_page(ret);
			page->private = size;
		}
		return ret;
	}
}
EXPORT_SYMBOL(__kmalloc_node);

void kfree(const void *block)
{
	struct slob_page *sp;

	if (unlikely(ZERO_OR_NULL_PTR(block)))
		return;

	sp = (struct slob_page *)virt_to_page(block);
	if (slob_page(sp)) {
		int align = max(ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
		unsigned int *m = (unsigned int *)(block - align);
		slob_free(m, *m + align);
	} else
		put_page(&sp->page);
}
EXPORT_SYMBOL(kfree);

/* can't use ksize for kmem_cache_alloc memory, only kmalloc */
size_t ksize(const void *block)
{
	struct slob_page *sp;

	BUG_ON(!block);
	if (unlikely(block == ZERO_SIZE_PTR))
		return 0;

	sp = (struct slob_page *)virt_to_page(block);
	if (slob_page(sp))
		return ((slob_t *)block - 1)->units + SLOB_UNIT;
	else
		return sp->page.private;
}
EXPORT_SYMBOL(ksize);

/*
 * slab缓存结构描述符
 *
 * 1、slob分配器并不像slab分配器那样，为kmem_cache创建对象cpu缓存和结点slab链表
 *   而是将所有的slob缓存统一在一个通用链表中维护；
 * 2、slob分配器并不像slab分配器那样，不同大小的对象在不同的slab缓存中分配
 *   而是在分配对象时，直接从通用链表中首个满足分配的空闲slob缓存分配内存块；
 */
struct kmem_cache {
	unsigned int size, align;
	unsigned long flags;
	const char *name;
	void (*ctor)(struct kmem_cache *, void *);
};

struct kmem_cache *kmem_cache_create(const char *name, size_t size,
	size_t align, unsigned long flags,
	void (*ctor)(struct kmem_cache *, void *))
{
	struct kmem_cache *c;

	c = slob_alloc(sizeof(struct kmem_cache), flags, 0, -1);

	if (c) {
		c->name = name;
		c->size = size;
		if (flags & SLAB_DESTROY_BY_RCU) {
			/* leave room for rcu footer at the end of object */
			c->size += sizeof(struct slob_rcu);
		}
		c->flags = flags;
		c->ctor = ctor;
		/* ignore alignment unless it's forced */
		c->align = (flags & SLAB_HWCACHE_ALIGN) ? SLOB_ALIGN : 0;
		if (c->align < ARCH_SLAB_MINALIGN)
			c->align = ARCH_SLAB_MINALIGN;
		if (c->align < align)
			c->align = align;
	} else if (flags & SLAB_PANIC)
		panic("Cannot create slab cache %s\n", name);

	return c;
}
EXPORT_SYMBOL(kmem_cache_create);

void kmem_cache_destroy(struct kmem_cache *c)
{
	slob_free(c, sizeof(struct kmem_cache));
}
EXPORT_SYMBOL(kmem_cache_destroy);

void *kmem_cache_alloc_node(struct kmem_cache *c, gfp_t flags, int node)
{
	void *b;

	if (c->size < PAGE_SIZE)
		b = slob_alloc(c->size, flags, c->align, node);
	/*
	 * 因单个slob缓存永远占用一个页框大小
	 * 所以若通过slob分配大小大于一页的对象，则直接调用伙伴系统分配连续页
	 */
	else
		b = slob_new_page(flags, get_order(c->size), node);

	if (c->ctor)
		c->ctor(c, b);

	return b;
}
EXPORT_SYMBOL(kmem_cache_alloc_node);

static void __kmem_cache_free(void *b, int size)
{
	if (size < PAGE_SIZE)
		slob_free(b, size);
	else
		free_pages((unsigned long)b, get_order(size));
}

static void kmem_rcu_free(struct rcu_head *head)
{
	struct slob_rcu *slob_rcu = (struct slob_rcu *)head;
	void *b = (void *)slob_rcu - (slob_rcu->size - sizeof(struct slob_rcu));

	__kmem_cache_free(b, slob_rcu->size);
}

void kmem_cache_free(struct kmem_cache *c, void *b)
{
	if (unlikely(c->flags & SLAB_DESTROY_BY_RCU)) {
		struct slob_rcu *slob_rcu;
		slob_rcu = b + (c->size - sizeof(struct slob_rcu));
		INIT_RCU_HEAD(&slob_rcu->head);
		slob_rcu->size = c->size;
		call_rcu(&slob_rcu->head, kmem_rcu_free);
	} else {
		__kmem_cache_free(b, c->size);
	}
}
EXPORT_SYMBOL(kmem_cache_free);

unsigned int kmem_cache_size(struct kmem_cache *c)
{
	return c->size;
}
EXPORT_SYMBOL(kmem_cache_size);

const char *kmem_cache_name(struct kmem_cache *c)
{
	return c->name;
}
EXPORT_SYMBOL(kmem_cache_name);

int kmem_cache_shrink(struct kmem_cache *d)
{
	return 0;
}
EXPORT_SYMBOL(kmem_cache_shrink);

int kmem_ptr_validate(struct kmem_cache *a, const void *b)
{
	return 0;
}

static unsigned int slob_ready __read_mostly;

int slab_is_available(void)
{
	return slob_ready;
}

void __init kmem_cache_init(void)
{
	slob_ready = 1;
}
