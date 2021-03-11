/*
 * SLUB: A slab allocator that limits cache line use instead of queuing
 * objects in per cpu and per node lists.
 *
 * The allocator synchronizes using per slab locks and only
 * uses a centralized lock to manage a pool of partial slabs.
 *
 * (C) 2007 SGI, Christoph Lameter <clameter@sgi.com>
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/bit_spinlock.h>
#include <linux/interrupt.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/mempolicy.h>
#include <linux/ctype.h>
#include <linux/kallsyms.h>
#include <linux/memory.h>

/*
 * Lock order:
 *   1. slab_lock(page)
 *   2. slab->list_lock
 *
 *   The slab_lock protects operations on the object of a particular
 *   slab and its metadata in the page struct. If the slab lock
 *   has been taken then no allocations nor frees can be performed
 *   on the objects in the slab nor can the slab be added or removed
 *   from the partial or full lists since this would mean modifying
 *   the page_struct of the slab.
 *
 *   The list_lock protects the partial and full list on each node and
 *   the partial slab counter. If taken then no new slabs may be added or
 *   removed from the lists nor make the number of partial slabs be modified.
 *   (Note that the total number of slabs is an atomic value that may be
 *   modified without taking the list lock).
 *
 *   The list_lock is a centralized lock and thus we avoid taking it as
 *   much as possible. As long as SLUB does not have to handle partial
 *   slabs, operations can continue without any centralized lock. F.e.
 *   allocating a long series of objects that fill up slabs does not require
 *   the list lock.
 *
 *   The lock order is sometimes inverted when we are trying to get a slab
 *   off a list. We take the list_lock and then look for a page on the list
 *   to use. While we do that objects in the slabs may be freed. We can
 *   only operate on the slab if we have also taken the slab_lock. So we use
 *   a slab_trylock() on the slab. If trylock was successful then no frees
 *   can occur anymore and we can use the slab for allocations etc. If the
 *   slab_trylock() does not succeed then frees are in progress in the slab and
 *   we must stay away from it for a while since we may cause a bouncing
 *   cacheline if we try to acquire the lock. So go onto the next slab.
 *   If all pages are busy then we may allocate a new slab instead of reusing
 *   a partial slab. A new slab has noone operating on it and thus there is
 *   no danger of cacheline contention.
 *
 *   Interrupts are disabled during allocation and deallocation in order to
 *   make the slab allocator safe to use in the context of an irq. In addition
 *   interrupts are disabled to ensure that the processor does not change
 *   while handling per_cpu slabs, due to kernel preemption.
 *
 * SLUB assigns one slab for allocation to each processor.
 * Allocations only occur from these slabs called cpu slabs.
 *
 * Slabs with free elements are kept on a partial list and during regular
 * operations no list for full slabs is used. If an object in a full slab is
 * freed then the slab will show up again on the partial lists.
 * We track full slabs for debugging purposes though because otherwise we
 * cannot scan all objects.
 *
 * Slabs are freed when they become empty. Teardown and setup is
 * minimal so we rely on the page allocators per cpu caches for
 * fast frees and allocs.
 *
 * Overloading of page flags that are otherwise used for LRU management.
 *
 * PageActive 		The slab is frozen and exempt from list processing.
 * 			This means that the slab is dedicated to a purpose
 * 			such as satisfying allocations for a specific
 * 			processor. Objects may be freed in the slab while
 * 			it is frozen but slab_free will then skip the usual
 * 			list operations. It is up to the processor holding
 * 			the slab to integrate the slab into the slab lists
 * 			when the slab is no longer needed.
 *
 * 			One use of this flag is to mark slabs that are
 * 			used for allocations. Then such a slab becomes a cpu
 * 			slab. The cpu slab may be equipped with an additional
 * 			freelist that allows lockless access to
 * 			free objects in addition to the regular freelist
 * 			that requires the slab lock.
 *
 * PageError		Slab requires special handling due to debug
 * 			options set. This moves	slab handling out of
 * 			the fast path and disables lockless freelists.
 */

#define FROZEN (1 << PG_active)

#ifdef CONFIG_SLUB_DEBUG
#define SLABDEBUG (1 << PG_error)
#else
#define SLABDEBUG 0
#endif

static inline int SlabFrozen(struct page *page)
{
	return page->flags & FROZEN;
}

static inline void SetSlabFrozen(struct page *page)
{
	page->flags |= FROZEN;
}

static inline void ClearSlabFrozen(struct page *page)
{
	page->flags &= ~FROZEN;
}

static inline int SlabDebug(struct page *page)
{
	return page->flags & SLABDEBUG;
}

static inline void SetSlabDebug(struct page *page)
{
	page->flags |= SLABDEBUG;
}

static inline void ClearSlabDebug(struct page *page)
{
	page->flags &= ~SLABDEBUG;
}

/*
 * Issues still to be resolved:
 *
 * - Support PAGE_ALLOC_DEBUG. Should be easy to do.
 *
 * - Variable sizing of the per node arrays
 */

/* Enable to test recovery from slab corruption on boot */
#undef SLUB_RESILIENCY_TEST

#if PAGE_SHIFT <= 12

/*
 * Small page size. Make sure that we do not fragment memory
 */
#define DEFAULT_MAX_ORDER 1
#define DEFAULT_MIN_OBJECTS 4

#else

/*
 * Large page machines are customarily able to handle larger
 * page orders.
 */
#define DEFAULT_MAX_ORDER 2
#define DEFAULT_MIN_OBJECTS 8

#endif

/*
 * Mininum number of partial slabs. These will be left on the partial
 * lists even if they are empty. kmem_cache_shrink may reclaim them.
 */
#define MIN_PARTIAL 5

/*
 * Maximum number of desirable partial slabs.
 * The existence of more partial slabs makes kmem_cache_shrink
 * sort the partial list by the number of objects in the.
 */
#define MAX_PARTIAL 10

#define DEBUG_DEFAULT_FLAGS (SLAB_DEBUG_FREE | SLAB_RED_ZONE | \
				SLAB_POISON | SLAB_STORE_USER)

/*
 * Set of flags that will prevent slab merging
 */
#define SLUB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
		SLAB_TRACE | SLAB_DESTROY_BY_RCU)

#define SLUB_MERGE_SAME (SLAB_DEBUG_FREE | SLAB_RECLAIM_ACCOUNT | \
		SLAB_CACHE_DMA)

#ifndef ARCH_KMALLOC_MINALIGN
#define ARCH_KMALLOC_MINALIGN __alignof__(unsigned long long)
#endif

#ifndef ARCH_SLAB_MINALIGN
#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
#endif

/* Internal SLUB flags */
#define __OBJECT_POISON		0x80000000 /* Poison object */
#define __SYSFS_ADD_DEFERRED	0x40000000 /* Not yet visible via sysfs */

/* Not all arches define cache_line_size */
#ifndef cache_line_size
#define cache_line_size()	L1_CACHE_BYTES
#endif

static int kmem_size = sizeof(struct kmem_cache);

#ifdef CONFIG_SMP
static struct notifier_block slab_notifier;
#endif

/*
 * 全局变量slab_state用于记录slub分配器的状态
 */
static enum {
	/* 还没有开始建立slub分配器 */
	DOWN,		/* No slab functionality available */
	/* kmem_cache_node缓存已创建，但通用缓存未创建 */
	PARTIAL,	/* kmem_cache_open() works but kmalloc does not */
	/* slub通用缓存已创建 */
	UP,		/* Everything works but does not show up in sysfs */
	/* slub “/sys/kernel/slab/”节点已经创建 */
	SYSFS		/* Sysfs up */
} slab_state = DOWN;

/* A list of all slab caches on the system */
static DECLARE_RWSEM(slub_lock);
/*
 * SLUB分配器中高速缓存链表
 */
static LIST_HEAD(slab_caches);

/*
 * Tracking user of a slab.
 */
struct track {
	void *addr;		/* Called from address */
	int cpu;		/* Was running on cpu */
	int pid;		/* Pid context */
	unsigned long when;	/* When did the operation occur */
};

enum track_item { TRACK_ALLOC, TRACK_FREE };

#if defined(CONFIG_SYSFS) && defined(CONFIG_SLUB_DEBUG)
static int sysfs_slab_add(struct kmem_cache *);
static int sysfs_slab_alias(struct kmem_cache *, const char *);
static void sysfs_slab_remove(struct kmem_cache *);
#else
static inline int sysfs_slab_add(struct kmem_cache *s) { return 0; }
static inline int sysfs_slab_alias(struct kmem_cache *s, const char *p)
							{ return 0; }
static inline void sysfs_slab_remove(struct kmem_cache *s) {}
#endif

/********************************************************************
 * 			Core slab cache functions
 *******************************************************************/
/* slub分配器是否可用，slab_state状态为UP表示kmem_cache_node和kmalloc通用缓存均创建ok */
int slab_is_available(void)
{
	return slab_state >= UP;
}

/* 获取对应结点的kmem_cache_node，一致性内存访问只有一个，非一致性内存访问则根据node返回 */
static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
{
#ifdef CONFIG_NUMA
	return s->node[node];
#else
	return &s->local_node;
#endif
}

/* 获取对应CPU的kmem_cache_cpu高速缓存，非对称多处理系统只有一个，对称多处理系统则根据cpu返回 */
static inline struct kmem_cache_cpu *get_cpu_slab(struct kmem_cache *s, int cpu)
{
#ifdef CONFIG_SMP
	return s->cpu_slab[cpu];
#else
	return &s->cpu_slab;
#endif
}

static inline int check_valid_pointer(struct kmem_cache *s,
				struct page *page, const void *object)
{
	void *base;

	if (!object)
		return 1;

	base = page_address(page);
	if (object < base || object >= base + s->objects * s->size ||
		(object - base) % s->size) {
		return 0;
	}

	return 1;
}

/*
 * Slow version of get and set free pointer.
 *
 * This version requires touching the cache lines of kmem_cache which
 * we avoid to do in the fast alloc free paths. There we obtain the offset
 * from the page struct.
 */
/* 获取缓存对象object内的、指向下一空闲对象的指针 */
static inline void *get_freepointer(struct kmem_cache *s, void *object)
{
	/*
	 * kmem_cache.offset存在两种值，一种为0，一种为kmem_cache.objsize + word_align
	 * 前者表示freepointer存放在object首地址位置，在ctor/poison未指定时
	 * 后者表示freepointer存放在object有效数据尾部，在ctor/poison指定时
	 */
	return *(void **)(object + s->offset);
}

static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
{
	*(void **)(object + s->offset) = fp;
}

/* Loop over all objects in a slab */
/* 遍历一个slab中的所有对象，objects表示一个slab中对象个数，size表示一个对象占用的字节空间 */
#define for_each_object(__p, __s, __addr) \
	for (__p = (__addr); __p < (__addr) + (__s)->objects * (__s)->size;\
			__p += (__s)->size)

/* Scan freelist */
/* 遍历一个slab的所有空闲对象 */
#define for_each_free_object(__p, __s, __free) \
	for (__p = (__free); __p; __p = get_freepointer((__s), __p))

/* Determine object index from a given position */
static inline int slab_index(void *p, struct kmem_cache *s, void *addr)
{
	return (p - addr) / s->size;
}

#ifdef CONFIG_SLUB_DEBUG
/*
 * Debug settings:
 */
#ifdef CONFIG_SLUB_DEBUG_ON
static int slub_debug = DEBUG_DEFAULT_FLAGS;
#else
static int slub_debug;
#endif

static char *slub_debug_slabs;

/*
 * Object debugging
 */
static void print_section(char *text, u8 *addr, unsigned int length)
{
	int i, offset;
	int newline = 1;
	char ascii[17];

	ascii[16] = 0;

	for (i = 0; i < length; i++) {
		if (newline) {
			printk(KERN_ERR "%8s 0x%p: ", text, addr + i);
			newline = 0;
		}
		printk(" %02x", addr[i]);
		offset = i % 16;
		ascii[offset] = isgraph(addr[i]) ? addr[i] : '.';
		if (offset == 15) {
			printk(" %s\n",ascii);
			newline = 1;
		}
	}
	if (!newline) {
		i %= 16;
		while (i < 16) {
			printk("   ");
			ascii[i] = ' ';
			i++;
		}
		printk(" %s\n", ascii);
	}
}

static struct track *get_track(struct kmem_cache *s, void *object,
	enum track_item alloc)
{
	struct track *p;

	if (s->offset)
		p = object + s->offset + sizeof(void *);
	else
		p = object + s->inuse;

	return p + alloc;
}

static void set_track(struct kmem_cache *s, void *object,
				enum track_item alloc, void *addr)
{
	struct track *p;

	if (s->offset)
		p = object + s->offset + sizeof(void *);
	else
		p = object + s->inuse;

	p += alloc;
	if (addr) {
		p->addr = addr;
		p->cpu = smp_processor_id();
		p->pid = current ? current->pid : -1;
		p->when = jiffies;
	} else
		memset(p, 0, sizeof(struct track));
}

static void init_tracking(struct kmem_cache *s, void *object)
{
	if (!(s->flags & SLAB_STORE_USER))
		return;

	set_track(s, object, TRACK_FREE, NULL);
	set_track(s, object, TRACK_ALLOC, NULL);
}

static void print_track(const char *s, struct track *t)
{
	if (!t->addr)
		return;

	printk(KERN_ERR "INFO: %s in ", s);
	__print_symbol("%s", (unsigned long)t->addr);
	printk(" age=%lu cpu=%u pid=%d\n", jiffies - t->when, t->cpu, t->pid);
}

static void print_tracking(struct kmem_cache *s, void *object)
{
	if (!(s->flags & SLAB_STORE_USER))
		return;

	print_track("Allocated", get_track(s, object, TRACK_ALLOC));
	print_track("Freed", get_track(s, object, TRACK_FREE));
}

static void print_page_info(struct page *page)
{
	printk(KERN_ERR "INFO: Slab 0x%p used=%u fp=0x%p flags=0x%04lx\n",
		page, page->inuse, page->freelist, page->flags);

}

static void slab_bug(struct kmem_cache *s, char *fmt, ...)
{
	va_list args;
	char buf[100];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	printk(KERN_ERR "========================================"
			"=====================================\n");
	printk(KERN_ERR "BUG %s: %s\n", s->name, buf);
	printk(KERN_ERR "----------------------------------------"
			"-------------------------------------\n\n");
}

static void slab_fix(struct kmem_cache *s, char *fmt, ...)
{
	va_list args;
	char buf[100];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	printk(KERN_ERR "FIX %s: %s\n", s->name, buf);
}

static void print_trailer(struct kmem_cache *s, struct page *page, u8 *p)
{
	unsigned int off;	/* Offset of last byte */
	u8 *addr = page_address(page);

	print_tracking(s, p);

	print_page_info(page);

	printk(KERN_ERR "INFO: Object 0x%p @offset=%tu fp=0x%p\n\n",
			p, p - addr, get_freepointer(s, p));

	if (p > addr + 16)
		print_section("Bytes b4", p - 16, 16);

	print_section("Object", p, min(s->objsize, 128));

	if (s->flags & SLAB_RED_ZONE)
		print_section("Redzone", p + s->objsize,
			s->inuse - s->objsize);

	if (s->offset)
		off = s->offset + sizeof(void *);
	else
		off = s->inuse;

	if (s->flags & SLAB_STORE_USER)
		off += 2 * sizeof(struct track);

	if (off != s->size)
		/* Beginning of the filler is the free pointer */
		print_section("Padding", p + off, s->size - off);

	dump_stack();
}

static void object_err(struct kmem_cache *s, struct page *page,
			u8 *object, char *reason)
{
	slab_bug(s, reason);
	print_trailer(s, page, object);
}

static void slab_err(struct kmem_cache *s, struct page *page, char *fmt, ...)
{
	va_list args;
	char buf[100];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	slab_bug(s, fmt);
	print_page_info(page);
	dump_stack();
}

/*
 * slub对象布局如下：
 * 1、第一种布局：poison未开启，且ctor也未指定
 *   kmem_cache.offset为0、free pointer存放在objsize首地址处；
 *   word align存放red zone、inuse为alloc tracker的偏移位置
 * |      inuse                    |
 * ------------------------------------------------------------------------
 * | free pointer|    | word align |alloc tracker| free tracker  |obj align|
 * |       objsize    | (red zone) |             |               |         |
 * -------------------------------------------------------------------------
 *
 * 2、第二种布局：POISON开启/ctor指定
 *   kmem_cache.offset为objsize + word align、free pointer存放在offset偏移位置；
 *   word align存放red zone、inuse为free pointer的偏移位置
 * |      offset          |
 * |      inuse           |
 * --------------------------------------------------------------------------------
 * | objsize | word align | free pointer | alloc tracker| free tracker  |obj align|
 * |         | (red zone) |              |              |               |         |
 * --------------------------------------------------------------------------------
 */
static void init_object(struct kmem_cache *s, void *object, int active)
{
	u8 *p = object;

	if (s->flags & __OBJECT_POISON) {
		memset(p, POISON_FREE, s->objsize - 1);
		p[s->objsize -1] = POISON_END;
	}

	if (s->flags & SLAB_RED_ZONE)
		memset(p + s->objsize,
			active ? SLUB_RED_ACTIVE : SLUB_RED_INACTIVE,
			s->inuse - s->objsize);
}

static u8 *check_bytes(u8 *start, unsigned int value, unsigned int bytes)
{
	while (bytes) {
		if (*start != (u8)value)
			return start;
		start++;
		bytes--;
	}
	return NULL;
}

static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
						void *from, void *to)
{
	slab_fix(s, "Restoring 0x%p-0x%p=0x%x\n", from, to - 1, data);
	memset(from, data, to - from);
}

static int check_bytes_and_report(struct kmem_cache *s, struct page *page,
			u8 *object, char *what,
			u8* start, unsigned int value, unsigned int bytes)
{
	u8 *fault;
	u8 *end;

	fault = check_bytes(start, value, bytes);
	if (!fault)
		return 1;

	end = start + bytes;
	while (end > fault && end[-1] == value)
		end--;

	slab_bug(s, "%s overwritten", what);
	printk(KERN_ERR "INFO: 0x%p-0x%p. First byte 0x%x instead of 0x%x\n",
					fault, end - 1, fault[0], value);
	print_trailer(s, page, object);

	restore_bytes(s, what, value, fault, end);
	return 0;
}

/*
 * Object layout:
 *
 * object address
 * 	Bytes of the object to be managed.
 * 	If the freepointer may overlay the object then the free
 * 	pointer is the first word of the object.
 *
 * 	Poisoning uses 0x6b (POISON_FREE) and the last byte is
 * 	0xa5 (POISON_END)
 *
 * object + s->objsize
 * 	Padding to reach word boundary. This is also used for Redzoning.
 * 	Padding is extended by another word if Redzoning is enabled and
 * 	objsize == inuse.
 *
 * 	We fill with 0xbb (RED_INACTIVE) for inactive objects and with
 * 	0xcc (RED_ACTIVE) for objects in use.
 *
 * object + s->inuse
 * 	Meta data starts here.
 *
 * 	A. Free pointer (if we cannot overwrite object on free)
 * 	B. Tracking data for SLAB_STORE_USER
 * 	C. Padding to reach required alignment boundary or at mininum
 * 		one word if debuggin is on to be able to detect writes
 * 		before the word boundary.
 *
 *	Padding is done using 0x5a (POISON_INUSE)
 *
 * object + s->size
 * 	Nothing is used beyond s->size.
 *
 * If slabcaches are merged then the objsize and inuse boundaries are mostly
 * ignored. And therefore no slab options that rely on these boundaries
 * may be used with merged slabcaches.
 */

static int check_pad_bytes(struct kmem_cache *s, struct page *page, u8 *p)
{
	unsigned long off = s->inuse;	/* The end of info */

	if (s->offset)
		/* Freepointer is placed after the object. */
		off += sizeof(void *);

	if (s->flags & SLAB_STORE_USER)
		/* We also have user information there */
		off += 2 * sizeof(struct track);

	if (s->size == off)
		return 1;

	return check_bytes_and_report(s, page, p, "Object padding",
				p + off, POISON_INUSE, s->size - off);
}

static int slab_pad_check(struct kmem_cache *s, struct page *page)
{
	u8 *start;
	u8 *fault;
	u8 *end;
	int length;
	int remainder;

	if (!(s->flags & SLAB_POISON))
		return 1;

	start = page_address(page);
	end = start + (PAGE_SIZE << s->order);
	length = s->objects * s->size;
	remainder = end - (start + length);
	if (!remainder)
		return 1;

	fault = check_bytes(start + length, POISON_INUSE, remainder);
	if (!fault)
		return 1;
	while (end > fault && end[-1] == POISON_INUSE)
		end--;

	slab_err(s, page, "Padding overwritten. 0x%p-0x%p", fault, end - 1);
	print_section("Padding", start, length);

	restore_bytes(s, "slab padding", POISON_INUSE, start, end);
	return 0;
}

static int check_object(struct kmem_cache *s, struct page *page,
					void *object, int active)
{
	u8 *p = object;
	u8 *endobject = object + s->objsize;

	if (s->flags & SLAB_RED_ZONE) {
		unsigned int red =
			active ? SLUB_RED_ACTIVE : SLUB_RED_INACTIVE;

		if (!check_bytes_and_report(s, page, object, "Redzone",
			endobject, red, s->inuse - s->objsize))
			return 0;
	} else {
		if ((s->flags & SLAB_POISON) && s->objsize < s->inuse)
			check_bytes_and_report(s, page, p, "Alignment padding", endobject,
				POISON_INUSE, s->inuse - s->objsize);
	}

	if (s->flags & SLAB_POISON) {
		if (!active && (s->flags & __OBJECT_POISON) &&
			(!check_bytes_and_report(s, page, p, "Poison", p,
					POISON_FREE, s->objsize - 1) ||
			 !check_bytes_and_report(s, page, p, "Poison",
			 	p + s->objsize -1, POISON_END, 1)))
			return 0;
		/*
		 * check_pad_bytes cleans up on its own.
		 */
		check_pad_bytes(s, page, p);
	}

	if (!s->offset && active)
		/*
		 * Object and freepointer overlap. Cannot check
		 * freepointer while object is allocated.
		 */
		return 1;

	/* Check free pointer validity */
	if (!check_valid_pointer(s, page, get_freepointer(s, p))) {
		object_err(s, page, p, "Freepointer corrupt");
		/*
		 * No choice but to zap it and thus loose the remainder
		 * of the free objects in this slab. May cause
		 * another error because the object count is now wrong.
		 */
		set_freepointer(s, p, NULL);
		return 0;
	}
	return 1;
}

static int check_slab(struct kmem_cache *s, struct page *page)
{
	VM_BUG_ON(!irqs_disabled());

	if (!PageSlab(page)) {
		slab_err(s, page, "Not a valid slab page");
		return 0;
	}
	if (page->inuse > s->objects) {
		slab_err(s, page, "inuse %u > max %u",
			s->name, page->inuse, s->objects);
		return 0;
	}
	/* Slab_pad_check fixes things up after itself */
	slab_pad_check(s, page);
	return 1;
}

/*
 * Determine if a certain object on a page is on the freelist. Must hold the
 * slab lock to guarantee that the chains are in a consistent state.
 */
static int on_freelist(struct kmem_cache *s, struct page *page, void *search)
{
	int nr = 0;
	void *fp = page->freelist;
	void *object = NULL;

	while (fp && nr <= s->objects) {
		if (fp == search)
			return 1;
		if (!check_valid_pointer(s, page, fp)) {
			if (object) {
				object_err(s, page, object,
					"Freechain corrupt");
				set_freepointer(s, object, NULL);
				break;
			} else {
				slab_err(s, page, "Freepointer corrupt");
				page->freelist = NULL;
				page->inuse = s->objects;
				slab_fix(s, "Freelist cleared");
				return 0;
			}
			break;
		}
		object = fp;
		fp = get_freepointer(s, object);
		nr++;
	}

	if (page->inuse != s->objects - nr) {
		slab_err(s, page, "Wrong object count. Counter is %d but "
			"counted were %d", page->inuse, s->objects - nr);
		page->inuse = s->objects - nr;
		slab_fix(s, "Object count adjusted.");
	}
	return search == NULL;
}

static void trace(struct kmem_cache *s, struct page *page, void *object, int alloc)
{
	if (s->flags & SLAB_TRACE) {
		printk(KERN_INFO "TRACE %s %s 0x%p inuse=%d fp=0x%p\n",
			s->name,
			alloc ? "alloc" : "free",
			object, page->inuse,
			page->freelist);

		if (!alloc)
			print_section("Object", (void *)object, s->objsize);

		dump_stack();
	}
}

/*
 * Tracking of fully allocated slabs for debugging purposes.
 */
static void add_full(struct kmem_cache_node *n, struct page *page)
{
	spin_lock(&n->list_lock);
	list_add(&page->lru, &n->full);
	spin_unlock(&n->list_lock);
}

static void remove_full(struct kmem_cache *s, struct page *page)
{
	struct kmem_cache_node *n;

	if (!(s->flags & SLAB_STORE_USER))
		return;

	n = get_node(s, page_to_nid(page));

	spin_lock(&n->list_lock);
	list_del(&page->lru);
	spin_unlock(&n->list_lock);
}

static void setup_object_debug(struct kmem_cache *s, struct page *page,
								void *object)
{
	if (!(s->flags & (SLAB_STORE_USER|SLAB_RED_ZONE|__OBJECT_POISON)))
		return;

	init_object(s, object, 0);
	init_tracking(s, object);
}

static int alloc_debug_processing(struct kmem_cache *s, struct page *page,
						void *object, void *addr)
{
	if (!check_slab(s, page))
		goto bad;

	if (object && !on_freelist(s, page, object)) {
		object_err(s, page, object, "Object already allocated");
		goto bad;
	}

	if (!check_valid_pointer(s, page, object)) {
		object_err(s, page, object, "Freelist Pointer check fails");
		goto bad;
	}

	if (object && !check_object(s, page, object, 0))
		goto bad;

	/* Success perform special debug activities for allocs */
	if (s->flags & SLAB_STORE_USER)
		set_track(s, object, TRACK_ALLOC, addr);
	trace(s, page, object, 1);
	init_object(s, object, 1);
	return 1;

bad:
	if (PageSlab(page)) {
		/*
		 * If this is a slab page then lets do the best we can
		 * to avoid issues in the future. Marking all objects
		 * as used avoids touching the remaining objects.
		 */
		slab_fix(s, "Marking all objects used");
		page->inuse = s->objects;
		page->freelist = NULL;
	}
	return 0;
}

static int free_debug_processing(struct kmem_cache *s, struct page *page,
						void *object, void *addr)
{
	if (!check_slab(s, page))
		goto fail;

	if (!check_valid_pointer(s, page, object)) {
		slab_err(s, page, "Invalid object pointer 0x%p", object);
		goto fail;
	}

	if (on_freelist(s, page, object)) {
		object_err(s, page, object, "Object already free");
		goto fail;
	}

	if (!check_object(s, page, object, 1))
		return 0;

	if (unlikely(s != page->slab)) {
		if (!PageSlab(page))
			slab_err(s, page, "Attempt to free object(0x%p) "
				"outside of slab", object);
		else
		if (!page->slab) {
			printk(KERN_ERR
				"SLUB <none>: no slab for object 0x%p.\n",
						object);
			dump_stack();
		}
		else
			object_err(s, page, object,
					"page slab pointer corrupt.");
		goto fail;
	}

	/* Special debug activities for freeing objects */
	if (!SlabFrozen(page) && !page->freelist)
		remove_full(s, page);
	if (s->flags & SLAB_STORE_USER)
		set_track(s, object, TRACK_FREE, addr);
	trace(s, page, object, 0);
	init_object(s, object, 0);
	return 1;

fail:
	slab_fix(s, "Object at 0x%p not freed", object);
	return 0;
}

static int __init setup_slub_debug(char *str)
{
	slub_debug = DEBUG_DEFAULT_FLAGS;
	if (*str++ != '=' || !*str)
		/*
		 * No options specified. Switch on full debugging.
		 */
		goto out;

	if (*str == ',')
		/*
		 * No options but restriction on slabs. This means full
		 * debugging for slabs matching a pattern.
		 */
		goto check_slabs;

	slub_debug = 0;
	if (*str == '-')
		/*
		 * Switch off all debugging measures.
		 */
		goto out;

	/*
	 * Determine which debug features should be switched on
	 */
	for ( ;*str && *str != ','; str++) {
		switch (tolower(*str)) {
		case 'f':
			slub_debug |= SLAB_DEBUG_FREE;
			break;
		case 'z':
			slub_debug |= SLAB_RED_ZONE;
			break;
		case 'p':
			slub_debug |= SLAB_POISON;
			break;
		case 'u':
			slub_debug |= SLAB_STORE_USER;
			break;
		case 't':
			slub_debug |= SLAB_TRACE;
			break;
		default:
			printk(KERN_ERR "slub_debug option '%c' "
				"unknown. skipped\n",*str);
		}
	}

check_slabs:
	if (*str == ',')
		slub_debug_slabs = str + 1;
out:
	return 1;
}

__setup("slub_debug", setup_slub_debug);

static unsigned long kmem_cache_flags(unsigned long objsize,
	unsigned long flags, const char *name,
	void (*ctor)(struct kmem_cache *, void *))
{
	/*
	 * The page->offset field is only 16 bit wide. This is an offset
	 * in units of words from the beginning of an object. If the slab
	 * size is bigger then we cannot move the free pointer behind the
	 * object anymore.
	 *
	 * On 32 bit platforms the limit is 256k. On 64bit platforms
	 * the limit is 512k.
	 *
	 * Debugging or ctor may create a need to move the free
	 * pointer. Fail if this happens.
	 */
	if (objsize >= 65535 * sizeof(void *)) {
		BUG_ON(flags & (SLAB_RED_ZONE | SLAB_POISON |
				SLAB_STORE_USER | SLAB_DESTROY_BY_RCU));
		BUG_ON(ctor);
	} else {
		/*
		 * Enable debugging if selected on the kernel commandline.
		 */
		if (slub_debug && (!slub_debug_slabs ||
		    strncmp(slub_debug_slabs, name,
		    	strlen(slub_debug_slabs)) == 0))
				flags |= slub_debug;
	}

	return flags;
}
#else
static inline void setup_object_debug(struct kmem_cache *s,
			struct page *page, void *object) {}

static inline int alloc_debug_processing(struct kmem_cache *s,
	struct page *page, void *object, void *addr) { return 0; }

static inline int free_debug_processing(struct kmem_cache *s,
	struct page *page, void *object, void *addr) { return 0; }

static inline int slab_pad_check(struct kmem_cache *s, struct page *page)
			{ return 1; }
static inline int check_object(struct kmem_cache *s, struct page *page,
			void *object, int active) { return 1; }
static inline void add_full(struct kmem_cache_node *n, struct page *page) {}
static inline unsigned long kmem_cache_flags(unsigned long objsize,
	unsigned long flags, const char *name,
	void (*ctor)(struct kmem_cache *, void *))
{
	return flags;
}
#define slub_debug 0
#endif
/*
 * Slab allocation and freeing
 */
static struct page *allocate_slab(struct kmem_cache *s, gfp_t flags, int node)
{
	struct page * page;
	int pages = 1 << s->order;

	if (s->order)
		flags |= __GFP_COMP;

	if (s->flags & SLAB_CACHE_DMA)
		flags |= SLUB_DMA;

	if (s->flags & SLAB_RECLAIM_ACCOUNT)
		flags |= __GFP_RECLAIMABLE;

	if (node == -1)
		page = alloc_pages(flags, s->order);
	else
		page = alloc_pages_node(node, flags, s->order);

	if (!page)
		return NULL;

	mod_zone_page_state(page_zone(page),
		(s->flags & SLAB_RECLAIM_ACCOUNT) ?
		NR_SLAB_RECLAIMABLE : NR_SLAB_UNRECLAIMABLE,
		pages);

	return page;
}

static void setup_object(struct kmem_cache *s, struct page *page,
				void *object)
{
	setup_object_debug(s, page, object);
	if (unlikely(s->ctor))
		s->ctor(s, object);
}

/* 分配slab */
static struct page *new_slab(struct kmem_cache *s, gfp_t flags, int node)
{
	struct page *page;
	struct kmem_cache_node *n;
	void *start;
	void *last;
	void *p;

	BUG_ON(flags & GFP_SLAB_BUG_MASK);

	page = allocate_slab(s,
		flags & (GFP_RECLAIM_MASK | GFP_CONSTRAINT_MASK), node);
	if (!page)
		goto out;

	n = get_node(s, page_to_nid(page));
	if (n)
		/* 递增对应内存结点已分配/未回收的slab缓存数量 */
		atomic_long_inc(&n->nr_slabs);
	/*
	 * page->slab记录slab所属kmem_cache缓存对象
	 * full slab通常不像partial slab一样采用双链表维护(除非DEBUG开启)，当full slab内对象回收转为
	 * partial slab后需重新链接到kmem_cache的partial链表中，此时就可以根据page->slab字段获取所属
	 * kmem_chache缓存对象
	 */
	page->slab = s;
	page->flags |= 1 << PG_slab;
	if (s->flags & (SLAB_DEBUG_FREE | SLAB_RED_ZONE | SLAB_POISON |
			SLAB_STORE_USER | SLAB_TRACE))
		SetSlabDebug(page);

	start = page_address(page);

	if (unlikely(s->flags & SLAB_POISON))
		memset(start, POISON_INUSE, PAGE_SIZE << s->order);

	last = start;
	for_each_object(p, s, start) {
		setup_object(s, page, last);
		set_freepointer(s, last, p);
		last = p;
	}
	setup_object(s, page, last);
	set_freepointer(s, last, NULL);

	page->freelist = start;
	/*
	 * inuse代表被占用对象个数，可被分配或在本次CPU高速缓存中
	 * inuse为0代表slab内对象全部空闲，即slab可被回收
	 */
	page->inuse = 0;
out:
	return page;
}

/* 回收slab。当slab中对象全部空闲、即inuse为0时，slab可回收 */
static void __free_slab(struct kmem_cache *s, struct page *page)
{
	int pages = 1 << s->order;

	if (unlikely(SlabDebug(page))) {
		void *p;

		slab_pad_check(s, page);
		for_each_object(p, s, page_address(page))
			check_object(s, page, p, 0);
		ClearSlabDebug(page);
	}

	mod_zone_page_state(page_zone(page),
		(s->flags & SLAB_RECLAIM_ACCOUNT) ?
		NR_SLAB_RECLAIMABLE : NR_SLAB_UNRECLAIMABLE,
		- pages);

	__free_pages(page, s->order);
}

static void rcu_free_slab(struct rcu_head *h)
{
	struct page *page;

	page = container_of((struct list_head *)h, struct page, lru);
	__free_slab(page->slab, page);
}

static void free_slab(struct kmem_cache *s, struct page *page)
{
	if (unlikely(s->flags & SLAB_DESTROY_BY_RCU)) {
		/*
		 * RCU free overloads the RCU head over the LRU
		 */
		struct rcu_head *head = (void *)&page->lru;

		call_rcu(head, rcu_free_slab);
	} else
		__free_slab(s, page);
}

/* 将slab从缓存中移除回收 */
static void discard_slab(struct kmem_cache *s, struct page *page)
{
	struct kmem_cache_node *n = get_node(s, page_to_nid(page));

	atomic_long_dec(&n->nr_slabs);
	reset_page_mapcount(page);
	__ClearPageSlab(page);
	free_slab(s, page);
}

/*
 * Per slab locking using the pagelock
 */
static __always_inline void slab_lock(struct page *page)
{
	bit_spin_lock(PG_locked, &page->flags);
}

static __always_inline void slab_unlock(struct page *page)
{
	bit_spin_unlock(PG_locked, &page->flags);
}

static __always_inline int slab_trylock(struct page *page)
{
	int rc = 1;

	rc = bit_spin_trylock(PG_locked, &page->flags);
	return rc;
}

/*
 * Management of partially allocated slabs
 */
static void add_partial_tail(struct kmem_cache_node *n, struct page *page)
{
	spin_lock(&n->list_lock);
	n->nr_partial++;
	list_add_tail(&page->lru, &n->partial);
	spin_unlock(&n->list_lock);
}

static void add_partial(struct kmem_cache_node *n, struct page *page)
{
	spin_lock(&n->list_lock);
	n->nr_partial++;
	list_add(&page->lru, &n->partial);
	spin_unlock(&n->list_lock);
}

static void remove_partial(struct kmem_cache *s,
						struct page *page)
{
	struct kmem_cache_node *n = get_node(s, page_to_nid(page));

	spin_lock(&n->list_lock);
	list_del(&page->lru);
	n->nr_partial--;
	spin_unlock(&n->list_lock);
}

/*
 * Lock slab and remove from the partial list.
 *
 * Must hold list_lock.
 */
static inline int lock_and_freeze_slab(struct kmem_cache_node *n, struct page *page)
{
	if (slab_trylock(page)) {
		list_del(&page->lru);
		n->nr_partial--;
		SetSlabFrozen(page);
		return 1;
	}
	return 0;
}

/*
 * Try to allocate a partial slab from a specific node.
 */
static struct page *get_partial_node(struct kmem_cache_node *n)
{
	struct page *page;

	/*
	 * Racy check. If we mistakenly see no partial slabs then we
	 * just allocate an empty slab. If we mistakenly try to get a
	 * partial slab and there is none available then get_partials()
	 * will return NULL.
	 */
	if (!n || !n->nr_partial)
		return NULL;

	spin_lock(&n->list_lock);
	list_for_each_entry(page, &n->partial, lru)
		if (lock_and_freeze_slab(n, page))
			goto out;
	page = NULL;
out:
	spin_unlock(&n->list_lock);
	return page;
}

/*
 * Get a page from somewhere. Search in increasing NUMA distances.
 */
static struct page *get_any_partial(struct kmem_cache *s, gfp_t flags)
{
#ifdef CONFIG_NUMA
	struct zonelist *zonelist;
	struct zone **z;
	struct page *page;

	/*
	 * The defrag ratio allows a configuration of the tradeoffs between
	 * inter node defragmentation and node local allocations. A lower
	 * defrag_ratio increases the tendency to do local allocations
	 * instead of attempting to obtain partial slabs from other nodes.
	 *
	 * If the defrag_ratio is set to 0 then kmalloc() always
	 * returns node local objects. If the ratio is higher then kmalloc()
	 * may return off node objects because partial slabs are obtained
	 * from other nodes and filled up.
	 *
	 * If /sys/slab/xx/defrag_ratio is set to 100 (which makes
	 * defrag_ratio = 1000) then every (well almost) allocation will
	 * first attempt to defrag slab caches on other nodes. This means
	 * scanning over all nodes to look for partial slabs which may be
	 * expensive if we do it every time we are trying to find a slab
	 * with available objects.
	 */
	if (!s->defrag_ratio || get_cycles() % 1024 > s->defrag_ratio)
		return NULL;

	zonelist = &NODE_DATA(slab_node(current->mempolicy))
					->node_zonelists[gfp_zone(flags)];
	for (z = zonelist->zones; *z; z++) {
		struct kmem_cache_node *n;

		n = get_node(s, zone_to_nid(*z));

		if (n && cpuset_zone_allowed_hardwall(*z, flags) &&
				n->nr_partial > MIN_PARTIAL) {
			page = get_partial_node(n);
			if (page)
				return page;
		}
	}
#endif
	return NULL;
}

/*
 * Get a partial page, lock it and return it.
 */
static struct page *get_partial(struct kmem_cache *s, gfp_t flags, int node)
{
	struct page *page;
	int searchnode = (node == -1) ? numa_node_id() : node;

	page = get_partial_node(get_node(s, searchnode));
	if (page || (flags & __GFP_THISNODE))
		return page;

	return get_any_partial(s, flags);
}

/*
 * Move a page back to the lists.
 *
 * Must be called with the slab lock held.
 *
 * On exit the slab lock will have been dropped.
 */
static void unfreeze_slab(struct kmem_cache *s, struct page *page)
{
	struct kmem_cache_node *n = get_node(s, page_to_nid(page));

	/* 清楚slab的frozen标志，表示不被本地CPU高速缓存占有 */
	ClearSlabFrozen(page);
	/* inuse不为0，表示slab中部分对象处在被分配状态 */
	if (page->inuse) {
		/* freelist不为NULL，则表示slab存在空闲对象，将slab插入partial链表 */
		if (page->freelist)
			add_partial(n, page);
		/* freelist为NULL，则表示slab不存在空闲对象；当DEBUG开启时，将slab插入full链表，否则不链接管理 */
		else if (SlabDebug(page) && (s->flags & SLAB_STORE_USER))
			add_full(n, page);
		/* 解锁slab，与frozen标志同步更新 */
		slab_unlock(page);
	/* inuse为0，表示slab中全部对象均空闲，则可回收 */
	} else {
		if (n->nr_partial < MIN_PARTIAL) {
			/*
			 * Adding an empty slab to the partial slabs in order
			 * to avoid page allocator overhead. This slab needs
			 * to come after the other slabs with objects in
			 * order to fill them up. That way the size of the
			 * partial list stays small. kmem_cache_shrink can
			 * reclaim empty slabs from the partial list.
			 */
			add_partial_tail(n, page);
			slab_unlock(page);
		} else {
			slab_unlock(page);
			discard_slab(s, page);
		}
	}
}

/*
 * Remove the cpu slab
 */
/* 将本地CPU的slab迁移到对应结点的partial slab链表 */
static void deactivate_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
{
	struct page *page = c->page;
	/*
	 * Merge cpu freelist into freelist. Typically we get here
	 * because both freelists are empty. So this is unlikely
	 * to occur.
	 */
	/* 遍历c->freelist，将空闲对象迁移到page->freelist，并更新inuse值 */
	while (unlikely(c->freelist)) {
		void **object;

		/* Retrieve object from cpu_freelist */
		object = c->freelist;
		c->freelist = c->freelist[c->offset];

		/* And put onto the regular freelist */
		object[c->offset] = page->freelist;
		page->freelist = object;
		page->inuse--;
	}
	c->page = NULL;
	/* 根据page->inuse决定将slab移到对应结点的partial slab链表还是直接回收 */
	unfreeze_slab(s, page);
}

static inline void flush_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
{
	slab_lock(c->page);
	deactivate_slab(s, c);
}

/*
 * Flush cpu slab.
 * Called from IPI handler with interrupts disabled.
 */
static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu)
{
	struct kmem_cache_cpu *c = get_cpu_slab(s, cpu);

	if (likely(c && c->page))
		flush_slab(s, c);
}

static void flush_cpu_slab(void *d)
{
	struct kmem_cache *s = d;

	__flush_cpu_slab(s, smp_processor_id());
}

static void flush_all(struct kmem_cache *s)
{
#ifdef CONFIG_SMP
	on_each_cpu(flush_cpu_slab, s, 1, 1);
#else
	unsigned long flags;

	local_irq_save(flags);
	flush_cpu_slab(s);
	local_irq_restore(flags);
#endif
}

/*
 * Check if the objects in a per cpu structure fit numa
 * locality expectations.
 */
static inline int node_match(struct kmem_cache_cpu *c, int node)
{
#ifdef CONFIG_NUMA
	if (node != -1 && c->node != node)
		return 0;
#endif
	return 1;
}

/*
 * Slow path. The lockless freelist is empty or we need to perform
 * debugging duties.
 *
 * Interrupts are disabled.
 *
 * Processing is still very fast if new objects have been freed to the
 * regular freelist. In that case we simply take over the regular freelist
 * as the lockless freelist and zap the regular freelist.
 *
 * If that is not working then we fall back to the partial lists. We take the
 * first element of the freelist as the object to allocate now and move the
 * rest of the freelist to the lockless freelist.
 *
 * And if we were unable to get a new slab from the partial slab lists then
 * we need to allocate a new slab. This is slowest path since we may sleep.
 */
static void *__slab_alloc(struct kmem_cache *s,
		gfp_t gfpflags, int node, void *addr, struct kmem_cache_cpu *c)
{
	void **object;
	struct page *new;

	/*
	 * 本地CPU的slab中没有可分配的内存(初始状态或CPU高速缓存已分配完)，则为其寻找新的slab
	 */
	if (!c->page)
		goto new_slab;

	slab_lock(c->page);
	/*
	 * 本地CPU存在slab，但结点不匹配(node不为-1，且c->node != node)
	 * 则将本地CPU的slab移回c->page对应结点的partial slab链表中
	 */
	if (unlikely(!node_match(c, node)))
		goto another_slab;
load_freelist:
	object = c->page->freelist;
	if (unlikely(!object)) 
		goto another_slab;
	if (unlikely(SlabDebug(c->page)))
		goto debug;

	object = c->page->freelist;
	c->freelist = object[c->offset];
	c->page->inuse = s->objects;
	c->page->freelist = NULL;
	c->node = page_to_nid(c->page);
	slab_unlock(c->page);
	return object;

another_slab:
	/* 将本地CPU的slab移回c->page对应结点的partial slab链表中 */
	deactivate_slab(s, c);

new_slab:
	/* 从指定结点的partial slab链表中寻找一个可用slab */
	new = get_partial(s, gfpflags, node);
	if (new) {
		c->page = new;
		goto load_freelist;
	}

	if (gfpflags & __GFP_WAIT)
		local_irq_enable();

	/* 指定结点的partial slab链表中不存在可用slab时，从伙伴系统中分配slab进行补充 */
	new = new_slab(s, gfpflags, node);

	if (gfpflags & __GFP_WAIT)
		local_irq_disable();

	if (new) {
		/*
		 * 最新分配的slab优先作为本地CPU的高速缓存
		 * 原有的本地CPU高速缓存需移回到partial(若存在空闲对象，否则移到full链表) slab链表中
		 */
		c = get_cpu_slab(s, smp_processor_id());
		if (c->page)
			flush_slab(s, c);
		slab_lock(new);
		SetSlabFrozen(new);
		c->page = new;
		goto load_freelist;
	}
	return NULL;
debug:
	object = c->page->freelist;
	if (!alloc_debug_processing(s, c->page, object, addr))
		goto another_slab;

	c->page->inuse++;
	c->page->freelist = object[c->offset];
	c->node = -1;
	slab_unlock(c->page);
	return object;
}

/*
 * Inlined fastpath so that allocation functions (kmalloc, kmem_cache_alloc)
 * have the fastpath folded into their functions. So no function call
 * overhead for requests that can be satisfied on the fastpath.
 *
 * The fastpath works by first checking if the lockless freelist can be used.
 * If not then __slab_alloc is called for slow processing.
 *
 * Otherwise we can simply pick the next object from the lockless free list.
 */
/*
 * slub分配器优先从每CPU高速缓存中分配对象，当其不满足(空或结点不匹配)时，从kmem_cache_node结点缓存中分配
 */
static void __always_inline *slab_alloc(struct kmem_cache *s,
		gfp_t gfpflags, int node, void *addr)
{
	void **object;
	unsigned long flags;
	struct kmem_cache_cpu *c;

	local_irq_save(flags);
	/* 获取本地CPU的slub缓存结构 */
	c = get_cpu_slab(s, smp_processor_id());
	/*
	 * 如果本地CPU的slub缓存freelist为空，或者节点不匹配
	 * 则通过慢速途径分配缓存对象
	 */
	if (unlikely(!c->freelist || !node_match(c, node)))

		object = __slab_alloc(s, gfpflags, node, addr, c);

	/*
	 * 如果本地CPU的slub缓存freelist不为空，且节点匹配
	 * 则直接从本地 CPU的slub缓存分配
	 */
	else {
		/* 使用freelist指向的对象进行分配 */
		object = c->freelist;
		/*
		 * 每个空闲对象均包含一个指向下一空闲对象的指针
		 * 且该指针相对空闲对象地址首部的偏移位置记录在c->offset内
		 *
		 * 当从本地CPU的freelist分配一个空闲对象后，需将下一个空闲对象地址保存到freelist中
		 */
		c->freelist = object[c->offset];
	}
	local_irq_restore(flags);

	if (unlikely((gfpflags & __GFP_ZERO) && object))
		memset(object, 0, c->objsize);

	return object;
}

/* 从kmem_cache缓存中所有内存结点分配对象，非NUMA系统中只有一个内存结点，即本地结点 */
void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
{
	return slab_alloc(s, gfpflags, -1, __builtin_return_address(0));
}
EXPORT_SYMBOL(kmem_cache_alloc);

#ifdef CONFIG_NUMA
/* NUMA从kmem_cache缓存中指定结点node分配对象，-1表示所有内存结点均可满足分配 */
void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
{
	/*
	 * __builtin_return_address(0)用于得到当前函数的返回地址，即slab_alloc的返回地址
	 * __builtin_return_address(1)用于得到当前函数调用者的返回地址，即kmem_cache_alloc_node的返回地址
	 */
	return slab_alloc(s, gfpflags, node, __builtin_return_address(0));
}
EXPORT_SYMBOL(kmem_cache_alloc_node);
#endif

/*
 * Slow patch handling. This may still be called frequently since objects
 * have a longer lifetime than the cpu slabs in most processing loads.
 *
 * So we still attempt to reduce cache line usage. Just take the slab
 * lock and free the item. If there is no additional partial page
 * handling required then we can return immediately.
 */
static void __slab_free(struct kmem_cache *s, struct page *page,
				void *x, void *addr, unsigned int offset)
{
	void *prior;
	void **object = (void *)x;

	slab_lock(page);

	if (unlikely(SlabDebug(page)))
		goto debug;
checks_ok:
	prior = object[offset] = page->freelist;
	page->freelist = object;
	page->inuse--;

	if (unlikely(SlabFrozen(page)))
		goto out_unlock;

	if (unlikely(!page->inuse))
		goto slab_empty;

	/*
	 * Objects left in the slab. If it
	 * was not on the partial list before
	 * then add it.
	 */
	if (unlikely(!prior))
		add_partial_tail(get_node(s, page_to_nid(page)), page);

out_unlock:
	slab_unlock(page);
	return;

slab_empty:
	if (prior)
		/*
		 * Slab still on the partial list.
		 */
		remove_partial(s, page);

	slab_unlock(page);
	discard_slab(s, page);
	return;

debug:
	if (!free_debug_processing(s, page, x, addr))
		goto out_unlock;
	goto checks_ok;
}

/*
 * Fastpath with forced inlining to produce a kfree and kmem_cache_free that
 * can perform fastpath freeing without additional function calls.
 *
 * The fastpath is only possible if we are freeing to the current cpu slab
 * of this processor. This typically the case if we have just allocated
 * the item before.
 *
 * If fastpath is not possible then fall back to __slab_free where we deal
 * with all sorts of special processing.
 */
static void __always_inline slab_free(struct kmem_cache *s,
			struct page *page, void *x, void *addr)
{
	void **object = (void *)x;
	unsigned long flags;
	struct kmem_cache_cpu *c;

	local_irq_save(flags);
	debug_check_no_locks_freed(object, s->objsize);
	c = get_cpu_slab(s, smp_processor_id());
	if (likely(page == c->page && c->node >= 0)) {
		object[c->offset] = c->freelist;
		c->freelist = object;
	} else
		__slab_free(s, page, x, addr, c->offset);

	local_irq_restore(flags);
}

void kmem_cache_free(struct kmem_cache *s, void *x)
{
	struct page *page;

	page = virt_to_head_page(x);

	slab_free(s, page, x, __builtin_return_address(0));
}
EXPORT_SYMBOL(kmem_cache_free);

/* Figure out on which slab object the object resides */
static struct page *get_object_page(const void *x)
{
	struct page *page = virt_to_head_page(x);

	if (!PageSlab(page))
		return NULL;

	return page;
}

/*
 * Object placement in a slab is made very easy because we always start at
 * offset 0. If we tune the size of the object to the alignment then we can
 * get the required alignment by putting one properly sized object after
 * another.
 *
 * Notice that the allocation order determines the sizes of the per cpu
 * caches. Each processor has always one slab available for allocations.
 * Increasing the allocation order reduces the number of times that slabs
 * must be moved on and off the partial lists and is therefore a factor in
 * locking overhead.
 */

/*
 * Mininum / Maximum order of slab pages. This influences locking overhead
 * and slab fragmentation. A higher order reduces the number of partial slabs
 * and increases the number of allocations possible without having to
 * take the list_lock.
 */
static int slub_min_order;
static int slub_max_order = DEFAULT_MAX_ORDER;
static int slub_min_objects = DEFAULT_MIN_OBJECTS;

/*
 * Merge control. If this is set then no merging of slab caches will occur.
 * (Could be removed. This was introduced to pacify the merge skeptics.)
 */
/*
 * SLUB缓存复用控制选项，如果设置了这个选项，则不复用SLUB缓存
 */
static int slub_nomerge;

/*
 * Calculate the order of allocation given an slab object size.
 *
 * The order of allocation has significant impact on performance and other
 * system components. Generally order 0 allocations should be preferred since
 * order 0 does not cause fragmentation in the page allocator. Larger objects
 * be problematic to put into order 0 slabs because there may be too much
 * unused space left. We go to a higher order if more than 1/8th of the slab
 * would be wasted.
 *
 * In order to reach satisfactory performance we must ensure that a minimum
 * number of objects is in one slab. Otherwise we may generate too much
 * activity on the partial lists which requires taking the list_lock. This is
 * less a concern for large slabs though which are rarely used.
 *
 * slub_max_order specifies the order where we begin to stop considering the
 * number of objects in a slab as critical. If we reach slub_max_order then
 * we try to keep the page order as low as possible. So we accept more waste
 * of space in favor of a small page order.
 *
 * Higher order allocations also allow the placement of more objects in a
 * slab and thereby reduce object handling overhead. If the user has
 * requested a higher mininum order then we start with that one instead of
 * the smallest order which will fit the object.
 */
static inline int slab_order(int size, int min_objects,
				int max_order, int fract_leftover)
{
	int order;
	int rem;
	int min_order = slub_min_order;

	for (order = max(min_order,
				fls(min_objects * size - 1) - PAGE_SHIFT);
			order <= max_order; order++) {

		unsigned long slab_size = PAGE_SIZE << order;

		if (slab_size < min_objects * size)
			continue;

		rem = slab_size % size;

		if (rem <= slab_size / fract_leftover)
			break;

	}

	return order;
}

static inline int calculate_order(int size)
{
	int order;
	int min_objects;
	int fraction;

	/*
	 * Attempt to find best configuration for a slab. This
	 * works by first attempting to generate a layout with
	 * the best configuration and backing off gradually.
	 *
	 * First we reduce the acceptable waste in a slab. Then
	 * we reduce the minimum objects required in a slab.
	 */
	min_objects = slub_min_objects;
	while (min_objects > 1) {
		fraction = 8;
		while (fraction >= 4) {
			order = slab_order(size, min_objects,
						slub_max_order, fraction);
			if (order <= slub_max_order)
				return order;
			fraction /= 2;
		}
		min_objects /= 2;
	}

	/*
	 * We were unable to place multiple objects in a slab. Now
	 * lets see if we can place a single object there.
	 */
	order = slab_order(size, 1, slub_max_order, 1);
	if (order <= slub_max_order)
		return order;

	/*
	 * Doh this slab cannot be placed using slub_max_order.
	 */
	order = slab_order(size, 1, MAX_ORDER, 1);
	if (order <= MAX_ORDER)
		return order;
	return -ENOSYS;
}

/*
 * Figure out what the alignment of the objects will be.
 */
static unsigned long calculate_alignment(unsigned long flags,
		unsigned long align, unsigned long size)
{
	/*
	 * If the user wants hardware cache aligned objects then
	 * follow that suggestion if the object is sufficiently
	 * large.
	 *
	 * The hardware cache alignment cannot override the
	 * specified alignment though. If that is greater
	 * then use it.
	 */
	if ((flags & SLAB_HWCACHE_ALIGN) &&
			size > cache_line_size() / 2)
		return max_t(unsigned long, align, cache_line_size());

	if (align < ARCH_SLAB_MINALIGN)
		return ARCH_SLAB_MINALIGN;

	return ALIGN(align, sizeof(void *));
}

static void init_kmem_cache_cpu(struct kmem_cache *s,
			struct kmem_cache_cpu *c)
{
	c->page = NULL;
	c->freelist = NULL;
	c->node = 0;
	c->offset = s->offset / sizeof(void *);
	c->objsize = s->objsize;
}

static void init_kmem_cache_node(struct kmem_cache_node *n)
{
	n->nr_partial = 0;
	atomic_long_set(&n->nr_slabs, 0);
	spin_lock_init(&n->list_lock);
	INIT_LIST_HEAD(&n->partial);
#ifdef CONFIG_SLUB_DEBUG
	INIT_LIST_HEAD(&n->full);
#endif
}

#ifdef CONFIG_SMP
/*
 * Per cpu array for per cpu structures.
 *
 * The per cpu array places all kmem_cache_cpu structures from one processor
 * close together meaning that it becomes possible that multiple per cpu
 * structures are contained in one cacheline. This may be particularly
 * beneficial for the kmalloc caches.
 *
 * A desktop system typically has around 60-80 slabs. With 100 here we are
 * likely able to get per cpu structures for all caches from the array defined
 * here. We must be able to cover all kmalloc caches during bootstrap.
 *
 * If the per cpu array is exhausted then fall back to kmalloc
 * of individual cachelines. No sharing is possible then.
 */
#define NR_KMEM_CACHE_CPU 100

static DEFINE_PER_CPU(struct kmem_cache_cpu,
				kmem_cache_cpu)[NR_KMEM_CACHE_CPU];

static DEFINE_PER_CPU(struct kmem_cache_cpu *, kmem_cache_cpu_free);
static cpumask_t kmem_cach_cpu_free_init_once = CPU_MASK_NONE;

static struct kmem_cache_cpu *alloc_kmem_cache_cpu(struct kmem_cache *s,
							int cpu, gfp_t flags)
{
	struct kmem_cache_cpu *c = per_cpu(kmem_cache_cpu_free, cpu);

	if (c)
		per_cpu(kmem_cache_cpu_free, cpu) =
				(void *)c->freelist;
	else {
		/* Table overflow: So allocate ourselves */
		c = kmalloc_node(
			ALIGN(sizeof(struct kmem_cache_cpu), cache_line_size()),
			flags, cpu_to_node(cpu));
		if (!c)
			return NULL;
	}

	init_kmem_cache_cpu(s, c);
	return c;
}

static void free_kmem_cache_cpu(struct kmem_cache_cpu *c, int cpu)
{
	if (c < per_cpu(kmem_cache_cpu, cpu) ||
			c > per_cpu(kmem_cache_cpu, cpu) + NR_KMEM_CACHE_CPU) {
		kfree(c);
		return;
	}
	c->freelist = (void *)per_cpu(kmem_cache_cpu_free, cpu);
	per_cpu(kmem_cache_cpu_free, cpu) = c;
}

static void free_kmem_cache_cpus(struct kmem_cache *s)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct kmem_cache_cpu *c = get_cpu_slab(s, cpu);

		if (c) {
			s->cpu_slab[cpu] = NULL;
			free_kmem_cache_cpu(c, cpu);
		}
	}
}

static int alloc_kmem_cache_cpus(struct kmem_cache *s, gfp_t flags)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct kmem_cache_cpu *c = get_cpu_slab(s, cpu);

		if (c)
			continue;

		c = alloc_kmem_cache_cpu(s, cpu, flags);
		if (!c) {
			free_kmem_cache_cpus(s);
			return 0;
		}
		s->cpu_slab[cpu] = c;
	}
	return 1;
}

/*
 * Initialize the per cpu array.
 */
static void init_alloc_cpu_cpu(int cpu)
{
	int i;

	if (cpu_isset(cpu, kmem_cach_cpu_free_init_once))
		return;

	for (i = NR_KMEM_CACHE_CPU - 1; i >= 0; i--)
		free_kmem_cache_cpu(&per_cpu(kmem_cache_cpu, cpu)[i], cpu);

	cpu_set(cpu, kmem_cach_cpu_free_init_once);
}

static void __init init_alloc_cpu(void)
{
	int cpu;

	for_each_online_cpu(cpu)
		init_alloc_cpu_cpu(cpu);
  }

#else
static inline void free_kmem_cache_cpus(struct kmem_cache *s) {}
static inline void init_alloc_cpu(void) {}

static inline int alloc_kmem_cache_cpus(struct kmem_cache *s, gfp_t flags)
{
	init_kmem_cache_cpu(s, &s->cpu_slab);
	return 1;
}
#endif

#ifdef CONFIG_NUMA
/*
 * No kmalloc_node yet so do it by hand. We know that this is the first
 * slab on the node for this slabcache. There are no concurrent accesses
 * possible.
 *
 * Note that this function only works on the kmalloc_node_cache
 * when allocating for the kmalloc_node_cache. This is used for bootstrapping
 * memory on a fresh node that has no slab structures yet.
 */
static struct kmem_cache_node *early_kmem_cache_node_alloc(gfp_t gfpflags,
							   int node)
{
	struct page *page;
	struct kmem_cache_node *n;

	BUG_ON(kmalloc_caches->size < sizeof(struct kmem_cache_node));

	page = new_slab(kmalloc_caches, gfpflags, node);

	BUG_ON(!page);
	if (page_to_nid(page) != node) {
		printk(KERN_ERR "SLUB: Unable to allocate memory from "
				"node %d\n", node);
		printk(KERN_ERR "SLUB: Allocating a useless per node structure "
				"in order to be able to continue\n");
	}

	n = page->freelist;
	BUG_ON(!n);
	page->freelist = get_freepointer(kmalloc_caches, n);
	page->inuse++;
	kmalloc_caches->node[node] = n;
#ifdef CONFIG_SLUB_DEBUG
	init_object(kmalloc_caches, n, 1);
	init_tracking(kmalloc_caches, n);
#endif
	init_kmem_cache_node(n);
	atomic_long_inc(&n->nr_slabs);
	add_partial(n, page);
	return n;
}

static void free_kmem_cache_nodes(struct kmem_cache *s)
{
	int node;

	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = s->node[node];
		if (n && n != &s->local_node)
			kmem_cache_free(kmalloc_caches, n);
		s->node[node] = NULL;
	}
}

static int init_kmem_cache_nodes(struct kmem_cache *s, gfp_t gfpflags)
{
	int node;
	int local_node;

	if (slab_state >= UP)
		local_node = page_to_nid(virt_to_page(s));
	else
		local_node = 0;

	/* 遍历系统内全部内存结点，为状态为N_NORMAL_MEMORY的结点创建kmem_cache_node */
	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n;

		/* 节点为本地节点，直接取s->local_node地址，而不用从kmem_cache_node缓存中分配 */
		if (local_node == node)
			n = &s->local_node;
		else {
			/*
			 * slab_state为DOWN，则表示kmem_cache_node缓存还未创建
			 * 即无法分配kmem_cache_node对象
			 *
			 * kmem_cache_init初始化SLUB分配器时，slab_state在创建kmem_cache_node缓存后由DOWN变为UP
			 * 而kmem_cache_node缓存同理也需要调用init_kmem_cache_nodes初始化该缓存的node[MAX_NUMNODES]成员
			 * 那此时必然不能直接从kmem_cache_node缓存中分配对象，early_kmem_cache_node_alloc即为了解决此问题
			 */
			if (slab_state == DOWN) {
				n = early_kmem_cache_node_alloc(gfpflags,
								node);
				continue;
			}

			/*
			 * slab_state不为DOWN，则表示kmem_cache_node缓存已创建
			 * 可直接从kmalloc_caches[0]缓存中分配struct kmem_cache_node对象
			 */
			n = kmem_cache_alloc_node(kmalloc_caches,
							gfpflags, node);

			if (!n) {
				free_kmem_cache_nodes(s);
				return 0;
			}

		}
		s->node[node] = n;
		init_kmem_cache_node(n);
	}
	return 1;
}
#else
static void free_kmem_cache_nodes(struct kmem_cache *s)
{
}

static int init_kmem_cache_nodes(struct kmem_cache *s, gfp_t gfpflags)
{
	init_kmem_cache_node(&s->local_node);
	return 1;
}
#endif

/*
 * calculate_sizes() determines the order and the distribution of data within
 * a slab object.
 */
static int calculate_sizes(struct kmem_cache *s)
{
	unsigned long flags = s->flags;
	unsigned long size = s->objsize;
	unsigned long align = s->align;

	/*
	 * Determine if we can poison the object itself. If the user of
	 * the slab may touch the object after free or before allocation
	 * then we should never poison the object itself.
	 */
	if ((flags & SLAB_POISON) && !(flags & SLAB_DESTROY_BY_RCU) &&
			!s->ctor)
		s->flags |= __OBJECT_POISON;
	else
		s->flags &= ~__OBJECT_POISON;

	/*
	 * Round up object size to the next word boundary. We can only
	 * place the free pointer at word boundaries and this determines
	 * the possible location of the free pointer.
	 */
	/*
	 * SLUB分配器中每个对象都包含一个用于指向下一个空闲对象的指针
	 * ALIGN(size, sizeof(void *))保证每个缓存对象占据的空间都能放下指针
	 */
	size = ALIGN(size, sizeof(void *));

#ifdef CONFIG_SLUB_DEBUG
	/*
	 * If we are Redzoning then check if there is some space between the
	 * end of the object and the free pointer. If not then add an
	 * additional word to have some bytes to store Redzone information.
	 */
	if ((flags & SLAB_RED_ZONE) && size == s->objsize)
		size += sizeof(void *);
#endif

	/*
	 * With that we have determined the number of bytes in actual use
	 * by the object. This is the potential offset to the free pointer.
	 */
	s->inuse = size;

	/*
	 * 使用SLAB_POISON特性或者指定ctor初始化对象时，对象内容不因被污染
	 * 因此对象内部指向下一空闲对象的指针需外置存储，即在对象后划分sizeof(void *)个字节存放
	 */
	if (((flags & (SLAB_DESTROY_BY_RCU | SLAB_POISON)) ||
		s->ctor)) {
		/*
		 * Relocate free pointer after the object if it is not
		 * permitted to overwrite the first word of the object on
		 * kmem_cache_free.
		 *
		 * This is the case if we do RCU, have a constructor or
		 * destructor or are poisoning the objects.
		 */
		/*
		 * s->offset记录存放指向下一个空闲对象的偏移位置
		 */
		s->offset = size;
		size += sizeof(void *);
	}

#ifdef CONFIG_SLUB_DEBUG
	if (flags & SLAB_STORE_USER)
		/*
		 * Need to store information about allocs and frees after
		 * the object.
		 */
		size += 2 * sizeof(struct track);

	if (flags & SLAB_RED_ZONE)
		/*
		 * Add some empty padding so that we can catch
		 * overwrites from earlier objects rather than let
		 * tracking information or the free pointer be
		 * corrupted if an user writes before the start
		 * of the object.
		 */
		size += sizeof(void *);
#endif

	/*
	 * Determine the alignment based on various parameters that the
	 * user specified and the dynamic determination of cache line size
	 * on bootup.
	 */
	align = calculate_alignment(flags, align, s->objsize);

	/*
	 * SLUB stores one object immediately after another beginning from
	 * offset 0. In order to align the objects we have to simply size
	 * each object to conform to the alignment.
	 */
	size = ALIGN(size, align);
	// 单个缓存对象整体占用的内存空间大小，包括：red_zone、free pointer、align等辅助空间
	s->size = size;

	// 根据单个缓存对象整体占用空间大小计算恰当的SLUB页帧阶数
	s->order = calculate_order(size);
	if (s->order < 0)
		return 0;

	/*
	 * Determine the number of objects per slab
	 */
	// objects代表单个SLUB缓存中缓存对象个数
	s->objects = (PAGE_SIZE << s->order) / size;

	return !!s->objects;

}

static int kmem_cache_open(struct kmem_cache *s, gfp_t gfpflags,
		const char *name, size_t size,
		size_t align, unsigned long flags,
		void (*ctor)(struct kmem_cache *, void *))
{
	memset(s, 0, kmem_size);
	s->name = name;
	s->ctor = ctor;
	/* 缓存对象数据占用的内存空间大小，不包括：red_zone、free pointer、align等辅助空间 */
	s->objsize = size;
	s->align = align;
	s->flags = kmem_cache_flags(size, flags, name, ctor);

	if (!calculate_sizes(s))
		goto error;

	/* SLUB缓存对象种类数为1，新建缓存暂时不存在复用 */
	s->refcount = 1;
#ifdef CONFIG_NUMA
	s->defrag_ratio = 100;
#endif
    /* 初始化struct kmem_cache_node，对于NUMA架构要先分配kmem_cache_node */
	if (!init_kmem_cache_nodes(s, gfpflags & ~SLUB_DMA))
		goto error;

	/* 初始化struct kmem_cache_cpu，对于SMP系统要先分配kmem_cache_cpu */
	if (alloc_kmem_cache_cpus(s, gfpflags & ~SLUB_DMA))
		return 1;
	free_kmem_cache_nodes(s);
error:
	if (flags & SLAB_PANIC)
		panic("Cannot create slab %s size=%lu realsize=%u "
			"order=%u offset=%u flags=%lx\n",
			s->name, (unsigned long)size, s->size, s->order,
			s->offset, flags);
	return 0;
}

/*
 * Check if a given pointer is valid
 */
int kmem_ptr_validate(struct kmem_cache *s, const void *object)
{
	struct page * page;

	page = get_object_page(object);

	if (!page || s != page->slab)
		/* No slab or wrong slab */
		return 0;

	if (!check_valid_pointer(s, page, object))
		return 0;

	/*
	 * We could also check if the object is on the slabs freelist.
	 * But this would be too expensive and it seems that the main
	 * purpose of kmem_ptr_valid is to check if the object belongs
	 * to a certain slab.
	 */
	return 1;
}
EXPORT_SYMBOL(kmem_ptr_validate);

/*
 * Determine the size of a slab object
 */
unsigned int kmem_cache_size(struct kmem_cache *s)
{
	return s->objsize;
}
EXPORT_SYMBOL(kmem_cache_size);

const char *kmem_cache_name(struct kmem_cache *s)
{
	return s->name;
}
EXPORT_SYMBOL(kmem_cache_name);

/*
 * Attempt to free all slabs on a node. Return the number of slabs we
 * were unable to free.
 */
static int free_list(struct kmem_cache *s, struct kmem_cache_node *n,
			struct list_head *list)
{
	int slabs_inuse = 0;
	unsigned long flags;
	struct page *page, *h;

	spin_lock_irqsave(&n->list_lock, flags);
	list_for_each_entry_safe(page, h, list, lru)
		if (!page->inuse) {
			list_del(&page->lru);
			discard_slab(s, page);
		} else
			slabs_inuse++;
	spin_unlock_irqrestore(&n->list_lock, flags);
	return slabs_inuse;
}

/*
 * Release all resources used by a slab cache.
 */
static inline int kmem_cache_close(struct kmem_cache *s)
{
	int node;

	flush_all(s);

	/* Attempt to free all objects */
	free_kmem_cache_cpus(s);
	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = get_node(s, node);

		n->nr_partial -= free_list(s, n, &n->partial);
		if (atomic_long_read(&n->nr_slabs))
			return 1;
	}
	free_kmem_cache_nodes(s);
	return 0;
}

/*
 * Close a cache and release the kmem_cache structure
 * (must be used for caches created using kmem_cache_create)
 */
void kmem_cache_destroy(struct kmem_cache *s)
{
	down_write(&slub_lock);
	s->refcount--;
	if (!s->refcount) {
		list_del(&s->list);
		up_write(&slub_lock);
		if (kmem_cache_close(s))
			WARN_ON(1);
		sysfs_slab_remove(s);
		kfree(s);
	} else
		up_write(&slub_lock);
}
EXPORT_SYMBOL(kmem_cache_destroy);

/********************************************************************
 *		Kmalloc subsystem
 *******************************************************************/
/*
 * SLUB分配器的通用缓存
 * PAGE_SHIFT为12，则表示存在12个通用缓存
 */
struct kmem_cache kmalloc_caches[PAGE_SHIFT] __cacheline_aligned;
EXPORT_SYMBOL(kmalloc_caches);

#ifdef CONFIG_ZONE_DMA
static struct kmem_cache *kmalloc_caches_dma[PAGE_SHIFT];
#endif

static int __init setup_slub_min_order(char *str)
{
	get_option (&str, &slub_min_order);

	return 1;
}

__setup("slub_min_order=", setup_slub_min_order);

static int __init setup_slub_max_order(char *str)
{
	get_option (&str, &slub_max_order);

	return 1;
}

__setup("slub_max_order=", setup_slub_max_order);

static int __init setup_slub_min_objects(char *str)
{
	get_option (&str, &slub_min_objects);

	return 1;
}

__setup("slub_min_objects=", setup_slub_min_objects);

static int __init setup_slub_nomerge(char *str)
{
	slub_nomerge = 1;
	return 1;
}

__setup("slub_nomerge", setup_slub_nomerge);

static struct kmem_cache *create_kmalloc_cache(struct kmem_cache *s,
		const char *name, int size, gfp_t gfp_flags)
{
	unsigned int flags = 0;

	if (gfp_flags & SLUB_DMA)
		flags = SLAB_CACHE_DMA;

	down_write(&slub_lock);
	if (!kmem_cache_open(s, gfp_flags, name, size, ARCH_KMALLOC_MINALIGN,
			flags, NULL))
		goto panic;

	list_add(&s->list, &slab_caches);
	up_write(&slub_lock);
	if (sysfs_slab_add(s))
		goto panic;
	return s;

panic:
	panic("Creation of kmalloc slab %s size=%d failed.\n", name, size);
}

#ifdef CONFIG_ZONE_DMA

static void sysfs_add_func(struct work_struct *w)
{
	struct kmem_cache *s;

	down_write(&slub_lock);
	list_for_each_entry(s, &slab_caches, list) {
		if (s->flags & __SYSFS_ADD_DEFERRED) {
			s->flags &= ~__SYSFS_ADD_DEFERRED;
			sysfs_slab_add(s);
		}
	}
	up_write(&slub_lock);
}

static DECLARE_WORK(sysfs_add_work, sysfs_add_func);

static noinline struct kmem_cache *dma_kmalloc_cache(int index, gfp_t flags)
{
	struct kmem_cache *s;
	char *text;
	size_t realsize;

	s = kmalloc_caches_dma[index];
	if (s)
		return s;

	/* Dynamically create dma cache */
	if (flags & __GFP_WAIT)
		down_write(&slub_lock);
	else {
		if (!down_write_trylock(&slub_lock))
			goto out;
	}

	if (kmalloc_caches_dma[index])
		goto unlock_out;

	realsize = kmalloc_caches[index].objsize;
	text = kasprintf(flags & ~SLUB_DMA, "kmalloc_dma-%d", (unsigned int)realsize),
	s = kmalloc(kmem_size, flags & ~SLUB_DMA);

	if (!s || !text || !kmem_cache_open(s, flags, text,
			realsize, ARCH_KMALLOC_MINALIGN,
			SLAB_CACHE_DMA|__SYSFS_ADD_DEFERRED, NULL)) {
		kfree(s);
		kfree(text);
		goto unlock_out;
	}

	list_add(&s->list, &slab_caches);
	kmalloc_caches_dma[index] = s;

	schedule_work(&sysfs_add_work);

unlock_out:
	up_write(&slub_lock);
out:
	return kmalloc_caches_dma[index];
}
#endif

/*
 * Conversion table for small slabs sizes / 8 to the index in the
 * kmalloc array. This is necessary for slabs < 192 since we have non power
 * of two cache sizes there. The size of larger slabs can be determined using
 * fls.
 */
static s8 size_index[24] = {
	3,	/* 8 */
	4,	/* 16 */
	5,	/* 24 */
	5,	/* 32 */
	6,	/* 40 */
	6,	/* 48 */
	6,	/* 56 */
	6,	/* 64 */
	1,	/* 72 */
	1,	/* 80 */
	1,	/* 88 */
	1,	/* 96 */
	7,	/* 104 */
	7,	/* 112 */
	7,	/* 120 */
	7,	/* 128 */
	2,	/* 136 */
	2,	/* 144 */
	2,	/* 152 */
	2,	/* 160 */
	2,	/* 168 */
	2,	/* 176 */
	2,	/* 184 */
	2	/* 192 */
};

static struct kmem_cache *get_slab(size_t size, gfp_t flags)
{
	int index;

	if (size <= 192) {
		if (!size)
			return ZERO_SIZE_PTR;

		index = size_index[(size - 1) / 8];
	} else
		index = fls(size - 1);

#ifdef CONFIG_ZONE_DMA
	if (unlikely((flags & SLUB_DMA)))
		return dma_kmalloc_cache(index, flags);

#endif
	return &kmalloc_caches[index];
}

void *__kmalloc(size_t size, gfp_t flags)
{
	struct kmem_cache *s;

	if (unlikely(size > PAGE_SIZE / 2))
		return (void *)__get_free_pages(flags | __GFP_COMP,
							get_order(size));

	s = get_slab(size, flags);

	if (unlikely(ZERO_OR_NULL_PTR(s)))
		return s;

	return slab_alloc(s, flags, -1, __builtin_return_address(0));
}
EXPORT_SYMBOL(__kmalloc);

#ifdef CONFIG_NUMA
void *__kmalloc_node(size_t size, gfp_t flags, int node)
{
	struct kmem_cache *s;

	if (unlikely(size > PAGE_SIZE / 2))
		return (void *)__get_free_pages(flags | __GFP_COMP,
							get_order(size));

	s = get_slab(size, flags);

	if (unlikely(ZERO_OR_NULL_PTR(s)))
		return s;

	return slab_alloc(s, flags, node, __builtin_return_address(0));
}
EXPORT_SYMBOL(__kmalloc_node);
#endif

size_t ksize(const void *object)
{
	struct page *page;
	struct kmem_cache *s;

	BUG_ON(!object);
	if (unlikely(object == ZERO_SIZE_PTR))
		return 0;

	page = virt_to_head_page(object);
	BUG_ON(!page);

	if (unlikely(!PageSlab(page)))
		return PAGE_SIZE << compound_order(page);

	s = page->slab;
	BUG_ON(!s);

	/*
	 * Debugging requires use of the padding between object
	 * and whatever may come after it.
	 */
	if (s->flags & (SLAB_RED_ZONE | SLAB_POISON))
		return s->objsize;

	/*
	 * If we have the need to store the freelist pointer
	 * back there or track user information then we can
	 * only use the space before that information.
	 */
	if (s->flags & (SLAB_DESTROY_BY_RCU | SLAB_STORE_USER))
		return s->inuse;

	/*
	 * Else we can use all the padding etc for the allocation
	 */
	return s->size;
}
EXPORT_SYMBOL(ksize);

void kfree(const void *x)
{
	struct page *page;

	if (unlikely(ZERO_OR_NULL_PTR(x)))
		return;

	page = virt_to_head_page(x);
	if (unlikely(!PageSlab(page))) {
		put_page(page);
		return;
	}
	slab_free(page->slab, page, (void *)x, __builtin_return_address(0));
}
EXPORT_SYMBOL(kfree);

/*
 * kmem_cache_shrink removes empty slabs from the partial lists and sorts
 * the remaining slabs by the number of items in use. The slabs with the
 * most items in use come first. New allocations will then fill those up
 * and thus they can be removed from the partial lists.
 *
 * The slabs with the least items are placed last. This results in them
 * being allocated from last increasing the chance that the last objects
 * are freed in them.
 */
int kmem_cache_shrink(struct kmem_cache *s)
{
	int node;
	int i;
	struct kmem_cache_node *n;
	struct page *page;
	struct page *t;
	struct list_head *slabs_by_inuse =
		kmalloc(sizeof(struct list_head) * s->objects, GFP_KERNEL);
	unsigned long flags;

	if (!slabs_by_inuse)
		return -ENOMEM;

	flush_all(s);
	for_each_node_state(node, N_NORMAL_MEMORY) {
		n = get_node(s, node);

		if (!n->nr_partial)
			continue;

		for (i = 0; i < s->objects; i++)
			INIT_LIST_HEAD(slabs_by_inuse + i);

		spin_lock_irqsave(&n->list_lock, flags);

		/*
		 * Build lists indexed by the items in use in each slab.
		 *
		 * Note that concurrent frees may occur while we hold the
		 * list_lock. page->inuse here is the upper limit.
		 */
		list_for_each_entry_safe(page, t, &n->partial, lru) {
			if (!page->inuse && slab_trylock(page)) {
				/*
				 * Must hold slab lock here because slab_free
				 * may have freed the last object and be
				 * waiting to release the slab.
				 */
				list_del(&page->lru);
				n->nr_partial--;
				slab_unlock(page);
				discard_slab(s, page);
			} else {
				list_move(&page->lru,
				slabs_by_inuse + page->inuse);
			}
		}

		/*
		 * Rebuild the partial list with the slabs filled up most
		 * first and the least used slabs at the end.
		 */
		for (i = s->objects - 1; i >= 0; i--)
			list_splice(slabs_by_inuse + i, n->partial.prev);

		spin_unlock_irqrestore(&n->list_lock, flags);
	}

	kfree(slabs_by_inuse);
	return 0;
}
EXPORT_SYMBOL(kmem_cache_shrink);

#if defined(CONFIG_NUMA) && defined(CONFIG_MEMORY_HOTPLUG)
static int slab_mem_going_offline_callback(void *arg)
{
	struct kmem_cache *s;

	down_read(&slub_lock);
	list_for_each_entry(s, &slab_caches, list)
		kmem_cache_shrink(s);
	up_read(&slub_lock);

	return 0;
}

static void slab_mem_offline_callback(void *arg)
{
	struct kmem_cache_node *n;
	struct kmem_cache *s;
	struct memory_notify *marg = arg;
	int offline_node;

	offline_node = marg->status_change_nid;

	/*
	 * If the node still has available memory. we need kmem_cache_node
	 * for it yet.
	 */
	if (offline_node < 0)
		return;

	down_read(&slub_lock);
	list_for_each_entry(s, &slab_caches, list) {
		n = get_node(s, offline_node);
		if (n) {
			/*
			 * if n->nr_slabs > 0, slabs still exist on the node
			 * that is going down. We were unable to free them,
			 * and offline_pages() function shoudn't call this
			 * callback. So, we must fail.
			 */
			BUG_ON(atomic_long_read(&n->nr_slabs));

			s->node[offline_node] = NULL;
			kmem_cache_free(kmalloc_caches, n);
		}
	}
	up_read(&slub_lock);
}

static int slab_mem_going_online_callback(void *arg)
{
	struct kmem_cache_node *n;
	struct kmem_cache *s;
	struct memory_notify *marg = arg;
	int nid = marg->status_change_nid;
	int ret = 0;

	/*
	 * If the node's memory is already available, then kmem_cache_node is
	 * already created. Nothing to do.
	 */
	if (nid < 0)
		return 0;

	/*
	 * We are bringing a node online. No memory is availabe yet. We must
	 * allocate a kmem_cache_node structure in order to bring the node
	 * online.
	 */
	down_read(&slub_lock);
	list_for_each_entry(s, &slab_caches, list) {
		/*
		 * XXX: kmem_cache_alloc_node will fallback to other nodes
		 *      since memory is not yet available from the node that
		 *      is brought up.
		 */
		n = kmem_cache_alloc(kmalloc_caches, GFP_KERNEL);
		if (!n) {
			ret = -ENOMEM;
			goto out;
		}
		init_kmem_cache_node(n);
		s->node[nid] = n;
	}
out:
	up_read(&slub_lock);
	return ret;
}

static int slab_memory_callback(struct notifier_block *self,
				unsigned long action, void *arg)
{
	int ret = 0;

	switch (action) {
	case MEM_GOING_ONLINE:
		ret = slab_mem_going_online_callback(arg);
		break;
	case MEM_GOING_OFFLINE:
		ret = slab_mem_going_offline_callback(arg);
		break;
	case MEM_OFFLINE:
	case MEM_CANCEL_ONLINE:
		slab_mem_offline_callback(arg);
		break;
	case MEM_ONLINE:
	case MEM_CANCEL_OFFLINE:
		break;
	}

	ret = notifier_from_errno(ret);
	return ret;
}

#endif /* CONFIG_MEMORY_HOTPLUG */

/********************************************************************
 *			Basic setup of slabs
 *******************************************************************/
/*
 * 初始化slub高速缓存，主要用于初始化kmem_cache_node缓存和kmalloc缓存
 */
void __init kmem_cache_init(void)
{
	int i;
	int caches = 0;

	init_alloc_cpu();

#ifdef CONFIG_NUMA
	/*
	 * Must first have the slab cache available for the allocations of the
	 * struct kmem_cache_node's. There is special bootstrap code in
	 * kmem_cache_open for slab_state == DOWN.
	 */
	/* 创建kmalloc_caches的第0个缓存用来存储struct kmem_cache_node */
	create_kmalloc_cache(&kmalloc_caches[0], "kmem_cache_node",
		sizeof(struct kmem_cache_node), GFP_KERNEL);
	kmalloc_caches[0].refcount = -1;
	caches++;

	hotplug_memory_notifier(slab_memory_callback, 1);
#endif

	/* Able to allocate the per node structures */
	slab_state = PARTIAL;

	/* Caches that are not of the two-to-the-power-of size */
	/* 如果kmalloc的最小对象大小不大于64则创建第1个缓存，对象大小为96字节 */
	if (KMALLOC_MIN_SIZE <= 64) {
		create_kmalloc_cache(&kmalloc_caches[1],
				"kmalloc-96", 96, GFP_KERNEL);
		caches++;
	}
	/* 如果kmalloc的最小对象大小不大于128则创建第2个缓存，对象大小为192字节 */
	if (KMALLOC_MIN_SIZE <= 128) {
		create_kmalloc_cache(&kmalloc_caches[2],
				"kmalloc-192", 192, GFP_KERNEL);
		caches++;
	}

	/* 创建后续的通用缓存 */
	for (i = KMALLOC_SHIFT_LOW; i < PAGE_SHIFT; i++) {
		create_kmalloc_cache(&kmalloc_caches[i],
			"kmalloc", 1 << i, GFP_KERNEL);
		caches++;
	}


	/*
	 * Patch up the size_index table if we have strange large alignment
	 * requirements for the kmalloc array. This is only the case for
	 * mips it seems. The standard arches will not generate any code here.
	 *
	 * Largest permitted alignment is 256 bytes due to the way we
	 * handle the index determination for the smaller caches.
	 *
	 * Make sure that nothing crazy happens if someone starts tinkering
	 * around with ARCH_KMALLOC_MINALIGN
	 */
	BUILD_BUG_ON(KMALLOC_MIN_SIZE > 256 ||
		(KMALLOC_MIN_SIZE & (KMALLOC_MIN_SIZE - 1)));

	for (i = 8; i < KMALLOC_MIN_SIZE; i += 8)
		size_index[(i - 1) / 8] = KMALLOC_SHIFT_LOW;

	/* 更新SLUB分配器的初始化进度 */
	slab_state = UP;

	/* Provide the correct kmalloc names now that the caches are up */
	for (i = KMALLOC_SHIFT_LOW; i < PAGE_SHIFT; i++)
		kmalloc_caches[i]. name =
			kasprintf(GFP_KERNEL, "kmalloc-%d", 1 << i);

#ifdef CONFIG_SMP
	register_cpu_notifier(&slab_notifier);
	kmem_size = offsetof(struct kmem_cache, cpu_slab) +
				nr_cpu_ids * sizeof(struct kmem_cache_cpu *);
#else
	kmem_size = sizeof(struct kmem_cache);
#endif


	printk(KERN_INFO "SLUB: Genslabs=%d, HWalign=%d, Order=%d-%d, MinObjects=%d,"
		" CPUs=%d, Nodes=%d\n",
		caches, cache_line_size(),
		slub_min_order, slub_max_order, slub_min_objects,
		nr_cpu_ids, nr_node_ids);
}

/*
 * Find a mergeable slab cache
 */
static int slab_unmergeable(struct kmem_cache *s)
{
	if (slub_nomerge || (s->flags & SLUB_NEVER_MERGE))
		return 1;

	if (s->ctor)
		return 1;

	/*
	 * We may have set a slab to be unmergeable during bootstrap.
	 */
	if (s->refcount < 0)
		return 1;

	return 0;
}

static struct kmem_cache *find_mergeable(size_t size,
		size_t align, unsigned long flags, const char *name,
		void (*ctor)(struct kmem_cache *, void *))
{
	struct kmem_cache *s;

	/*
	 * slub_nomerge被设置，则SLUB缓存全部都不复用
	 * SLUB_NEVER_MERGE标志位被设置，则当前创建的缓存不与其他缓存复用
	 */
	if (slub_nomerge || (flags & SLUB_NEVER_MERGE))
		return NULL;

	/*
	 * ctor对象初始化函数为指定，则表明对象初始内存存在差异，不因复用缓存
	 */
	if (ctor)
		return NULL;

	/*
	 * 缓存可复用，则表明SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
	 *	SLAB_TRACE | SLAB_DESTROY_BY_RCU等特性均未被开启
	 * 因此缓存对象size只需考虑free pointer和align即可
	 */
	size = ALIGN(size, sizeof(void *));
	align = calculate_alignment(flags, align, size);
	size = ALIGN(size, align);
	flags = kmem_cache_flags(size, flags, name, NULL);

	/* 遍历slab_caches缓存链表 */
	list_for_each_entry(s, &slab_caches, list) {
		/* 不允许复用，则跳过 */
		if (slab_unmergeable(s))
			continue;

		/* 缓存对象占用内存空间小于要求的size，则跳过 */
		if (size > s->size)
			continue;

		/* 相关标识不一致，则跳过 */
		if ((flags & SLUB_MERGE_SAME) != (s->flags & SLUB_MERGE_SAME))
				continue;
		/*
		 * Check if alignment is compatible.
		 * Courtesy of Adrian Drzewiecki
		 */
		/*
		 * 检查字节对齐是否兼容，即可复用缓存的对象大小也可看成按照align对齐
		 */
		if ((s->size & ~(align -1)) != s->size)
			continue;

		/* 缓存对象占用内存空间大小比指定的size多出1个字长以上，则跳过，避免过多空间浪费 */
		if (s->size - size >= sizeof(void *))
			continue;

		return s;
	}
	return NULL;
}

struct kmem_cache *kmem_cache_create(const char *name, size_t size,
		size_t align, unsigned long flags,
		void (*ctor)(struct kmem_cache *, void *))
{
	struct kmem_cache *s;

	down_write(&slub_lock);
	/*
	 * 先试图从已有的缓存中找到一个可以满足要求的进行复用，这样就不用创建新的缓存
	 */
	s = find_mergeable(size, align, flags, name, ctor);
	if (s) {
		int cpu;

		/*
		 * 缓存的引用计数加1，表示缓存中多了一种对象
		 */
		s->refcount++;
		/*
		 * Adjust the object sizes so that we clear
		 * the complete object on kzalloc.
		 */
		/*
		 * 在新对象大小和原有对象大小中取较大者作为缓存的对象大小
		 */
		s->objsize = max(s->objsize, (int)size);

		/*
		 * And then we need to update the object size in the
		 * per cpu structures
		 */
		/*
		 * 更新每CPU结构中的对象大小值
		 */
		for_each_online_cpu(cpu)
			get_cpu_slab(s, cpu)->objsize = s->objsize;
		s->inuse = max_t(int, s->inuse, ALIGN(size, sizeof(void *)));
		up_write(&slub_lock);
		if (sysfs_slab_alias(s, name))
			goto err;
		return s;
	}

	/*
	 * 未找到可复用缓存，则新建一个SLUB缓存
	 * kmem_cache对象不再从cache_cache特定高速缓存分配，而是通过kmalloc从通用高速缓存分配
	 */
	s = kmalloc(kmem_size, GFP_KERNEL);
	if (s) {
		if (kmem_cache_open(s, GFP_KERNEL, name,
				size, align, flags, ctor)) {
			// 将新建的kmem_cache高速缓存链接到slab_caches全局链表
			list_add(&s->list, &slab_caches);
			up_write(&slub_lock);
			if (sysfs_slab_add(s))
				goto err;
			return s;
		}
		kfree(s);
	}
	up_write(&slub_lock);

err:
	if (flags & SLAB_PANIC)
		panic("Cannot create slabcache %s\n", name);
	else
		s = NULL;
	return s;
}
EXPORT_SYMBOL(kmem_cache_create);

#ifdef CONFIG_SMP
/*
 * Use the cpu notifier to insure that the cpu slabs are flushed when
 * necessary.
 */
static int __cpuinit slab_cpuup_callback(struct notifier_block *nfb,
		unsigned long action, void *hcpu)
{
	long cpu = (long)hcpu;
	struct kmem_cache *s;
	unsigned long flags;

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		init_alloc_cpu_cpu(cpu);
		down_read(&slub_lock);
		list_for_each_entry(s, &slab_caches, list)
			s->cpu_slab[cpu] = alloc_kmem_cache_cpu(s, cpu,
							GFP_KERNEL);
		up_read(&slub_lock);
		break;

	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		down_read(&slub_lock);
		list_for_each_entry(s, &slab_caches, list) {
			struct kmem_cache_cpu *c = get_cpu_slab(s, cpu);

			local_irq_save(flags);
			__flush_cpu_slab(s, cpu);
			local_irq_restore(flags);
			free_kmem_cache_cpu(c, cpu);
			s->cpu_slab[cpu] = NULL;
		}
		up_read(&slub_lock);
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata slab_notifier =
	{ &slab_cpuup_callback, NULL, 0 };

#endif

void *__kmalloc_track_caller(size_t size, gfp_t gfpflags, void *caller)
{
	struct kmem_cache *s;

	if (unlikely(size > PAGE_SIZE / 2))
		return (void *)__get_free_pages(gfpflags | __GFP_COMP,
							get_order(size));
	s = get_slab(size, gfpflags);

	if (unlikely(ZERO_OR_NULL_PTR(s)))
		return s;

	return slab_alloc(s, gfpflags, -1, caller);
}

void *__kmalloc_node_track_caller(size_t size, gfp_t gfpflags,
					int node, void *caller)
{
	struct kmem_cache *s;

	if (unlikely(size > PAGE_SIZE / 2))
		return (void *)__get_free_pages(gfpflags | __GFP_COMP,
							get_order(size));
	s = get_slab(size, gfpflags);

	if (unlikely(ZERO_OR_NULL_PTR(s)))
		return s;

	return slab_alloc(s, gfpflags, node, caller);
}

static unsigned long count_partial(struct kmem_cache_node *n)
{
	unsigned long flags;
	unsigned long x = 0;
	struct page *page;

	spin_lock_irqsave(&n->list_lock, flags);
	list_for_each_entry(page, &n->partial, lru)
		x += page->inuse;
	spin_unlock_irqrestore(&n->list_lock, flags);
	return x;
}

#if defined(CONFIG_SYSFS) && defined(CONFIG_SLUB_DEBUG)
static int validate_slab(struct kmem_cache *s, struct page *page,
						unsigned long *map)
{
	void *p;
	void *addr = page_address(page);

	if (!check_slab(s, page) ||
			!on_freelist(s, page, NULL))
		return 0;

	/* Now we know that a valid freelist exists */
	bitmap_zero(map, s->objects);

	for_each_free_object(p, s, page->freelist) {
		set_bit(slab_index(p, s, addr), map);
		if (!check_object(s, page, p, 0))
			return 0;
	}

	for_each_object(p, s, addr)
		if (!test_bit(slab_index(p, s, addr), map))
			if (!check_object(s, page, p, 1))
				return 0;
	return 1;
}

static void validate_slab_slab(struct kmem_cache *s, struct page *page,
						unsigned long *map)
{
	if (slab_trylock(page)) {
		validate_slab(s, page, map);
		slab_unlock(page);
	} else
		printk(KERN_INFO "SLUB %s: Skipped busy slab 0x%p\n",
			s->name, page);

	if (s->flags & DEBUG_DEFAULT_FLAGS) {
		if (!SlabDebug(page))
			printk(KERN_ERR "SLUB %s: SlabDebug not set "
				"on slab 0x%p\n", s->name, page);
	} else {
		if (SlabDebug(page))
			printk(KERN_ERR "SLUB %s: SlabDebug set on "
				"slab 0x%p\n", s->name, page);
	}
}

static int validate_slab_node(struct kmem_cache *s,
		struct kmem_cache_node *n, unsigned long *map)
{
	unsigned long count = 0;
	struct page *page;
	unsigned long flags;

	spin_lock_irqsave(&n->list_lock, flags);

	list_for_each_entry(page, &n->partial, lru) {
		validate_slab_slab(s, page, map);
		count++;
	}
	if (count != n->nr_partial)
		printk(KERN_ERR "SLUB %s: %ld partial slabs counted but "
			"counter=%ld\n", s->name, count, n->nr_partial);

	if (!(s->flags & SLAB_STORE_USER))
		goto out;

	list_for_each_entry(page, &n->full, lru) {
		validate_slab_slab(s, page, map);
		count++;
	}
	if (count != atomic_long_read(&n->nr_slabs))
		printk(KERN_ERR "SLUB: %s %ld slabs counted but "
			"counter=%ld\n", s->name, count,
			atomic_long_read(&n->nr_slabs));

out:
	spin_unlock_irqrestore(&n->list_lock, flags);
	return count;
}

static long validate_slab_cache(struct kmem_cache *s)
{
	int node;
	unsigned long count = 0;
	unsigned long *map = kmalloc(BITS_TO_LONGS(s->objects) *
				sizeof(unsigned long), GFP_KERNEL);

	if (!map)
		return -ENOMEM;

	flush_all(s);
	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = get_node(s, node);

		count += validate_slab_node(s, n, map);
	}
	kfree(map);
	return count;
}

#ifdef SLUB_RESILIENCY_TEST
static void resiliency_test(void)
{
	u8 *p;

	printk(KERN_ERR "SLUB resiliency testing\n");
	printk(KERN_ERR "-----------------------\n");
	printk(KERN_ERR "A. Corruption after allocation\n");

	p = kzalloc(16, GFP_KERNEL);
	p[16] = 0x12;
	printk(KERN_ERR "\n1. kmalloc-16: Clobber Redzone/next pointer"
			" 0x12->0x%p\n\n", p + 16);

	validate_slab_cache(kmalloc_caches + 4);

	/* Hmmm... The next two are dangerous */
	p = kzalloc(32, GFP_KERNEL);
	p[32 + sizeof(void *)] = 0x34;
	printk(KERN_ERR "\n2. kmalloc-32: Clobber next pointer/next slab"
		 	" 0x34 -> -0x%p\n", p);
	printk(KERN_ERR "If allocated object is overwritten then not detectable\n\n");

	validate_slab_cache(kmalloc_caches + 5);
	p = kzalloc(64, GFP_KERNEL);
	p += 64 + (get_cycles() & 0xff) * sizeof(void *);
	*p = 0x56;
	printk(KERN_ERR "\n3. kmalloc-64: corrupting random byte 0x56->0x%p\n",
									p);
	printk(KERN_ERR "If allocated object is overwritten then not detectable\n\n");
	validate_slab_cache(kmalloc_caches + 6);

	printk(KERN_ERR "\nB. Corruption after free\n");
	p = kzalloc(128, GFP_KERNEL);
	kfree(p);
	*p = 0x78;
	printk(KERN_ERR "1. kmalloc-128: Clobber first word 0x78->0x%p\n\n", p);
	validate_slab_cache(kmalloc_caches + 7);

	p = kzalloc(256, GFP_KERNEL);
	kfree(p);
	p[50] = 0x9a;
	printk(KERN_ERR "\n2. kmalloc-256: Clobber 50th byte 0x9a->0x%p\n\n", p);
	validate_slab_cache(kmalloc_caches + 8);

	p = kzalloc(512, GFP_KERNEL);
	kfree(p);
	p[512] = 0xab;
	printk(KERN_ERR "\n3. kmalloc-512: Clobber redzone 0xab->0x%p\n\n", p);
	validate_slab_cache(kmalloc_caches + 9);
}
#else
static void resiliency_test(void) {};
#endif

/*
 * Generate lists of code addresses where slabcache objects are allocated
 * and freed.
 */

struct location {
	unsigned long count;
	void *addr;
	long long sum_time;
	long min_time;
	long max_time;
	long min_pid;
	long max_pid;
	cpumask_t cpus;
	nodemask_t nodes;
};

struct loc_track {
	unsigned long max;
	unsigned long count;
	struct location *loc;
};

static void free_loc_track(struct loc_track *t)
{
	if (t->max)
		free_pages((unsigned long)t->loc,
			get_order(sizeof(struct location) * t->max));
}

static int alloc_loc_track(struct loc_track *t, unsigned long max, gfp_t flags)
{
	struct location *l;
	int order;

	order = get_order(sizeof(struct location) * max);

	l = (void *)__get_free_pages(flags, order);
	if (!l)
		return 0;

	if (t->count) {
		memcpy(l, t->loc, sizeof(struct location) * t->count);
		free_loc_track(t);
	}
	t->max = max;
	t->loc = l;
	return 1;
}

static int add_location(struct loc_track *t, struct kmem_cache *s,
				const struct track *track)
{
	long start, end, pos;
	struct location *l;
	void *caddr;
	unsigned long age = jiffies - track->when;

	start = -1;
	end = t->count;

	for ( ; ; ) {
		pos = start + (end - start + 1) / 2;

		/*
		 * There is nothing at "end". If we end up there
		 * we need to add something to before end.
		 */
		if (pos == end)
			break;

		caddr = t->loc[pos].addr;
		if (track->addr == caddr) {

			l = &t->loc[pos];
			l->count++;
			if (track->when) {
				l->sum_time += age;
				if (age < l->min_time)
					l->min_time = age;
				if (age > l->max_time)
					l->max_time = age;

				if (track->pid < l->min_pid)
					l->min_pid = track->pid;
				if (track->pid > l->max_pid)
					l->max_pid = track->pid;

				cpu_set(track->cpu, l->cpus);
			}
			node_set(page_to_nid(virt_to_page(track)), l->nodes);
			return 1;
		}

		if (track->addr < caddr)
			end = pos;
		else
			start = pos;
	}

	/*
	 * Not found. Insert new tracking element.
	 */
	if (t->count >= t->max && !alloc_loc_track(t, 2 * t->max, GFP_ATOMIC))
		return 0;

	l = t->loc + pos;
	if (pos < t->count)
		memmove(l + 1, l,
			(t->count - pos) * sizeof(struct location));
	t->count++;
	l->count = 1;
	l->addr = track->addr;
	l->sum_time = age;
	l->min_time = age;
	l->max_time = age;
	l->min_pid = track->pid;
	l->max_pid = track->pid;
	cpus_clear(l->cpus);
	cpu_set(track->cpu, l->cpus);
	nodes_clear(l->nodes);
	node_set(page_to_nid(virt_to_page(track)), l->nodes);
	return 1;
}

static void process_slab(struct loc_track *t, struct kmem_cache *s,
		struct page *page, enum track_item alloc)
{
	void *addr = page_address(page);
	DECLARE_BITMAP(map, s->objects);
	void *p;

	bitmap_zero(map, s->objects);
	for_each_free_object(p, s, page->freelist)
		set_bit(slab_index(p, s, addr), map);

	for_each_object(p, s, addr)
		if (!test_bit(slab_index(p, s, addr), map))
			add_location(t, s, get_track(s, p, alloc));
}

static int list_locations(struct kmem_cache *s, char *buf,
					enum track_item alloc)
{
	int n = 0;
	unsigned long i;
	struct loc_track t = { 0, 0, NULL };
	int node;

	if (!alloc_loc_track(&t, PAGE_SIZE / sizeof(struct location),
			GFP_TEMPORARY))
		return sprintf(buf, "Out of memory\n");

	/* Push back cpu slabs */
	flush_all(s);

	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = get_node(s, node);
		unsigned long flags;
		struct page *page;

		if (!atomic_long_read(&n->nr_slabs))
			continue;

		spin_lock_irqsave(&n->list_lock, flags);
		list_for_each_entry(page, &n->partial, lru)
			process_slab(&t, s, page, alloc);
		list_for_each_entry(page, &n->full, lru)
			process_slab(&t, s, page, alloc);
		spin_unlock_irqrestore(&n->list_lock, flags);
	}

	for (i = 0; i < t.count; i++) {
		struct location *l = &t.loc[i];

		if (n > PAGE_SIZE - 100)
			break;
		n += sprintf(buf + n, "%7ld ", l->count);

		if (l->addr)
			n += sprint_symbol(buf + n, (unsigned long)l->addr);
		else
			n += sprintf(buf + n, "<not-available>");

		if (l->sum_time != l->min_time) {
			unsigned long remainder;

			n += sprintf(buf + n, " age=%ld/%ld/%ld",
			l->min_time,
			div_long_long_rem(l->sum_time, l->count, &remainder),
			l->max_time);
		} else
			n += sprintf(buf + n, " age=%ld",
				l->min_time);

		if (l->min_pid != l->max_pid)
			n += sprintf(buf + n, " pid=%ld-%ld",
				l->min_pid, l->max_pid);
		else
			n += sprintf(buf + n, " pid=%ld",
				l->min_pid);

		if (num_online_cpus() > 1 && !cpus_empty(l->cpus) &&
				n < PAGE_SIZE - 60) {
			n += sprintf(buf + n, " cpus=");
			n += cpulist_scnprintf(buf + n, PAGE_SIZE - n - 50,
					l->cpus);
		}

		if (num_online_nodes() > 1 && !nodes_empty(l->nodes) &&
				n < PAGE_SIZE - 60) {
			n += sprintf(buf + n, " nodes=");
			n += nodelist_scnprintf(buf + n, PAGE_SIZE - n - 50,
					l->nodes);
		}

		n += sprintf(buf + n, "\n");
	}

	free_loc_track(&t);
	if (!t.count)
		n += sprintf(buf, "No data\n");
	return n;
}

enum slab_stat_type {
	SL_FULL,
	SL_PARTIAL,
	SL_CPU,
	SL_OBJECTS
};

#define SO_FULL		(1 << SL_FULL)
#define SO_PARTIAL	(1 << SL_PARTIAL)
#define SO_CPU		(1 << SL_CPU)
#define SO_OBJECTS	(1 << SL_OBJECTS)

static unsigned long slab_objects(struct kmem_cache *s,
			char *buf, unsigned long flags)
{
	unsigned long total = 0;
	int cpu;
	int node;
	int x;
	unsigned long *nodes;
	unsigned long *per_cpu;

	nodes = kzalloc(2 * sizeof(unsigned long) * nr_node_ids, GFP_KERNEL);
	per_cpu = nodes + nr_node_ids;

	for_each_possible_cpu(cpu) {
		struct page *page;
		int node;
		struct kmem_cache_cpu *c = get_cpu_slab(s, cpu);

		if (!c)
			continue;

		page = c->page;
		node = c->node;
		if (node < 0)
			continue;
		if (page) {
			if (flags & SO_CPU) {
				int x = 0;

				if (flags & SO_OBJECTS)
					x = page->inuse;
				else
					x = 1;
				total += x;
				nodes[node] += x;
			}
			per_cpu[node]++;
		}
	}

	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = get_node(s, node);

		if (flags & SO_PARTIAL) {
			if (flags & SO_OBJECTS)
				x = count_partial(n);
			else
				x = n->nr_partial;
			total += x;
			nodes[node] += x;
		}

		if (flags & SO_FULL) {
			int full_slabs = atomic_long_read(&n->nr_slabs)
					- per_cpu[node]
					- n->nr_partial;

			if (flags & SO_OBJECTS)
				x = full_slabs * s->objects;
			else
				x = full_slabs;
			total += x;
			nodes[node] += x;
		}
	}

	x = sprintf(buf, "%lu", total);
#ifdef CONFIG_NUMA
	for_each_node_state(node, N_NORMAL_MEMORY)
		if (nodes[node])
			x += sprintf(buf + x, " N%d=%lu",
					node, nodes[node]);
#endif
	kfree(nodes);
	return x + sprintf(buf + x, "\n");
}

static int any_slab_objects(struct kmem_cache *s)
{
	int node;
	int cpu;

	for_each_possible_cpu(cpu) {
		struct kmem_cache_cpu *c = get_cpu_slab(s, cpu);

		if (c && c->page)
			return 1;
	}

	for_each_online_node(node) {
		struct kmem_cache_node *n = get_node(s, node);

		if (!n)
			continue;

		if (n->nr_partial || atomic_long_read(&n->nr_slabs))
			return 1;
	}
	return 0;
}

#define to_slab_attr(n) container_of(n, struct slab_attribute, attr)
#define to_slab(n) container_of(n, struct kmem_cache, kobj);

struct slab_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kmem_cache *s, char *buf);
	ssize_t (*store)(struct kmem_cache *s, const char *x, size_t count);
};

#define SLAB_ATTR_RO(_name) \
	static struct slab_attribute _name##_attr = __ATTR_RO(_name)

#define SLAB_ATTR(_name) \
	static struct slab_attribute _name##_attr =  \
	__ATTR(_name, 0644, _name##_show, _name##_store)

static ssize_t slab_size_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->size);
}
SLAB_ATTR_RO(slab_size);

static ssize_t align_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->align);
}
SLAB_ATTR_RO(align);

static ssize_t object_size_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->objsize);
}
SLAB_ATTR_RO(object_size);

static ssize_t objs_per_slab_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->objects);
}
SLAB_ATTR_RO(objs_per_slab);

static ssize_t order_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->order);
}
SLAB_ATTR_RO(order);

static ssize_t ctor_show(struct kmem_cache *s, char *buf)
{
	if (s->ctor) {
		int n = sprint_symbol(buf, (unsigned long)s->ctor);

		return n + sprintf(buf + n, "\n");
	}
	return 0;
}
SLAB_ATTR_RO(ctor);

static ssize_t aliases_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->refcount - 1);
}
SLAB_ATTR_RO(aliases);

static ssize_t slabs_show(struct kmem_cache *s, char *buf)
{
	return slab_objects(s, buf, SO_FULL|SO_PARTIAL|SO_CPU);
}
SLAB_ATTR_RO(slabs);

static ssize_t partial_show(struct kmem_cache *s, char *buf)
{
	return slab_objects(s, buf, SO_PARTIAL);
}
SLAB_ATTR_RO(partial);

static ssize_t cpu_slabs_show(struct kmem_cache *s, char *buf)
{
	return slab_objects(s, buf, SO_CPU);
}
SLAB_ATTR_RO(cpu_slabs);

static ssize_t objects_show(struct kmem_cache *s, char *buf)
{
	return slab_objects(s, buf, SO_FULL|SO_PARTIAL|SO_CPU|SO_OBJECTS);
}
SLAB_ATTR_RO(objects);

static ssize_t sanity_checks_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_DEBUG_FREE));
}

static ssize_t sanity_checks_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	s->flags &= ~SLAB_DEBUG_FREE;
	if (buf[0] == '1')
		s->flags |= SLAB_DEBUG_FREE;
	return length;
}
SLAB_ATTR(sanity_checks);

static ssize_t trace_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_TRACE));
}

static ssize_t trace_store(struct kmem_cache *s, const char *buf,
							size_t length)
{
	s->flags &= ~SLAB_TRACE;
	if (buf[0] == '1')
		s->flags |= SLAB_TRACE;
	return length;
}
SLAB_ATTR(trace);

static ssize_t reclaim_account_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_RECLAIM_ACCOUNT));
}

static ssize_t reclaim_account_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	s->flags &= ~SLAB_RECLAIM_ACCOUNT;
	if (buf[0] == '1')
		s->flags |= SLAB_RECLAIM_ACCOUNT;
	return length;
}
SLAB_ATTR(reclaim_account);

static ssize_t hwcache_align_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_HWCACHE_ALIGN));
}
SLAB_ATTR_RO(hwcache_align);

#ifdef CONFIG_ZONE_DMA
static ssize_t cache_dma_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_CACHE_DMA));
}
SLAB_ATTR_RO(cache_dma);
#endif

static ssize_t destroy_by_rcu_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_DESTROY_BY_RCU));
}
SLAB_ATTR_RO(destroy_by_rcu);

static ssize_t red_zone_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_RED_ZONE));
}

static ssize_t red_zone_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	if (any_slab_objects(s))
		return -EBUSY;

	s->flags &= ~SLAB_RED_ZONE;
	if (buf[0] == '1')
		s->flags |= SLAB_RED_ZONE;
	calculate_sizes(s);
	return length;
}
SLAB_ATTR(red_zone);

static ssize_t poison_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_POISON));
}

static ssize_t poison_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	if (any_slab_objects(s))
		return -EBUSY;

	s->flags &= ~SLAB_POISON;
	if (buf[0] == '1')
		s->flags |= SLAB_POISON;
	calculate_sizes(s);
	return length;
}
SLAB_ATTR(poison);

static ssize_t store_user_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_STORE_USER));
}

static ssize_t store_user_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	if (any_slab_objects(s))
		return -EBUSY;

	s->flags &= ~SLAB_STORE_USER;
	if (buf[0] == '1')
		s->flags |= SLAB_STORE_USER;
	calculate_sizes(s);
	return length;
}
SLAB_ATTR(store_user);

static ssize_t validate_show(struct kmem_cache *s, char *buf)
{
	return 0;
}

static ssize_t validate_store(struct kmem_cache *s,
			const char *buf, size_t length)
{
	int ret = -EINVAL;

	if (buf[0] == '1') {
		ret = validate_slab_cache(s);
		if (ret >= 0)
			ret = length;
	}
	return ret;
}
SLAB_ATTR(validate);

static ssize_t shrink_show(struct kmem_cache *s, char *buf)
{
	return 0;
}

static ssize_t shrink_store(struct kmem_cache *s,
			const char *buf, size_t length)
{
	if (buf[0] == '1') {
		int rc = kmem_cache_shrink(s);

		if (rc)
			return rc;
	} else
		return -EINVAL;
	return length;
}
SLAB_ATTR(shrink);

static ssize_t alloc_calls_show(struct kmem_cache *s, char *buf)
{
	if (!(s->flags & SLAB_STORE_USER))
		return -ENOSYS;
	return list_locations(s, buf, TRACK_ALLOC);
}
SLAB_ATTR_RO(alloc_calls);

static ssize_t free_calls_show(struct kmem_cache *s, char *buf)
{
	if (!(s->flags & SLAB_STORE_USER))
		return -ENOSYS;
	return list_locations(s, buf, TRACK_FREE);
}
SLAB_ATTR_RO(free_calls);

#ifdef CONFIG_NUMA
static ssize_t defrag_ratio_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->defrag_ratio / 10);
}

static ssize_t defrag_ratio_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	int n = simple_strtoul(buf, NULL, 10);

	if (n < 100)
		s->defrag_ratio = n * 10;
	return length;
}
SLAB_ATTR(defrag_ratio);
#endif

static struct attribute * slab_attrs[] = {
	&slab_size_attr.attr,
	&object_size_attr.attr,
	&objs_per_slab_attr.attr,
	&order_attr.attr,
	&objects_attr.attr,
	&slabs_attr.attr,
	&partial_attr.attr,
	&cpu_slabs_attr.attr,
	&ctor_attr.attr,
	&aliases_attr.attr,
	&align_attr.attr,
	&sanity_checks_attr.attr,
	&trace_attr.attr,
	&hwcache_align_attr.attr,
	&reclaim_account_attr.attr,
	&destroy_by_rcu_attr.attr,
	&red_zone_attr.attr,
	&poison_attr.attr,
	&store_user_attr.attr,
	&validate_attr.attr,
	&shrink_attr.attr,
	&alloc_calls_attr.attr,
	&free_calls_attr.attr,
#ifdef CONFIG_ZONE_DMA
	&cache_dma_attr.attr,
#endif
#ifdef CONFIG_NUMA
	&defrag_ratio_attr.attr,
#endif
	NULL
};

static struct attribute_group slab_attr_group = {
	.attrs = slab_attrs,
};

static ssize_t slab_attr_show(struct kobject *kobj,
				struct attribute *attr,
				char *buf)
{
	struct slab_attribute *attribute;
	struct kmem_cache *s;
	int err;

	attribute = to_slab_attr(attr);
	s = to_slab(kobj);

	if (!attribute->show)
		return -EIO;

	err = attribute->show(s, buf);

	return err;
}

static ssize_t slab_attr_store(struct kobject *kobj,
				struct attribute *attr,
				const char *buf, size_t len)
{
	struct slab_attribute *attribute;
	struct kmem_cache *s;
	int err;

	attribute = to_slab_attr(attr);
	s = to_slab(kobj);

	if (!attribute->store)
		return -EIO;

	err = attribute->store(s, buf, len);

	return err;
}

static struct sysfs_ops slab_sysfs_ops = {
	.show = slab_attr_show,
	.store = slab_attr_store,
};

static struct kobj_type slab_ktype = {
	.sysfs_ops = &slab_sysfs_ops,
};

static int uevent_filter(struct kset *kset, struct kobject *kobj)
{
	struct kobj_type *ktype = get_ktype(kobj);

	if (ktype == &slab_ktype)
		return 1;
	return 0;
}

static struct kset_uevent_ops slab_uevent_ops = {
	.filter = uevent_filter,
};

static decl_subsys(slab, &slab_ktype, &slab_uevent_ops);

#define ID_STR_LENGTH 64

/* Create a unique string id for a slab cache:
 * format
 * :[flags-]size:[memory address of kmemcache]
 */
static char *create_unique_id(struct kmem_cache *s)
{
	char *name = kmalloc(ID_STR_LENGTH, GFP_KERNEL);
	char *p = name;

	BUG_ON(!name);

	*p++ = ':';
	/*
	 * First flags affecting slabcache operations. We will only
	 * get here for aliasable slabs so we do not need to support
	 * too many flags. The flags here must cover all flags that
	 * are matched during merging to guarantee that the id is
	 * unique.
	 */
	if (s->flags & SLAB_CACHE_DMA)
		*p++ = 'd';
	if (s->flags & SLAB_RECLAIM_ACCOUNT)
		*p++ = 'a';
	if (s->flags & SLAB_DEBUG_FREE)
		*p++ = 'F';
	if (p != name + 1)
		*p++ = '-';
	p += sprintf(p, "%07d", s->size);
	BUG_ON(p > name + ID_STR_LENGTH - 1);
	return name;
}

static int sysfs_slab_add(struct kmem_cache *s)
{
	int err;
	const char *name;
	int unmergeable;

	if (slab_state < SYSFS)
		/* Defer until later */
		return 0;

	unmergeable = slab_unmergeable(s);
	if (unmergeable) {
		/*
		 * Slabcache can never be merged so we can use the name proper.
		 * This is typically the case for debug situations. In that
		 * case we can catch duplicate names easily.
		 */
		sysfs_remove_link(&slab_subsys.kobj, s->name);
		name = s->name;
	} else {
		/*
		 * Create a unique name for the slab as a target
		 * for the symlinks.
		 */
		name = create_unique_id(s);
	}

	kobj_set_kset_s(s, slab_subsys);
	kobject_set_name(&s->kobj, name);
	kobject_init(&s->kobj);
	err = kobject_add(&s->kobj);
	if (err)
		return err;

	err = sysfs_create_group(&s->kobj, &slab_attr_group);
	if (err)
		return err;
	kobject_uevent(&s->kobj, KOBJ_ADD);
	if (!unmergeable) {
		/* Setup first alias */
		sysfs_slab_alias(s, s->name);
		kfree(name);
	}
	return 0;
}

static void sysfs_slab_remove(struct kmem_cache *s)
{
	kobject_uevent(&s->kobj, KOBJ_REMOVE);
	kobject_del(&s->kobj);
}

/*
 * Need to buffer aliases during bootup until sysfs becomes
 * available lest we loose that information.
 */
struct saved_alias {
	struct kmem_cache *s;
	const char *name;
	struct saved_alias *next;
};

static struct saved_alias *alias_list;

static int sysfs_slab_alias(struct kmem_cache *s, const char *name)
{
	struct saved_alias *al;

	if (slab_state == SYSFS) {
		/*
		 * If we have a leftover link then remove it.
		 */
		sysfs_remove_link(&slab_subsys.kobj, name);
		return sysfs_create_link(&slab_subsys.kobj,
						&s->kobj, name);
	}

	al = kmalloc(sizeof(struct saved_alias), GFP_KERNEL);
	if (!al)
		return -ENOMEM;

	al->s = s;
	al->name = name;
	al->next = alias_list;
	alias_list = al;
	return 0;
}

static int __init slab_sysfs_init(void)
{
	struct kmem_cache *s;
	int err;

	err = subsystem_register(&slab_subsys);
	if (err) {
		printk(KERN_ERR "Cannot register slab subsystem.\n");
		return -ENOSYS;
	}

	slab_state = SYSFS;

	list_for_each_entry(s, &slab_caches, list) {
		err = sysfs_slab_add(s);
		if (err)
			printk(KERN_ERR "SLUB: Unable to add boot slab %s"
						" to sysfs\n", s->name);
	}

	while (alias_list) {
		struct saved_alias *al = alias_list;

		alias_list = alias_list->next;
		err = sysfs_slab_alias(al->s, al->name);
		if (err)
			printk(KERN_ERR "SLUB: Unable to add boot slab alias"
					" %s to sysfs\n", s->name);
		kfree(al);
	}

	resiliency_test();
	return 0;
}

__initcall(slab_sysfs_init);
#endif

/*
 * The /proc/slabinfo ABI
 */
#ifdef CONFIG_SLABINFO

ssize_t slabinfo_write(struct file *file, const char __user * buffer,
                       size_t count, loff_t *ppos)
{
	return -EINVAL;
}


static void print_slabinfo_header(struct seq_file *m)
{
	seq_puts(m, "slabinfo - version: 2.1\n");
	seq_puts(m, "# name            <active_objs> <num_objs> <objsize> "
		 "<objperslab> <pagesperslab>");
	seq_puts(m, " : tunables <limit> <batchcount> <sharedfactor>");
	seq_puts(m, " : slabdata <active_slabs> <num_slabs> <sharedavail>");
	seq_putc(m, '\n');
}

static void *s_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	down_read(&slub_lock);
	if (!n)
		print_slabinfo_header(m);

	return seq_list_start(&slab_caches, *pos);
}

static void *s_next(struct seq_file *m, void *p, loff_t *pos)
{
	return seq_list_next(p, &slab_caches, pos);
}

static void s_stop(struct seq_file *m, void *p)
{
	up_read(&slub_lock);
}

static int s_show(struct seq_file *m, void *p)
{
	unsigned long nr_partials = 0;
	unsigned long nr_slabs = 0;
	unsigned long nr_inuse = 0;
	unsigned long nr_objs;
	struct kmem_cache *s;
	int node;

	s = list_entry(p, struct kmem_cache, list);

	for_each_online_node(node) {
		struct kmem_cache_node *n = get_node(s, node);

		if (!n)
			continue;

		nr_partials += n->nr_partial;
		nr_slabs += atomic_long_read(&n->nr_slabs);
		nr_inuse += count_partial(n);
	}

	nr_objs = nr_slabs * s->objects;
	nr_inuse += (nr_slabs - nr_partials) * s->objects;

	seq_printf(m, "%-17s %6lu %6lu %6u %4u %4d", s->name, nr_inuse,
		   nr_objs, s->size, s->objects, (1 << s->order));
	seq_printf(m, " : tunables %4u %4u %4u", 0, 0, 0);
	seq_printf(m, " : slabdata %6lu %6lu %6lu", nr_slabs, nr_slabs,
		   0UL);
	seq_putc(m, '\n');
	return 0;
}

const struct seq_operations slabinfo_op = {
	.start = s_start,
	.next = s_next,
	.stop = s_stop,
	.show = s_show,
};

#endif /* CONFIG_SLABINFO */
