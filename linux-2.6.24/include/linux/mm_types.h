#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/auxvec.h>
#include <linux/types.h>
#include <linux/threads.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/prio_tree.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <asm/page.h>
#include <asm/mmu.h>

#ifndef AT_VECTOR_SIZE_ARCH
#define AT_VECTOR_SIZE_ARCH 0
#endif
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

struct address_space;

#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
typedef atomic_long_t mm_counter_t;
#else  /* NR_CPUS < CONFIG_SPLIT_PTLOCK_CPUS */
typedef unsigned long mm_counter_t;
#endif /* NR_CPUS < CONFIG_SPLIT_PTLOCK_CPUS */

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 */
/* 物理页框描述符 */
struct page {
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	atomic_t _count;		/* Usage count, see below. */
	union {
		/**
		 * 存放引用页框的页表项数量
		 * 计数器的起始值为-1，表示没有页表项引用改页框
		 * 如果值为0，表示页是非共享的，如果值大于1，则表示页是共享的
		 */
		atomic_t _mapcount;	/* Count of ptes mapped in mms,
					 * to show when page is mapped
					 * & limit reverse map searches.
					 */
		unsigned int inuse;	/* SLUB: Nr of objects */
	};
	union {
	    struct {
		unsigned long private;		/* Mapping-private opaque data:
					 	 * usually used for buffer_heads
						 * if PagePrivate set; used for
						 * swp_entry_t if PageSwapCache;
						 * indicates order in the buddy
						 * system if PG_buddy is set.
						 */
		/**
		 * 用于确定页是映射的还是匿名的
		 *
		 * 如果mapping字段为空，则该页属于交换高速缓存
		 * 如果mapping字段非空，且最低位为1，则该页为匿名页，同时mapping字段中存放的是指向anon_vma描述符的指针
		 * 	1、匿名线性区分配首个物理页帧时创建anon_vma；
		 * 	2、再将线性区vma_area_struct挂入anon_vma的head双向链表，同时设置该页帧描述符page的mapping字段值为anon_vma的地址；
		 * 	3、该匿名线性区后续分配物理页帧时，直接将对应页描述符page的mapping字段值设置为该anon_vma地址即可；
		 * 	4、如果另一个进程需要引用该页框时，内核将第二个进程的匿名线性区插入该anon_vma数据结构的双向循环链表中；
		 * 如果mapping字段非空，且最低位为0，则该页为映射页，同时mapping字段中存放的是指向对应文件的address_space对象指向
		 * (指针的其实地址最少需要按4字节对齐，因此mapping字段的最低位可用作一个标志位来表示该字段的指针是指向address_space还是anon_vma)
		 */
		struct address_space *mapping;	/* If low bit clear, points to
						 * inode address_space, or NULL.
						 * If page mapped as anonymous
						 * memory, low bit is set, and
						 * it points to anon_vma object:
						 * see PAGE_MAPPING_ANON below.
						 */
	    };
#if NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS
	    spinlock_t ptl;
#endif
	    struct kmem_cache *slab;	/* SLUB: Pointer to slab */
	    struct page *first_page;	/* Compound tail pages */
	};
	union {
		pgoff_t index;		/* Our offset within mapping. */
		void *freelist;		/* SLUB: freelist req. slab lock */
	};
	struct list_head lru;		/* Pageout list, eg. active_list
					 * protected by zone->lru_lock !
					 */
	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */
};

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
/* 进程线性地址区描述符 */
struct vm_area_struct {
	/* 指向线性地址区所在的内存描述符 */
	struct mm_struct * vm_mm;	/* The address space we belong to. */
	/* 线性地址区内的第一个线性地址 */
	unsigned long vm_start;		/* Our start address within vm_mm. */
	/* 线性地址区之后的第一个线性地址 */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	/* 指向进程线性地址空间的下一个线性地址区
	 * 进程所拥有的所有线性区是按内存地址的升序排列，并通过一个简单的链表链接在一起的
	 */
	struct vm_area_struct *vm_next;

	/* 线性地址区中页框的访问权限 */
	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	unsigned long vm_flags;		/* Flags, listed below. */

	/*
	 * 红-黑树节点，链接进程线性地址区组成的红-黑树
	 * 当进程的线性区数量较多时，从简单链表中查找包含指定线性地址的线性区将比较耗时，链表管理相当低效
	 * 因此，维护简单链表的同时，内核也将线性地址区存放在红-黑树中，通过红-黑树查找特定线性区非常高效，
	 * 而链表通常用在扫描整个线性地址区集合时
	 */
	struct rb_node vm_rb;

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap prio tree, or
	 * linkage to the list of like vmas hanging off its node, or
	 * linkage of vma in the address_space->i_mmap_nonlinear list.
	 */
	/*
	 * 用于链接建立文件某一区域与该区域被映射的所有虚拟地址空间之间的关联的优先查找树
	 *
	 * 1、当文件的某一区域只存在一个虚拟地址空间与之映射时，直接将prio_tree_node作为树结点挂入
	 * 2、当文件的某一区域存在多个虚拟地址空间与之映射时，则将一个vm_set对象作为树结点挂入，
	 * 此时vm_set.head字段指向映射该文件区域的虚拟地址区列表的首个对象，整个列表再由各个地址区的vm_set.list串接
	 */
	union {
		struct {
			/* list、parent 和 prio_tree_node占用内存完全重叠，可通过parent != NULL判断是否已经在优先查找树中 */
			struct list_head list;
			void *parent;	/* aligns with prio_tree_node parent */
			struct vm_area_struct *head;
		} vm_set;

		/*
		 * 优先查找树结点
		 * 当要查找映射文件中某一区域的所有虚拟地址区间时,
		 * 可直接通过遍历vm_file->f_mapping->i_mmap优先查找树实现
		 */
		struct raw_prio_tree_node prio_tree_node;
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	struct list_head anon_vma_node;	/* Serialized by anon_vma->lock */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	struct vm_operations_struct * vm_ops;

	/* Information about our backing store: */
	/**
	 * 如果是匿名线性区，该字段是0或者vm_start/PAGE_SIZE
	 * 如果是文件映射区，该字段为被映射文件的线性区偏移量
	 */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units, *not* PAGE_CACHE_SIZE */
	/* 指向file实例，描述一个被映射的文件，如果映射的对象不是文件，则为NULL指针 */
	struct file * vm_file;		/* File we map to (can be NULL). */
	void * vm_private_data;		/* was vm_pte (shared mem) */
	unsigned long vm_truncate_count;/* truncate_count or restart_addr */

#ifndef CONFIG_MMU
	atomic_t vm_usage;		/* refcount (VMAs shared if !MMU) */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
};

/* 包含与进程地址空间有关的全部信息的内存描述符 */
struct mm_struct {
	/* 指向进程线性地址区对象的链表头 */
	struct vm_area_struct * mmap;		/* list of VMAs */
	/* 指向进程线性地址区对象的红-黑树的根节点 */
	struct rb_root mm_rb;
	/* 指向最后一个引用的进程线性地址区对象 */
	struct vm_area_struct * mmap_cache;	/* last find_vma result */
	/* 在进程地址空间中搜索有效线性地址区间的方法 */
	unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
	void (*unmap_area) (struct mm_struct *mm, unsigned long addr);
	unsigned long mmap_base;		/* base of mmap area */
	unsigned long task_size;		/* size of task vm space */
	/*
	 * 存放前一次线性区查找成功前遍历过的不满足分配的所有间隙（两线性区的中间区域）的最大长度
	 * 新查找线性区的长度若大于该值，则直接从最后一次分配的线性区尾部开始查找即可，因该地址之前所有间隙都不满足分配
	 * 可用于减少不必要的线性区遍历
	 */
	unsigned long cached_hole_size; 	/* if non-zero, the largest hole below free_area_cache */
	/* 存放前一次线性区分配时，新线性区起始地址 + 新线性区长度的地址，结合cached_hole_size快速确定线性区遍历起始地址 */
	unsigned long free_area_cache;		/* first hole of size cached_hole_size or larger */
	/* 指向页全局目录 */
	pgd_t * pgd;
	/* 存放共享mm_struc的轻量级进程的个数 */
	atomic_t mm_users;			/* How many users with user space? */
	atomic_t mm_count;			/* How many references to "struct mm_struct" (users count as 1) */
	/* 进程线性地址区的个数 */
	int map_count;				/* number of VMAs */
	struct rw_semaphore mmap_sem;
	spinlock_t page_table_lock;		/* Protects page tables and some counters */

	/* 所有内存描述符存放在一个双向链表中，链表中的第一个元素是init_mm的mm_list字段 */
	struct list_head mmlist;		/* List of maybe swapped mm's.	These are globally strung
						 * together off init_mm.mmlist, and are protected
						 * by mmlist_lock
						 */

	/* Special counters, in some configurations protected by the
	 * page_table_lock, in other configurations by being atomic.
	 */
	mm_counter_t _file_rss;
	mm_counter_t _anon_rss;

	unsigned long hiwater_rss;	/* High-watermark of RSS usage */
	unsigned long hiwater_vm;	/* High-water virtual memory usage */

	/*
	 * total_vm：进程地址空间的页数
	 * locked_vm：“锁住”不能换出的页数
	 * shared_vm：共享文件内存映射的页数
	 * exec_vm：可执行内存映射的页数
	 */
	unsigned long total_vm, locked_vm, shared_vm, exec_vm;
	/*
	 * stack_vm：用户态堆栈的页数
	 * reserved_vm：在保留区中的页数或在特殊线性区中的页数
	 */
	unsigned long stack_vm, reserved_vm, def_flags, nr_ptes;
	/*
	 * start_code：可执行代码的起始线性地址
	 * end_code：可执行代码的结束线性地址
	 * start_data：已初始化数据的起始线性地址
	 * end_data：已初始化数据的结束线性地址
	 */
	unsigned long start_code, end_code, start_data, end_data;
	/*
	 * start_brk：堆的起始线性地址
	 * brk：堆当前的末尾线性地址
	 * start_stack：堆栈的起始线性地址
	 */
	unsigned long start_brk, brk, start_stack;
	/*
	 * arg_start：命令行参数的起始线性地址
	 * arg_end：命令行参数的结束线性地址
	 * env_start：环境变量的起始线性地址
	 * env_end：环境变量的结束线性地址
	 */
	unsigned long arg_start, arg_end, env_start, env_end;

	unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

	cpumask_t cpu_vm_mask;

	/* Architecture-specific MM context */
	mm_context_t context;

	/* Swap token stuff */
	/*
	 * Last value of global fault stamp as seen by this process.
	 * In other words, this value gives an indication of how long
	 * it has been since this task got the token.
	 * Look at mm/thrash.c
	 */
	unsigned int faultstamp;
	unsigned int token_priority;
	unsigned int last_interval;

	unsigned long flags; /* Must use atomic bitops to access the bits */

	/* coredumping support */
	int core_waiters;
	struct completion *core_startup_done, core_done;

	/* aio bits */
	rwlock_t		ioctx_list_lock;
	struct kioctx		*ioctx_list;
};

#endif /* _LINUX_MM_TYPES_H */
