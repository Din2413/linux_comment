linux code comment for 2.6.24

在对linux 2.6.24进行注释的同时，总结输出自己对于各个内核模块的理解。

持续不断更新......

# 内存管理

## 内核空间

### 内存划分

- 物理内存

  - 内存节点 node

    对于大型机器而言，内存会被分成许多簇，依据簇与处理器“距离”的不同，访问不同的簇所花费的代价（时间）也不同，每个簇都被认为是一个节点。


    - UMA 一致性内存访问

      系统中只存在一个内存节点，不同处理器到内存节点的访问时间相同，同一处理器到内存节点的不同区域的访问时间也相同。

    - NUMA 非一致性内存访问

      系统内存在多个内存节点，不同处理器到同一内存节点的访问时间不相同，同一处理器到不同内存节点的访问时间也不相同，但同一处理器到同一内存节点的不同区域访问时间相同。

  - 内存管理区 zone

    因实际的计算机体系结构有硬件的诸多限制，比如：ISA总线的直接内存寻址DMA只能对RAM的前16MB寻址、具有大容量RAM的32位计算机中CPU无法直接通过逻辑地址线性映射到所有的物理地址等，从而限制了页框的使用方式，因此Linux内核对不同区域的内存需要采用不同的管理方式和映射机制。

    因此，Linux中每个内存节点又被分成很多称为管理区（zone）的块，用于表示内存的某个范围。


    - 水位线

      每个管理区都存在三个极值，分别为pages_low、pages_min和pages_high，这些极值用于跟踪一个管理区承受了多大的压力，以此决定系统唤醒进程释放页面的频繁程度。


      - high watermark

        内存管理区高水位线，表示系统目前空闲内存充足，被唤醒释放内存的kswapd将再次睡眠。

      - low watermark

        内存管理区低水位线，表示系统空间内存紧张，到达该水位线时，会唤醒kswapd异步进行内存回收，直到内存重新回到high watermark水位线再将kswapd睡眠。

      - min watermark

        内存管理区最小水位线，低于该水位线时，表示系统空闲内存极度紧张，此时不再仅依靠kswapd异步回收内存，而是会在内存分配途中对内存进行同步回收，即伙伴分配器将以同步方式进行页面释放（direct-reclaim）。

    - 类别

      不同管理区类型适合不同类型的用途。


      - DMA zone

        低端范围的物理内存，用于外设直接内存访问。

      - Normal zone

        由内核直接映射到线性地址空间的较高部分。

      - Highmem zone

        高端内存，系统中预留的可用内存空间，不被内核直接映射。

  - 物理页帧 page

    在管理区之上，系统内存进一步划分成大小确定的页面，通过页表与虚拟内存的页进行映射。

- 虚拟内存

  虚拟内存可以让每个进程都有属于自己的虚拟地址空间。从用户角度来看，地址空间是一个平坦的线性地址空间，由两部分组成：一个是随上下文切换而改变的用户空间部分，一个是保持不变的内核空间部分。

  虚拟内存与物理内存之间的映射通过页表实现。


  - 页表

    页表的级数越高每次获取虚拟内存存储在真实物理内存中的数据所需要进行的访存操作也就越多，如三级页表获取指定虚拟地址存储的数据需要三次访存操作，因此为减少虚拟地址到物理地址转换过程中访存次数，引入TLB页表缓存机制。

    Linux采用一种同时适用于32位和64位系统，且与具体的体系结构无关的普通分页模型。对于32位系统，二级页表足够，但对于64位系统，二级页表只能映射到4GB的内存空间，因此需要更多数量的分页级别。直到2.6.10版本，Linux采用三级分页模型，而从2.6.11版本开始，Linux采用四级分页模型；

    四级分页模型四种页表分别为：页全局目录、页上级目录、页中间目录、页表；

    在四级分页模型中，页全局目录包含若干页上级目录的地址，页上级目录又依次包含若干页中间目录的地址，而页中间目录有包含若干页表的地址，每个页表项指向一个页框。在这种模型中，线性地址被分成五个部分，分别为“页全局目录偏移”、“页上级目录偏移”、“页中间目录偏移”、“页表项偏移”、“页框偏移”，每一部分的大小与具体的计算机体系结构有关。

    对于没有开启物理地址扩展的32位系统，二级页表足够使用。此时，Linux可将线性地址中的“页上级目录偏移”位和“页中间目录偏移”位设置为0，从根本上消除页上级目录和页中间目录字段。当需要采用三级页表实现虚拟内存转换时，也可采用类似方式将“页上级目录偏移”或“页中间目录偏移”位设置为0，以消除多余一级的页目录转换。

  - TLB缓存

    由于从虚拟地址转换成物理地址的开销较大，因此引入TLB（Translation Look-aside Buffer，地址变换高速缓存，简称快表）缓存机制减少访存操作，提供系统整体性能。具体实现后续研究。

### 内存映射

- 低端内存映射

  dma、normal zone

  - 直接映射

- 高端内存映射

  highmem zone

  - 永久映射
  - 临时映射

### 内存分配

- 连续内存

  - 按页分配

    alloc_pages

    - 伙伴系统

      按页管理物理内存，系统内存分配基础，所有可用内存均需通过伙伴系统管理后提供上层使。

  - 对象缓存

    通用对象缓存:kmalloc/kfree
    特殊对象缓存:kmem_cache_alloc/kmem_cache_free

    - slab分配器
    - slob分配器
    - slub分配器

- 非连续内存

  vmalloc/vfree

### 内存回收

- lru最近最少使用算法

  - active 活动链表

    从活动链表中筛选最近最少使用的页迁移至非活动链表

  - inactive 非活动链表

    从非活动链表中筛选内存页进行回收

    - 脏页写回

- 回收时机

  - 同步回收

    - MIN水位线不满足内存分配请求

  - 异步回收

    - LOW水位线唤醒kswap内核线程

## 进程空间

### 虚拟内存区

- 栈区

  自上而下增长

- mmap映射区

  mmap映射区位于栈区和堆区之间，且栈区自上而下增长，堆区自下而上增长。默认情况下，mmap区与堆一样，从堆区顶部开始自下而上增长（down_top），但这种进程空间分布会限制堆的可增长空闲必须位于mmap区之下，因此为放宽堆区的限制，引入另一个地址空间分布，即mmap区与栈一样，从栈区顶部开始自上而下增长（top_down）。

  如上，down_top会限制堆区扩展，而top_down则会限制栈区扩展，因此具体选择哪种空间分布因根据实际场景权衡选择

  - 文件映射

    虚拟内存区与某一文件映射，可通过内存方式直接读写文件。

  - 匿名映射

    虚拟内存区不与任一文件映射

- 堆区

  自上而下增长

- 数据区

- 代码区

### 内存分配

- malloc/free

- 延时分配

  初始只分配虚拟内存，将实际的物理内存分配推迟到真正需要访问时。

  虚拟内存状态:
  1.未分配；
  2.已分配、未映射；
  3.已映射、被换出不在内存中；
  4.已映射、在内存中；

- 写时复制

  最初创建子进程时，会对父进程做一次完全拷贝，这会增加不必要的内存拷贝工作，为解决该问题，引入写时复制机制。子进程只复制父进程的地址空间，而不拷贝实际的物理内存，且将共享内存写禁止，后续写时再通过缺页异常处理程序进行分配拷贝。

- 缺页异常

  因延迟分配、写时复制机制使得进程的虚拟内存可能并未与任何物理内存映射、或页权限与预期不匹配，当进程访问未映射的虚拟内存、或访问权限不匹配时，处理器会触发缺页异常，随后由缺页异常处理程序进行按需分页。

## 后续课题
1.内存水位线:high、low、min；</br>
2.内存映射:直接映射、永久映射、临时映射；</br>
3.内核空间内存分配:连续内存分配(伙伴系统、slab/slob/slub分配器)、非连续内存分配(vmalloc)；</br>
4.内存回收:回收时机、回收算法(扩展课题:磁盘页缓存、脏页回写)；</br>
5.进程地址空间:延时分配、mmap映射(匿名映射、文件映射)、elf目标文件(格式分析)；</br>
6:写时复制、缺页异常；