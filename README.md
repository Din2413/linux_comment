在对linux 2.6.24进行注释的同时，结合《深入理解Linux内核》（一年只啃这一本书）总结输出自己对于各个内核模块的理解。

持续不断更新......

# 内存管理

## 内核空间

### 内存划分

- 物理内存

  - 内存节点 node

    ​	对于大型机器而言，内存会被分成许多簇，依据簇与处理器“距离”的不同，访问不同的簇所花费的代价（时间）也不同，每个簇都被认为是一个节点。

    - UMA 一致性内存访问

      系统中只存在一个内存节点，不同处理器到内存节点的访问时间相同，同一处理器到内存节点的不同区域的访问时间也相同。

    - NUMA 非一致性内存访问

      系统内存在多个内存节点，不同处理器到同一内存节点的访问时间不相同，同一处理器到不同内存节点的访问时间也不相同，但同一处理器到同一内存节点的不同区域访问时间相同。

  - 内存管理区 zone

    ​	因实际的计算机体系结构有硬件的诸多限制，比如：80x86体系结构ISA总线的直接内存寻址DMA只能对RAM的前16MB寻址、具有大容量RAM的32位计算机中CPU无法直接通过逻辑地址线性映射到所有的物理地址等，从而限制了页框的使用方式，因此Linux内核把内存结点的物理内存划分成多个区域，对不同区域的内存需要采用不同的管理方式和映射机制。

    ​	这里的内存区域就是指管理区，用于表示内存的某个范围。

    - 类别

      不同管理区类型适合不同类型的用途。

      80x86 UMA体系结构中管理区划分为：
      1、ZONE_DMA 包含低于16MB的内存页框；
      2、ZONE_NORMAL 包含高于16MB且低于896MB的内存页框；
      3、ZONE_HIGHMEM 包含从896MB开始高于896MB的内存页框。

      其中`ZONE_DMA`和`ZONE_NORMAL`区包含内存的“常规”页框，内核可以对其进行直接访问（内核启动时已对这类管理区完成页表的线性映射）；而`ZONE_HIGHMEM`包含的内存页不能由内核直接访问，其必须先被非线性映射到地址空间，才能被内核访问。

      - DMA zone

        低端范围的物理内存，用于外设直接内存访问。

      - Normal zone

        由内核直接映射到线性地址空间的较高部分。

      - Highmem zone

        高端内存，系统中预留的可用内存空间，不被内核直接映射。

    - 水位线

      ​	每个管理区都存在三个极值，分别为pages_low、pages_min和pages_high，这些极值用于跟踪一个管理区承受了多大的压力，以此决定系统唤醒进程释放页面的频繁程度。

      - high watermark

        ​	内存管理区高水位线，表示系统目前空闲内存充足，被唤醒释放内存的`kswapd`将再次睡眠。

      - low watermark

        ​	内存管理区低水位线，表示系统空间内存紧张，到达该水位线时，会唤醒`kswapd`异步进行内存回收，直到内存重新回到high watermark水位线再将`kswapd`睡眠。

      - min watermark

        ​	内存管理区最小水位线，低于该水位线时，表示系统空闲内存极度紧张，此时不再仅依靠kswapd异步回收内存，而是会在内存分配途中对内存进行同步回收，即伙伴分配器将以同步方式进行页面释放（direct-reclaim）。

        ![管理区水位线](https://raw.githubusercontent.com/Din2413/linux_comment/master/files/%E7%AE%A1%E7%90%86%E5%8C%BA%E6%B0%B4%E4%BD%8D%E7%BA%BF.png)

    - 保留页框池 min_free_kbytes

      ​	内存分配请求在有足够的空闲内存可用的情况下，请求会被立刻得到满足；但当空闲内存短缺时，内核必须回收一些内存，同时将发出请求的内核控制路径阻塞，直到内存被释放。

      ​	然而一些内核控制路径在请求内存时不能被阻塞，比如中断处理程序内或者执行临界区内的代码。在这些情况下，内核控制路径应当产生原子内存分配请求（`GFP_ATOMIC`内存分配标志）。原子请求从不被阻塞，如果没有足够的空闲页，则仅仅是分配失败而已。

      ​	内核并不能保证一个原则内存分配请求绝不失败，但内核会设法尽量减少这种不幸事件的发生。为做到这一点，内核为原子内存分配请求保留了一个页框池，只有在内存不足时才使用。

      ​	保留的页框池数量（以KB为单位）存放在`min_free_kbytes`变量中。该值取决于直接映射到内核线性地址空间的物理内存数量（低端内存大小）。且保留页框池也是由低端内存管理区的部分页框组成，高端内存页框使用前需按需构建内存映射，该过程可能需要请求分配新的页表进而因此阻塞。

  - 物理页帧 page

    在管理区之上，系统内存进一步划分成大小确定的页面，通过页表与虚拟内存的页进行映射。
    
    ![内存节点](https://raw.githubusercontent.com/Din2413/linux_comment/master/files/%E5%86%85%E5%AD%98%E8%8A%82%E7%82%B9.png)

- 虚拟内存

  虚拟内存可以让每个进程都有属于自己的虚拟地址空间。从用户角度来看，地址空间是一个平坦的线性地址空间，由两部分组成：一个是随上下文切换而改变的用户空间部分，一个是保持不变的内核空间部分。

  虚拟内存与物理内存之间的映射通过页表实现。

  - 页表

    页表的级数越高每次获取虚拟内存存储在真实物理内存中的数据所需要进行的访存操作也就越多，如三级页表获取指定虚拟地址存储的数据需要三次访存操作，因此为减少虚拟地址到物理地址转换过程中访存次数，引入TLB页表缓存机制。

    Linux采用一种同时适用于32位和64位系统，且与具体的体系结构无关的普通分页模型。对于32位系统，二级页表足够，但对于64位系统，二级页表只能映射到4GB的内存空间，因此需要更多数量的分页级别。直到2.6.10版本，Linux采用三级分页模型，而从2.6.11版本开始，Linux采用四级分页模型；

    四级分页模型四种页表分别为：页全局目录、页上级目录、页中间目录、页表；

    在四级分页模型中，页全局目录包含若干页上级目录的地址，页上级目录又依次包含若干页中间目录的地址，而页中间目录有包含若干页表的地址，每个页表项指向一个页框。在这种模型中，线性地址被分成五个部分，分别为“页全局目录偏移”、“页上级目录偏移”、“页中间目录偏移”、“页表项偏移”、“页框偏移”，每一部分的大小与具体的计算机体系结构有关。

    对于没有开启物理地址扩展的32位系统，二级页表足够使用。此时，Linux可将线性地址中的“页上级目录偏移”位和“页中间目录偏移”位设置为0，从根本上消除页上级目录和页中间目录字段。当需要采用三级页表实现虚拟内存转换时，也可采用类似方式将“页上级目录偏移”或“页中间目录偏移”位设置为0，以消除多余一级的页目录转换。

    ![页表映射](https://raw.githubusercontent.com/Din2413/linux_comment/master/files/%E9%A1%B5%E8%A1%A8%E6%98%A0%E5%B0%84.png)

  - TLB缓存

    由于从虚拟地址转换成物理地址的开销较大，因此引入TLB（Translation Look-aside Buffer，地址变换高速缓存，简称快表）缓存机制减少访存操作，提供系统整体性能。具体实现后续研究。

### 内存映射

- 低端内存映射

  ​	在内核初始化时，会将低端内存直接线性映射到内核线性地址空间部分，后续内核可对这部分内存直接访问。

  ​	线性地址X所映射的物理地址为：`X - PAGE_OFFSET`，其中`PAGE_OFFSET`为线性地址空间中内核空间起始地址。

  - 直接映射

- 高端内存映射

  ​	高端内存并不直接映射（系统初始化时）在内核线性地址空间部分，因此，内核不能直接访问它们。这也意味着，返回所分配页框线性地址的页分配函数不适用于高端内存。

  ​	为使内核能够使用系统内所有可用的RAM，需要**将高端内存按需的映射到内核线性地址空间中的剩余部分**（直接映射占用外的部分，即32位80x86体系结构中内核线性地址空间的最后128MB），**并在使用完成后解除映射**，使得整个高端内存都能够在不同的时间被访问。
  
  ​	内核提供三种不同的机制将高端内存映射到内核线性地址空间，分别叫做“永久内核映射”、“临时内核映射”及“非连续内存分配”。
  
  ​	在64位硬件或可用RAM较少的平台上不存在这个问题，因为可使用的线性地址空间远大于能安装的RAM大小，简言之，这些情况下`ZONE_HIGHMEM`高端内存管理区总是空的。
  
  - 永久映射
  
    ​	永久内核映射使用主内核页表中一个专门的页表，该页表地址放在`pkmap_page_table`变量中，所映射的线性地址从`PKMAP_BASE`开始，页表的表项数由`LAST_PKMAP`宏产生，即永久映射一次最多访问`LAST_PKMAP * 4KB`（32位80x86体系结构且不支持PAE对应大小为4MB）的高端内存。
  
    ​	当永久内核映射页表项全部被映射时，建立新的永久映射的内核控制路径必须阻塞等待，直到永久内核映射页表中存在空闲页表项。因此，**建立永久内核映射可能阻塞当前进程，不能用在中断处理程序或可延迟函数等禁止阻塞的内核控制路径内**。
  
    ​	为了记录高端内存页框与永久内核映射线性地址之间的联系，内核使用散列表记录包含“页框描述符地址”以及“页框永久映射线性地址”的元素。
  
    ​	永久内核映射的建立与撤销分别由`kmap_high`、`kunmap_high`两个函数实现。
  
    ​	在获取页框对应的线性地址时，首先判断页框是否属于高端内存，如果不属于，则线性地址总是存在，且可以直接通过页框描述符计算页框下标，再转换成物理地址，最后根据物理地址得到线性地址，即`__va((unsigned long)(page - mem_map) << 12)；`如果属于，则先到永久映射关系的散列表查找，如果找到，则返回对应映射的线性地址，否则就调用`kmap_high`建立新的永久映射。
  
    ​	建立页框永久映射时，搜索专门页表`pkmap_page_table`中空闲页表项，将页框的物理地址写入该空闲页表项中，并创建一个新的映射关系对象添加进永久映射的散列表内。
  
    ​	具体实现可参照《深入理解linux内核(第三版)》-第八章内存管理-永久内核映射小节(308页)。
  
  - 临时映射
  
    ​	临时内核映射比永久映射的实现要简单，此外，建立临时内核映射不会阻塞当前进程，可以用在中断处理程序和可延迟函数等禁止阻塞的内核控制路径内部。
  
    ​	不过缺点在于只有很少的临时内核映射可以同时建立起来，**使用临时内核映射的内核控制路径必须保证当前没有其他的内核控制路径在使用同样的映射**。
  
    ​	高端内存的任一页框都可以通过一个“窗口”（为此而保留的一个页表项）映射到内核地址空间，不过留给临时内核映射的窗口数是非常少的。每个CPU都有它包含`KM_TYPE_NR`个窗口的集合，用`enum km_type`数据结构表示，其中定义的每个符号，如`KM_BOUNCE_READ`、`KM_PTE0`等，标识了窗口的线性地址。
  
    ​	临时内核映射也使用主内核页表中的一个专门的页表，该页表地址存放在`kmap_pte`变量中，所映射的线性地址从`FIXADDR_TOP`自上而下开始。
  
    ​	可使用如下方法获取指定类型的临时映射对应的线性地址：
    `\#define __fix_to_virt(x) (FIXADDR_TOP - ((x) << PAGE_SHIFT))
    idx = type + KM_TYPE_NR*smp_processor_id();
    vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);`
  
    ​	临时内核映射的建立与撤销分别由`kmap_atomic`、`kunmap_atomic`两个函数实现。
  
    ![内核空间内存映射](https://raw.githubusercontent.com/Din2413/linux_comment/master/files/%E5%86%85%E6%A0%B8%E7%A9%BA%E9%97%B4%E5%86%85%E5%AD%98%E6%98%A0%E5%B0%84.png)
    
    ​	具体实现可参照《深入理解linux内核(第三版)》-第八章内存管理-临时内核映射小节(311页)。

### 内存分配

- 内存碎片

  ​	“内存碎片”描述了一个系统中所有不可用的空闲内存，这些空闲内存较小且以不连续方式出现在物理内存的不同位置，内存分配器无法将这些内存利用起来分配给新的进程。

  ​	以内存相对进程的所属位置进行划分，碎片内存可分成两种：一种为“外部碎片”，该种空闲碎片指的是还没有被分配出去，不属于任何进程的内存，由于内存太小而无法分配给申请连续内存空间的新进程；另外一种为“内部碎片”，该空闲碎片指的是已分配出去，属于某个进程但并不被使用的内存，由于内存被进程占有而无法被系统再利用，直到进程将其释放或进程结束；

  - 外部碎片

    ​	“外部碎片”产生的原因是系统频繁的分配与回收物理页面导致大量的、不连续且小的页面块夹杂在已分配的页面中间。

    ​	对于“外部碎片”的解决方案主要有两种：一种是**利用分页单元把一组非连续的空闲页框映射到连续的线性地址，即地址转换技术**；另一种则是开发一种适当的技术来记录现存的空闲连续页框块的情况，以避免为满足对小块的请求而分割大的空闲块，保证大块内存的连续性和完整性；

    ​	第一种方式存在“用来映射非连续内存线性地址空间有限”、“每次映射都需要改写内核页表，导致内存分配速度大打折扣”的弊端。且在某些情况下，连续的页框确实是必要的，比如DMA处理器忽略分页单元而直接访问地址总线传送几个磁盘扇区的数据时。

    ​	因此**Linux内核系统采用了第二种方案，即使用伙伴系统（buddy system）算法解决“外部碎片”问题。**

  - 内部碎片

    ​	“内部碎片”产生的原因是内存分配必须起始于可被4、8或16整除的地址或者内存分配算法仅能把预定大小的内存分配给进程。

    ​	对于“内部碎片”的解决方案其实与“外部碎片”类似，都是尽量保证内存按需分配，从恰当大小的内存池中对申请的内存进行分配，避免内存分配过大而造成空闲浪费。**Linux内核系统采用一种内存分配粒度较小的SLAB分配算法解决“内部碎片”问题**。

- 连续内存

  - 按页分配

    ​	根据页框分配标志搜索一个能满足所请求的一组连续页框内存的管理区，并从中分配指定大小的页框块。

    ​	页框分配标注主要由两部分构成，一部分为`gfp_mask`，另一部分为`alloc_flags`。前者用于指定如何寻找、分配空闲页框，如`GFP_DMA/GFP_HIGHMEM`指定目标内存管理区、`GFP_ATOMIC/GFP_NOIO/GFP_NOFS`指定内存请求控制路径是否能被阻塞以及在可阻塞情况下是否允许换页回收内存；后者则用于指定如何进行水位线检查，如`ALLOC_NO_WATERMARKS`指定分配时不做水位线检查、`ALLOC_WMARK_MIN/LOW/HIGH`指定依次对最小/低/高水位进行检查，水位线检查失败则不满足分配。

    - 伙伴系统

      ​	按页管理物理内存，系统内存分配基础，所有可用内存均需通过伙伴系统管理后提供上层请求分配。

      ​	伙伴系统的宗旨就是用最小的内存块来满足内核对于内存的请求。**Linux伙伴系统把所有空闲页框分组为11个块链表，每个链表分别包含大小为1、2、4、8、16、32、64、128、256、512、1024个连续的页框**。每个块的第一个页框的物理地址是该块大小的整数倍（按块大小对齐）。

      ​	假设需要申请256个页框的连续内存，伙伴系统算法首先在256个页框的链表中检查是否还有空闲块，如果有就分配出去。如果没有，算法会找到下一个更大的512页框的链表，如果存在空闲块，内核会把512页框分割成两部分，一半用来分配，另一半插入到256页框的链表中。如果依旧没有，则继续朝下一个具有更大数量页框的链表中查找，直到1024个页框的链表中也没有空闲块时，系统返回异常。

      ​	同理，页框块在释放时，伙伴系统会将多个连续的页框块合并为一个较大的页框块。内核试图把大小为b的一对空闲伙伴块合并为一个大小为2b的单独块，并在成功后迭代进行。满足以下条件的两个块称为伙伴：①两个块具有相同的大小；②它们的物理地址是连续的；③**第一个块的第一个页框的物理地址是2\*b\*2^12的倍数**；

      ![伙伴系统](https://raw.githubusercontent.com/Din2413/linux_comment/master/files/%E4%BC%99%E4%BC%B4%E7%B3%BB%E7%BB%9F.png)

      ​	具体实现可参照《深入理解linux内核(第三版)》-第八章内存管理-伙伴系统算法小节(311页) 或 mm/page_alloc.c源代码注释。

      - 反碎片技术-内存分类

        ​	**伙伴系统仅仅寄托于内存释放时的合并操作而不考虑分配时的策略**，即伙伴系统的碎片防止机制寄托于内存使用者会及时释放掉内存的情况，但**当系统长期运行，或使用者长期不释放内存时，物理内存依然会产生很多碎片**。这些内存的存在，虽然对用户空间是没有影响的，因为用户态的内存是通过页面映射得到的；但对于内核态，碎片是个严肃的问题，因大部分物理内存都直接映射到内核的永久映射区。为了更进一步优化碎片问题，Linux内核引入**反碎片（anti-gragmentation）技术——内存分类**。

        ​	Linux将内存大体分为三类：**不可移动页**（在内存的固定位置，不能移动带其他地方，内核态分配的内存属于该类型）、**可回收页**（不能直接移动，但可以删除）、**可移动页**（在内存中的位置可随便移动，只要修改对应表项就行，用户态应用程序使用的页属于该类型）。**相同阶的、不同类型的页框块采用不同的链表进行维护；当出现碎片情况时，可移动页面将会迁移，为申请者腾出所需的连续页面空间，由此避免空闲页面空间过于零碎而无法申请大块连续内存。**

      - 每CPU页框高速缓存

        为提高系统整体性能，用于快速满足对单个页框的分配请求。

        每个CPU为每个内存管理区提供两个高速缓存：

        1.  一个热高速缓存，表明其存放页框所包含的内容很可能在CPU硬件高速缓存中；
        2.  一个冷高速缓存，表明其存放页框所包含的内容不在CPU硬件高速缓存中；

        ​	当请求的空闲内存块阶为0，即分配单页框时，可直接在'每CPU'页框高速缓存中分配；同理，释放单页框时，也直接放回‘每CPU’页框高速缓存中。当‘每CPU’高速缓存中无满足分配的页框或空闲页框达到某一上限值时，再向伙伴系统申请或释放一定数量的页框。

    - 后备管理区

      ​	对于非一致性内存访问`UNMA`而言，除本地结点，还可能存在多个远端内存结点。当本地内存结点请求内存分配失败时，可选择最优的远端内存结点进行后备分配。

      ​	内核引入后备管理区的概念，所有内存结点（本地内存结点或远端内存结点）内的、符合备选分配的管理区组成本地内存结点某类管理区的备选列表，当本地内存结点这类管理区的内存分配请求得不到满足时，可按序从备选列表中选择可用的管理区进行分配。

      ​	依据不同的情况，内核提供两种备选列表的排列方式，第一种按结点顺序依次排列，先排列本地结点的所有ZONE，再排列其他结点的所有ZONE，该种排列方式更侧重内存分配结点的本地性，如：`highmem(node0)->normal(node0)->dma(node0)->highmem(node1)...`；第二种按ZONE类型从高到低依次排列，先排列各结点高类型ZONE，再排列各结点低类型ZONE，该种排列方式更侧重内存分配管理区类型的一致性，如：`highmem(node0)->highmem(node1)->normal(node0)->normal(node1)...`；

      每个内存结点包含`MAX_ZONELISTS`个备选分区列表，值为`2*MAX_NR_ZONES`，整个备选分区列表由两部分组成：

      -  前半部分`[0~MAX_NR_ZONES-1]`包含所有内存结点管理区列表，当自身管理区不满足分配时可从备选列表尝试分配
      -  后半部分`[MAX_NR_ZONES~MAX_ZONELISTS]`只包含自身结点管理区列表

      当限制内存分配只能从本地内存结点请求时，则直接使用后半部分的管理区列表，否则使用包含远端内存结点的管理区列表。

      ​	系统中存在三个内存结点`node0/1/2`，每个内存结点包含`ZONE_DMA`、`ZONE_NORMAL`两个管理区，管理区排列方式采用`ZONELIST_ORDER_NODE`时，`node0`创建的`node_zonelists`各管理区的备用管理区列表如下所示：

      - `node_zonelists[ZONE_DMA] = ZONE_DMA(node0)->ZONE_DMA(node1)->ZONE_DMA(node2)；`
      - `node_zonelists[ZONE_NORMAL] = ZONE_NORMAL(node0)->ZONE_DMA(node0)->ZONE_NORMAL(node1)->ZONE_DMA(node1)->ZONE_NORMAL(node2)->ZONE_DMA(node2)；`
      - `node_zonelists[ZONE_DMA + MAX_NR_ZONES] = ZONE_DMA(node0)；`
      - `node_zonelists[ZONE_NORMAL + MAX_NR_ZONES] = ZONE_NORMAL(node0)->ZONE_DMA(node0)；`

  - 对象缓存

    **伙伴系统的最小分配单位为页框**，对于一些频繁申请/释放的小到几十字节的内存来说，直接采用伙伴系统进行内存分配显然是极其浪费且效率低下的。

    为缓解（通用对象缓存是按2的幂次方大小维护的，当请求的实际大小与2的幂次方大小不相等时，依然存在内部碎片浪费，只不过该机制可保证内部碎片小于50%）内存浪费以及低效问题，内核采用一种**建立在伙伴系统之上，以更小粒度和更高效的的方法**对小字节内存进行处理，该方法基于对象（所谓对象就是存放一组数据结构的内存区）进行管理，且以**对象提前分配与延迟释放**的方式提高小字节内存分配效率。

    该方法在对象请求分配时，提前从伙伴系统中请求分配以页框为单位的内存块，并将内存块划分成对象大小的缓存池，后续相同对象的请求分配可直接从缓存池中得到满足；同理，对象释放也采用类似策略，优先将对象放回缓存池，直到缓冲池中空闲数量较多或满足一定条件时，再将页框块重新释放回伙伴系统。

    - 对象类型

      高速缓存被分为两种类型：通用和专用。

      通用高速缓存在系统初始化期间创建，对象大小以2的幂次方几何分布，用于满足内核空间kmaloc/kfree对指定大小的内存分配请求。

      专用高速缓存是按需调用创建的，对象大小不具备任何规律，用于满足特定业务场景对特定数据结构的频繁分配和释放。

      - 通用对象缓存 kmalloc/kfree
      - 专用对象缓存 kmem_cache_alloc/kmem_cache_free

    - 分配算法

      内核提供三种可选的对象缓存分配器算法，分别为slab、slob、slub，Slab最初是Jeff Bonwick为Sun OS操作系统引入的一种算法，其围绕对象缓存为核心；Slub和Slob则是在slab的基础上针对特定场景的优化算法，前者主要针对大型机，而后者则是针对嵌入式系统等小型系统设计的。

      - slab分配器

        slab分配器把对象分组放进高速缓存，每个高速缓存都是同种类型对象的一种“储备”，包含高速缓存的主内存区被换分成多个slab，每个slab由一个或多个连续的页框组成。

        根据缓存对象的分配情况，slab被分成三种类型；包含空闲和非空闲对象的slab、只包含空闲对象的slab、不包含空闲对象的slab，不同的slab类型采用不同的链表维护。

        ![高速缓存与slab的关系](https://raw.githubusercontent.com/Din2413/linux_comment/master/files/%E9%AB%98%E9%80%9F%E7%BC%93%E5%AD%98%E4%B8%8Eslab%E7%9A%84%E5%85%B3%E7%B3%BB.png)

        一个新建的高速缓存并没有包含任何slab，即没有空闲的对象。当一个分配新对象的请求被发出且高速缓存不包含任何空闲对象时，slab分配器需从伙伴系统中请求分配一个新的slab（即一组连续的页框），用以补充缓存池。

        每个slab的缓存对象都是从某一个偏移位置开始依次排开的，为简单管理所有空闲的缓存对象，且在分配缓存对象时能尽快的获取缓存池中的空闲对象，**每个slab的缓存对象都是从某一个偏移位置开始依次排开的，为简单管理所有空闲的缓存对象，且在分配缓存对象时能尽快的获取缓存池中的空闲对象，每个slab描述符内均包含一个用于描述空闲对象序列的整型数组。数组长度与slab缓存池中对象个数一致，每个元素包含当前slab中下一个空闲对象的序号index， 通过设置值为BUFCTL_END用以表示空闲对象链表的尾部，首个空闲对象的序号index则由slab描述的free字段保存，因此从free开始、以BUFCTL_END结尾可按序遍历slab内全部空闲对象。**。

        ![slab空闲对象数组](https://raw.githubusercontent.com/Din2413/linux_comment/master/files/slab%E7%A9%BA%E9%97%B2%E5%AF%B9%E8%B1%A1%E6%95%B0%E7%BB%84.png)

        理想状态下，slab的页框块应无缝隙的划分成独立的缓存对象，但这样就会使得缓存对象的起始地址极度不规则，而**内存单元的物理地址按照字大小（即计算机的内部内存总线的宽度）对齐，可增加内存单元的存取速度**；同理按照硬件高速缓存行对齐，避免横跨两个高速缓存行，也可提升数据的存取速度。这种机制虽然会适当地引入额外的内部碎片，但以空间换时间，可获得较好的高速缓存性能。

        **同一硬件高速缓存行可以映射RAM中很多不同的块，而缓存对象又会按字大小或硬件高速缓存行对齐，因此不同的slab内具有相同偏移量的对象最终很可能映射在同一硬件高速缓存行内**。高速缓存的硬件可能因此而花费内存周期在同一高速缓存行与RAM内存单元之间来来往往传送两个对象，而其他的高速缓存行并未充分使用。

        为尽量降低高速缓存的这种不愉快行为，slab分配器引入了一种叫做**slab着色**的策略，**把叫做颜色的不同随机数分配给不同slab的首个对象的起始偏移**。**颜色只是用来细分slab，具有不同颜色的slab把slab的第一个对象存放在不同的内存单元**。**可用颜色的个数与slab内空闲未用的字节free和硬件高速缓存行大小有关**（free/按硬件高速缓存行对齐的长度），只有当free足够大时，着色才起作用。不然空闲未用字节不足以容纳按硬件高速缓存行对齐的偏移长度，导致唯一可能着色的slab就是具有颜色0的slab，也就是把这个slab的第一个对象偏移量增加0个字节，即不起任何作用。

        ![slab着色](https://raw.githubusercontent.com/Din2413/linux_comment/master/files/slab%E7%9D%80%E8%89%B2.png)

        与伙伴系统每CPU页框高速缓存类似，为减少处理器之间对自旋锁的竞争并更好的理由硬件高速缓存，slab分配器的每个高速缓存包含一个被称作slab本地高速缓存的每CPU数据结构，该结构由**一个指向被释放对象的指针数组组成**。slab对象的大多数分配和释放只影响本地数组，只有在本地数组下溢或上溢时才涉及slab数据结构。

        **主要缺陷：**

        1、**复杂的队列管理机制**。在slab分配器中存在众多的队列，例如本地缓存队列、空闲/部分空闲/已满队列等，每个slab处于一个特定状态的队列之中，管理较复杂；

        2、**管理数据和队列的存储开销较大**。每个slab均需要一个slab描述符和管理空闲对象列表的整型数组，当对象体积较小时，该存储结构将造成较大的开销；

        3、**冗余的partial队列**。slab分配器针对每个节点都有一个partial队列，如果slab迎来一个分配高峰期，将有大量的partial slab产生。

        具体实现可参照《深入理解linux内核(第三版)》-第八章内存管理-slab分配器小节(324页) 或者 mm/slab.c源代码注释。

      - slob分配器

      - slub分配器

        **slub分配器是slab分配器的进化版**。

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
~~1.内存水位线:high、low、min；</br>~~
~~2.内存映射:直接映射、永久映射、临时映射；</br>~~
~~3.内核空间内存分配:连续内存分配(伙伴系统、slab/slob/slub分配器)、非连续内存分配(vmalloc)；</br>~~
4.内存回收:回收时机、回收算法(扩展课题:磁盘页缓存、脏页回写)；</br>
5.进程地址空间:延时分配、mmap映射(匿名映射、文件映射)、elf目标文件(格式分析)；</br>
6:写时复制、缺页异常；
