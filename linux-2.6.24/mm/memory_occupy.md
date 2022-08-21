以某一个嵌入式设备为切入点，阐述系统各模块的内存消耗情况。

### 内存占用一窥
在我们开始着手进行优化之前，必须要先弄清楚系统内存都消耗到哪去了，才好针对性地选择一些内存消耗较大或者不合理的模块思考优化思路，再顺着思路着手进行优化措施。
#### 1、启动+预留
Linux内核启动时会使用`memblock`分配内存以加载kernel code ，并为各内核模块预留保证功能正常执行所需的内存，其中包含根据dts文件的 `reserved-memory`配置预留指定大小的内存空间，且如果 `reserved-memory`配置项包含no-map标签时，所指定的内存范围会提前（启动初期、解析dts配置文件时）从可用内存中移除，以对其他模块不可见。
以下是我的嵌入式设备通过dts文件配置的 `reserved-memory`，包含四块内存空间且每一块都包含no-map标签：

```c
reserved-memory {
		#address-cells = <2>;
		#size-cells = <2>;
		ranges;

		/* 192 KiB reserved for ARM Trusted Firmware (BL31) */
		secmon_reserved: secmon@43000000 {
			reg = <0 0x43000000 0 0x30000>;
			no-map;
		};

		/* 1024KB */
		wmcpu_emi: wmcpu-reserved@47C80000 {
			compatible = "mediatek,wmcpu-reserved";
			no-map;
			reg = <0 0x47C80000 0 0x00100000>;
		};

		/* 256K	*/
		wocpu0_emi: wocpu0_emi@47D80000 {
			compatible = "mediatek,wocpu0_emi";
			no-map;
			reg = <0 0x47D80000 0 0x40000>;
			shared = <0>;
		};

		/* 2304KB */
		wocpu_data: wocpu_data@47DC0000 {
			compatible = "mediatek,wocpu_data";
			no-map;
			reg = <0 0x47DC0000 0 0x240000>;
			shared = <1>;
		};
	};
```

通过 `/sys/kernel/debug/memblock/memory` 可以查看系统所有可见内存，这部分是已扣除包含no-map标签的`reserved-memory`后的内存空间：

```c
   0: 0x0000000040000000..0x0000000042ffffff
   1: 0x0000000043030000..0x0000000047c7ffff
   2: 0x0000000048000000..0x000000004fffffff
```

因此，**扣除no-map指定 **`**reserved-memory**`**后，可用的物理内存总量为 258368KB**（设备物理内存为256M，258368KB = 256M - 192 KB - 1024KB - 256K - 2304KB）。但这个内存总量并不就是Linux内核伙伴系统管理的内存，还需要从中去除kernel code、init(不过init段占用的内存会在内核所有模块启动完成后被释放到伙伴系统中)、以及其他模块保证运行所分配的预留内存，才是**伙伴系统管理的内存总量，即230408KB + init段内存大小448KB**（其中，230408KB = 258368KB - 27960K reserved）。

```c
Memory: 230408K/258368K available (6910K kernel code, 464K rwdata, 1880K rodata, 448K init, 650K bss, 27960K reserved, 0K cma-reserved)
```

通过`/sys/kernel/debug/memblock/reserved`可以查看系统启动时为各模块预分配的内存空间。以下是我的嵌入式设备启动时预分配的内存，内存分配都需要以4KB大小对齐，所有这些内存空间大小加起来其实刚好与内核启动打印的reserved总量一致（10396KB + 14336KB + 20KB + 2048KB + 548KB + 4KB + 608KB = 27960KB）。

```c
0: 0x0000000048080000..0x0000000048aa6fff        == 0xa27000  == 10396KB （kernel）
1: 0x000000004e800000..0x000000004f5fffff        == 0xe00000  == 14336KB （CONFIG_SPARSEMEM 内存模型预分配）
2: 0x000000004f7f2000..0x000000004f7f6fff        == 0x5000    == 20KB
3: 0x000000004fc00000..0x000000004fdfffff        == 0x200000  == 2048KB
4: 0x000000004fedc200..0x000000004ff3c707
5: 0x000000004ff3c740..0x000000004ff3cc1f
6: 0x000000004ff3cc40..0x000000004ff3cdc7
7: 0x000000004ff3ce00..0x000000004ff64fff        == 0x89000   == 548KB
8: 0x000000004ff67000..0x000000004ff67fff        == 0x1000    == 4KB
9: 0x000000004ff68040..0x000000004ff6814f
10: 0x000000004ff68180..0x000000004ff68187
11: 0x000000004ff681c0..0x000000004ff681c7
12: 0x000000004ff68200..0x000000004ff682d9
13: 0x000000004ff68300..0x000000004ff683d9
14: 0x000000004ff68400..0x000000004ff684d9
15: 0x000000004ff68500..0x000000004ff6b687
16: 0x000000004ff6b6b8..0x000000004ff7dffb
17: 0x000000004ff7e000..0x000000004fffffff        == 0x98000   == 608KB
```

#### 2、free 命令

该命令可对系统内存的整体使用情况有一个初步了解。
`total = used + free + buff/cache;`

- **total内存总量**：表示被内核伙伴系统（Buddy System）管理的物理内存总量，也即系统启动后所有可申请的内存总量；该值可通过`cat /proc/zoneinfo`输出的各个zone内存管理区的 `pages managed`求和得到；

**PS：**该设备物理内存容量为256MB，那为何free命令获取的total内存总量确不足256MB呢？
物理内存设备中可能存在不可用的内存空洞，且系统初始化需要提前占用一部分内存（比如：内核代码、数据结构等），因此真正可在系统启动后被申请的内存总量必然小于内存硬件总量；Linux内核中存在三种内存总量，分别为spanned（表示包含空洞的内存大小）、present（表示扣除空洞的内存大小）、managed（表示扣除空调且不包含系统初始化占用的内存大小，也即伙伴系统管理的内存大小）。

- **used已分配内存**
- **free空闲内存**：系统尚未使用的内存总量，**此处的空闲内存总量为230856KB，正好等于内核启动时打印的available 23408KB + init段内存大小 448KB**；
- **buff/cache 缓冲/存内存**：buffers表示块设备所占用的缓存页，而cache表示普通文件所占用的缓存页；后者包含三部分内存，一部分是当前与进程关联的文件缓存页（共享库、可执行文件、mmap映射文件等），第二部分是当前未与进程关联但仍然保留内容的文件缓存页，第三部分是tmpfs/devtmpfs文件系统占用的空间；

```c
              total        used        free      shared  buff/cache   available
Mem:         230856      146008       50364         836       34484       58128
Swap:             0           0           0
```

#### 3、/proc/meminfo

meminfo文件进一步细化系统内存占用情况。其实free、vmstat命令也是通过它获取数据的。

- **MemAvaliable系统可用内存**

部分应用程序会根据系统可用内存大小自动调整内存申请的多少，因此需要一个记录当前可用内存数量的统计值，而MemFree并不适用，因为MemFree不能代表系统全部可用内存，系统中有些内存虽然已被使用但可以回收，比如buffer/cache、slab都有一部分可以回收，这部分加上MemFree才是系统可以的内存，即MemAvaliable，该值是内核使用特定的算法**估算得出的**。

- **Active活跃内存**

LRU内存回收链表中活跃内存总量，Active(anon)代表活跃匿名页（比如进程的用户态堆或栈的所属页、tmpfs/shmem的所属页等），Active(file)代表活跃文件映射或缓存内存；
**PS：**在/tmp目录下导入一个大文件，可以看到Active(anon)会明显增大；

- **Inactive非活跃内存**

LRU内存回收链表中非活跃内存总量（内存回收只能回收该状态的页），Inactive(anon)代表非活跃匿名页（只有开启swap换页才能被回收），Inctive(file)代表活跃文件映射或缓存内存（根据是否为脏页决定是否需要进行writeback写回操作）；
**PS：Active + Inactive = AnonPages + Cached + Buffers**

- **AnonPages用户进程匿名页**

用户进程的内存分为两种，一种是与文件映射的内存页（代码段、库文件等），一种是不与文件映射的匿名页（堆、栈等）。AnonPages统计的便是用户进程匿名页的内存占用总量。
**PS：mmap private anonymous pages私有匿名映射页属于AnonPages，而mmap shared anonymous pages共享匿名映射页属于Cached，因为共享内存基于tmpfs实现**。

- **Mapped用户进程文件映射页**

用户进程与文件映射的内存占用总量由Mapped统计。
meminfo中的Cached统计信息包含两种文件缓存页，一种是文件当前已不在使用却仍然保留内容的缓存页面，一种是文件正被用户进程关联，比如共享库、可执行程序的文件、mmap映射的文件等。后面这种文件的缓存页即由Mapped统计；
**PS：所有进程的PSS之和 = Mapped + AnonPages**

- **Shmem共享内存**

tmpfs/devtmpfs、shared memory占用的内存总量。所有tmpfs类型文件占用的空间都计入共享内存，devtmpfs是/dev文件系统类型，/dev目录下的所有文件占用的空间也属于共享内存。
shared memory又包括shmget系统调用创建的SysV共享内存、shm_open系统调用创建的Posix共享内存以及mmap(...MAP_ANONYMOUS|MAP_SHARED...)系统调用创建的匿名共享映射内存，共享内存在内核中都是基于tmpfs实现的。
**PS：**shmget/shm_open/mmap创建共享内存时，物理内存尚未分配，要直到真正访问时才分配（按需分配），/proc/meminfo中的 Shmem 统计的是已经分配的大小，而不是创建时申请的大小；

- **Slab内核对象缓存**

内核Slab分配器（通用kmalloc和对象kmem_cache_alloc）占用的内存总量，其中SReclaimable为可回收类型（内存回收时可通过slab_shrink进行被动回收）、SUnreclaim为不可回收类型（只能在对象释放且满足主动释放页的条件时进行回收）；

- **KernelStack进程内核态堆栈**

每个线程都会分配一个内核栈；

- **PageTables所有进程页表的内存占用**
- **VmallocTotal内核非连续虚拟内存**

内核通过vmalloc申请的虚拟内存总量，可通过`/proc/vmallocinfo`文件查看，多用于内核模块加载；

- **VmallocUsed内核非连续物理内存**

内核vmalloc分配的虚拟内存中实际映射物理内存的总量，可通过`cat /proc/vmallocinfo | grep pages | cut -d '=' -f 2 | cut -d ' ' -f 1 | awk '{sum += $1};END {print sum}'` 命令计算得到；

```c
root@Openwrt:~# cat /proc/meminfo 
MemTotal:         230856 kB
MemFree:           49516 kB
MemAvailable:      57348 kB
Buffers:            7076 kB
Cached:            20736 kB
SwapCached:            0 kB
Active:            34384 kB
Inactive:          10148 kB
Active(anon):      17132 kB
Inactive(anon):      456 kB
Active(file):      17252 kB
Inactive(file):     9692 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:                 0 kB
Writeback:             0 kB
AnonPages:         16720 kB
Mapped:            12020 kB
Shmem:               868 kB
KReclaimable:       6832 kB
Slab:              47464 kB
SReclaimable:       6832 kB
SUnreclaim:        40632 kB
KernelStack:        1836 kB
PageTables:         1136 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:      115428 kB
Committed_AS:      28004 kB
VmallocTotal:   262930368 kB
VmallocUsed:       35556 kB
VmallocChunk:          0 kB
Percpu:              312 kB
```

追踪Linux系统的内存使用一直很多人试着把能想到的各种内存消耗都加在一起，kernel text、kernel modules、buffer、cache、slab、page table、process RSS…等等，却总是与物理内存的大小对不上，这是为什么呢？因为**Linux kernel并没有滴水不漏地统计所有的内存分配**，kernel动态分配的内存中就有一部分没有计入/proc/meminfo中。
正如我们所知，Linux内核动态内存分配可以通过如下几种接口：

   - alloc_pages/__get_free_page：以页为单位直接从伙伴系统请求分配；
   - vmalloc：以字节为单位分配虚拟地址连续的内存块；
   - kmalloc/kmem_cache_alloc：以字节为单位分配物理地址连续的内存对象；

其中，vmalloc方式的内存分配对应meminfo中的VmallocTotal和VmallocUsed统计信息，slab分配器的内存分配对应meminfo中的Slab(SReclaimable、SUnreclaim)统计信息，而**alloc_pages分配的内存不会自动统计，除非调用alloc_pages的内核模块主动进行统计，否则只能看到MemFree减少但meminfo中无对应统计信息**。
其实，系统内存主要由三部分占用，分别为空闲内存、内核空间占用、用户空间占用。空闲内存由MemFree进行统计，而内核空间占用可通过表达式**Slab + VmallocUsed + PageTables + KernelStack + X (+ Bounce + ... ) **计算得出（其中X为通过alloc_pages直接分配但未被统计的内存），而用户空间占用可通过如下三种方式进行统计：

   - 围绕LRU进行统计：Active + Inactive (+ Unevictable + ...)；
   - 围绕Cache进行统计：Cached + AnonPages + Buffers (+ Unevictable + ...)；
   - 围绕RSS/PSS进行统计：ΣPss + (Cached – mapped) + Buffers (+ Unevictable + ...)，其中ΣPss为/proc/[1-9]*/smaps中的Pss累加，表示所有用户进程占用的内存，但没包含Cached中的unmapped部分以及Buffer部分；

参考资料：[/proc/meminfo之谜](http://linuxperf.com/?p=142)
#### 4、/proc/{pid}/smaps
 smaps文件默认不创建，需开启内核宏 CONFIG_PROC_PAGE_MONITOR 才可见。smaps文件用于展示进程各匿名内存线性区（堆、栈、映射区等）的具体状态，比如：匿名内存还是共享内存、是否为脏页、以及该线性区所占用的物理内存大小等。
 
 下面以一个进程的stack线性区为例，讲解smaps中各关键字段的含义：

 ```c
 7fdac9a000-7fdacda000 rw-p 00000000 00:00 0                              [stack]
Size:                256 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                 256 kB
Pss:                 256 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:       256 kB
Referenced:          244 kB
Anonymous:           256 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:        0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:            0
VmFlags: rd wr mr mw me gd ac 
 ```
 
- Size：表示虚拟线性区大小；
- Rss：虚拟线性区实际分配的物理内存大小，是Shared_Clean + Shared_Dirty + Private_Clean + Private_Dirty的总和；
- Pss：按照分摊计算后，该线性区对应的物理内存大小。因共享内存可被多个进程映射使用，那实际占用的物理内存也应该均分到各个进程。比如进程有Private_Clean内存aKB，Private_Dirty内存bKB，又有与另外一个进程共享的Shared_Clean内存cKB，与另外两个进程共享的Shared_Dirty内存dKB，则进程Pss = a + b + c/2 + d/3;
- Shared_Clean、Shared_Dirty：共享内存，其中Clean表示非脏页，Dirty表示脏页；
- Private_Clean、Private_Dirty：私有内存，不与其他进程共享，其中Clean表示非脏页，Dirty表示脏页；
- Referenced：该线性区对应的物理内存中，在内核LRU链表中标记为最近被引用（也表示当前不可回收）的内存大小；
- Anonymous：线性区内占用的匿名内存的大小；

通过smaps文件，可以使用下面这个简单的脚本统计当前系统中各个进程所占用的分摊物理内存总量：

```c
#task_mem_sum脚本
#!/bin/sh

for file in /proc/*
do
        if [ -d "$file" -a -f "$file/smaps" ]
        then
                task_mem=`cat $file/smaps | grep Pss: | cut -d ':' -f 2 | cut -d 'k' -f 1 | awk '{sum += $1};END {print sum}'`
                if [ "$task_mem" != "" -a "$task_mem" != "0" ]
                then
                        exe_name=`cat $file/status | grep Name | cut -d ':' -f 2 | sed 's/^[ \t]*//g'`
                        echo "$exe_name(mem sum):$task_mem"
                fi
        fi
done
```

参考资料：[/proc/{pid}/smaps详解](https://www.jianshu.com/p/8203457a11cc)
