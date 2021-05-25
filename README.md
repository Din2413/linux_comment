linux code comment for 2.6.24

在对linux 2.6.24进行注释的同时，总结输出自己对于各个内核模块的理解。

持续不断更新......

# 内存管理
## 思维导图

<img src="https://raw.githubusercontent.com/Din2413/linux_comment/master/files/%E5%86%85%E5%AD%98%E7%AE%A1%E7%90%86.jpg" width="100%" height="100%"/><br/>

## 后续课题
1.内存水位线:high、low、min；</br>
2.内存映射:直接映射、永久映射、临时映射；</br>
3.内核空间内存分配:连续内存分配(伙伴系统、slab/slob/slub分配器)、非连续内存分配(vmalloc)；</br>
4.内存回收:回收时机、回收算法(扩展课题:磁盘页缓存、脏页回写)；</br>
5.进程地址空间:延时分配、mmap映射(匿名映射、文件映射)、elf目标文件(格式分析)；</br>
6:写时复制、缺页异常；
