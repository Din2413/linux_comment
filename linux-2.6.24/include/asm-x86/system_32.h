#ifndef __ASM_SYSTEM_H
#define __ASM_SYSTEM_H

#include <linux/kernel.h>
#include <asm/segment.h>
#include <asm/cpufeature.h>
#include <asm/cmpxchg.h>

#ifdef __KERNEL__
#define AT_VECTOR_SIZE_ARCH 2 /* entries in ARCH_DLINFO */

struct task_struct;	/* one of the stranger aspects of C forward declarations.. */
extern struct task_struct * FASTCALL(__switch_to(struct task_struct *prev, struct task_struct *next));

/*
 * Saving eflags is important. It switches not only IOPL between tasks,
 * it also protects other tasks from NT leaking through sysenter etc.
 */
/* 采用扩展的内联汇编语言编码，通过特殊位置计数法使用寄存器，实际使用的通用寄存器由编译器自由选择 */
/*
 * 进程硬件上下文切换流程：
 * 1、保存prev进程部分寄存器到内核堆栈中，并将%esp堆栈寄存器存入prev->thread.esp字段
 * 2、将next->thread.esp字段装入%esp堆栈寄存器，从此CPU开始使用next进程的堆栈空间
 * 3、将next进程下一条待执行指令地址next->thread.eip压入堆栈顶部（后续ret指令返回取栈顶返回地址时便能直接切换到next进程的指令空间运行）
 * 4、（__switch_to）处理其他硬件上下文切换（浮点运算、段寄存器等），将prev进程描述符地址存入%eax寄存器，并调用ret指令返回
 */
#define switch_to(prev,next,last) do {					\
	unsigned long esi,edi;	 /* 内嵌汇编语法：__asm__(汇编语句模板: 输出部分: 输入部分: 破坏描述部分)，第一部分必不可少，后三部分可选 */				\
	asm volatile("pushfl\n\t"		/* Save flags */	\
		     "pushl %%ebp\n\t"					\
		     "movl %%esp,%0\n\t"	/* save ESP，将指向堆栈顶部的esp寄存器的内容保存到prev->thread.esp字段中 */		\
		     "movl %5,%%esp\n\t"	/* restore ESP，将next->thread.esp字段的值装入指向堆栈顶部的esp寄存器 */	\
		     "movl $1f,%1\n\t"		/* save EIP，将标记为1的地址装入prev->thread.eip字段中，当被替换进程重新恢复执行时，进程执行被标记为1的那条指令 */		\
		     "pushl %6\n\t"		/* restore EIP，那next->thread.eip字段的值（绝大多数情况下是一个被标记为1的地址）压入next的内核栈中 */	\
		     "jmp __switch_to\n"	/* 跳转到__switch_to() c函数执行 */			\
		     "1:\t"		            /* 这里被替换的进程再次获得CPU，执行恢复eflags和ebp寄存器，这两条指令的第一条指令被标记为1 */ 				\
		     "popl %%ebp\n\t"					\
		     "popfl"						\
		     :"=m" (prev->thread.esp),"=m" (prev->thread.eip),	/* 输出部分 */ \
		      "=a" (last),"=S" (esi),"=D" (edi)	/* 替换进程A再次获得CPU（C->A）时，将%eax寄存器的值（C进程描述符地址）保存到last地址指向的单元，last与prev指向内容相同，prev跟随变化指向进程C描述符 */		\
		     :"m" (next->thread.esp),"m" (next->thread.eip),	/* 输入部分 */ \
		      "2" (prev), "d" (next));			/* A进程切换B前，next(B)装入到%edx、prev(A)装入到%eax */	\
} while (0)

#define _set_base(addr,base) do { unsigned long __pr; \
__asm__ __volatile__ ("movw %%dx,%1\n\t" \
	"rorl $16,%%edx\n\t" \
	"movb %%dl,%2\n\t" \
	"movb %%dh,%3" \
	:"=&d" (__pr) \
	:"m" (*((addr)+2)), \
	 "m" (*((addr)+4)), \
	 "m" (*((addr)+7)), \
         "0" (base) \
        ); } while(0)

#define _set_limit(addr,limit) do { unsigned long __lr; \
__asm__ __volatile__ ("movw %%dx,%1\n\t" \
	"rorl $16,%%edx\n\t" \
	"movb %2,%%dh\n\t" \
	"andb $0xf0,%%dh\n\t" \
	"orb %%dh,%%dl\n\t" \
	"movb %%dl,%2" \
	:"=&d" (__lr) \
	:"m" (*(addr)), \
	 "m" (*((addr)+6)), \
	 "0" (limit) \
        ); } while(0)

#define set_base(ldt,base) _set_base( ((char *)&(ldt)) , (base) )
#define set_limit(ldt,limit) _set_limit( ((char *)&(ldt)) , ((limit)-1) )

/*
 * Load a segment. Fall back on loading the zero
 * segment if something goes wrong..
 */
#define loadsegment(seg,value)			\
	asm volatile("\n"			\
		"1:\t"				\
		"mov %0,%%" #seg "\n"		\
		"2:\n"				\
		".section .fixup,\"ax\"\n"	\
		"3:\t"				\
		"pushl $0\n\t"			\
		"popl %%" #seg "\n\t"		\
		"jmp 2b\n"			\
		".previous\n"			\
		".section __ex_table,\"a\"\n\t"	\
		".align 4\n\t"			\
		".long 1b,3b\n"			\
		".previous"			\
		: :"rm" (value))

/*
 * Save a segment register away
 */
#define savesegment(seg, value) \
	asm volatile("mov %%" #seg ",%0":"=rm" (value))


static inline void native_clts(void)
{
	asm volatile ("clts");
}

static inline unsigned long native_read_cr0(void)
{
	unsigned long val;
	asm volatile("movl %%cr0,%0\n\t" :"=r" (val));
	return val;
}

static inline void native_write_cr0(unsigned long val)
{
	asm volatile("movl %0,%%cr0": :"r" (val));
}

static inline unsigned long native_read_cr2(void)
{
	unsigned long val;
	asm volatile("movl %%cr2,%0\n\t" :"=r" (val));
	return val;
}

static inline void native_write_cr2(unsigned long val)
{
	asm volatile("movl %0,%%cr2": :"r" (val));
}

static inline unsigned long native_read_cr3(void)
{
	unsigned long val;
	asm volatile("movl %%cr3,%0\n\t" :"=r" (val));
	return val;
}

static inline void native_write_cr3(unsigned long val)
{
	asm volatile("movl %0,%%cr3": :"r" (val));
}

static inline unsigned long native_read_cr4(void)
{
	unsigned long val;
	asm volatile("movl %%cr4,%0\n\t" :"=r" (val));
	return val;
}

static inline unsigned long native_read_cr4_safe(void)
{
	unsigned long val;
	/* This could fault if %cr4 does not exist */
	asm volatile("1: movl %%cr4, %0		\n"
		"2:				\n"
		".section __ex_table,\"a\"	\n"
		".long 1b,2b			\n"
		".previous			\n"
		: "=r" (val): "0" (0));
	return val;
}

static inline void native_write_cr4(unsigned long val)
{
	asm volatile("movl %0,%%cr4": :"r" (val));
}

static inline void native_wbinvd(void)
{
	asm volatile("wbinvd": : :"memory");
}

static inline void clflush(volatile void *__p)
{
	asm volatile("clflush %0" : "+m" (*(char __force *)__p));
}

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#else
#define read_cr0()	(native_read_cr0())
#define write_cr0(x)	(native_write_cr0(x))
#define read_cr2()	(native_read_cr2())
#define write_cr2(x)	(native_write_cr2(x))
#define read_cr3()	(native_read_cr3())
#define write_cr3(x)	(native_write_cr3(x))
#define read_cr4()	(native_read_cr4())
#define read_cr4_safe()	(native_read_cr4_safe())
#define write_cr4(x)	(native_write_cr4(x))
#define wbinvd()	(native_wbinvd())

/* Clear the 'TS' bit */
#define clts()		(native_clts())

#endif/* CONFIG_PARAVIRT */

/* Set the 'TS' bit */
#define stts() write_cr0(8 | read_cr0())

#endif	/* __KERNEL__ */

static inline unsigned long get_limit(unsigned long segment)
{
	unsigned long __limit;
	__asm__("lsll %1,%0"
		:"=r" (__limit):"r" (segment));
	return __limit+1;
}

#define nop() __asm__ __volatile__ ("nop")

/*
 * Force strict CPU ordering.
 * And yes, this is required on UP too when we're talking
 * to devices.
 *
 * For now, "wmb()" doesn't actually do anything, as all
 * Intel CPU's follow what Intel calls a *Processor Order*,
 * in which all writes are seen in the program order even
 * outside the CPU.
 *
 * I expect future Intel CPU's to have a weaker ordering,
 * but I'd also expect them to finally get their act together
 * and add some real memory barriers if so.
 *
 * Some non intel clones support out of order store. wmb() ceases to be a
 * nop for these.
 */
 

#define mb() alternative("lock; addl $0,0(%%esp)", "mfence", X86_FEATURE_XMM2)
#define rmb() alternative("lock; addl $0,0(%%esp)", "lfence", X86_FEATURE_XMM2)
#define wmb() alternative("lock; addl $0,0(%%esp)", "sfence", X86_FEATURE_XMM)

/**
 * read_barrier_depends - Flush all pending reads that subsequents reads
 * depend on.
 *
 * No data-dependent reads from memory-like regions are ever reordered
 * over this barrier.  All reads preceding this primitive are guaranteed
 * to access memory (but not necessarily other CPUs' caches) before any
 * reads following this primitive that depend on the data return by
 * any of the preceding reads.  This primitive is much lighter weight than
 * rmb() on most CPUs, and is never heavier weight than is
 * rmb().
 *
 * These ordering constraints are respected by both the local CPU
 * and the compiler.
 *
 * Ordering is not guaranteed by anything other than these primitives,
 * not even by data dependencies.  See the documentation for
 * memory_barrier() for examples and URLs to more information.
 *
 * For example, the following code would force ordering (the initial
 * value of "a" is zero, "b" is one, and "p" is "&a"):
 *
 * <programlisting>
 *	CPU 0				CPU 1
 *
 *	b = 2;
 *	memory_barrier();
 *	p = &b;				q = p;
 *					read_barrier_depends();
 *					d = *q;
 * </programlisting>
 *
 * because the read of "*q" depends on the read of "p" and these
 * two reads are separated by a read_barrier_depends().  However,
 * the following code, with the same initial values for "a" and "b":
 *
 * <programlisting>
 *	CPU 0				CPU 1
 *
 *	a = 2;
 *	memory_barrier();
 *	b = 3;				y = b;
 *					read_barrier_depends();
 *					x = a;
 * </programlisting>
 *
 * does not enforce ordering, since there is no data dependency between
 * the read of "a" and the read of "b".  Therefore, on some CPUs, such
 * as Alpha, "y" could be set to 3 and "x" to 0.  Use rmb()
 * in cases like this where there are no data dependencies.
 **/

#define read_barrier_depends()	do { } while(0)

#ifdef CONFIG_SMP
#define smp_mb()	mb()
#ifdef CONFIG_X86_PPRO_FENCE
# define smp_rmb()	rmb()
#else
# define smp_rmb()	barrier()
#endif
#ifdef CONFIG_X86_OOSTORE
# define smp_wmb() 	wmb()
#else
# define smp_wmb()	barrier()
#endif
#define smp_read_barrier_depends()	read_barrier_depends()
#define set_mb(var, value) do { (void) xchg(&var, value); } while (0)
#else
#define smp_mb()	barrier()
#define smp_rmb()	barrier()
#define smp_wmb()	barrier()
#define smp_read_barrier_depends()	do { } while(0)
#define set_mb(var, value) do { var = value; barrier(); } while (0)
#endif

#include <linux/irqflags.h>

/*
 * disable hlt during certain critical i/o operations
 */
#define HAVE_DISABLE_HLT
void disable_hlt(void);
void enable_hlt(void);

extern int es7000_plat;
void cpu_idle_wait(void);

extern unsigned long arch_align_stack(unsigned long sp);
extern void free_init_pages(char *what, unsigned long begin, unsigned long end);

void default_idle(void);
void __show_registers(struct pt_regs *, int all);

#endif
