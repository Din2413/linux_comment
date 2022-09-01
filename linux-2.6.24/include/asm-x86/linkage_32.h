#ifndef __ASM_LINKAGE_H
#define __ASM_LINKAGE_H

/*
 * __attribute__ 和 regparm关键字指定函数的参数传递方式
 * regparm(0)表示参数不使用寄存器传递，而全部使用堆栈传递
 * regparm(0)表示使用3个寄存器来传递参数(%eax, %edx, %ecx)，其余的参数使用堆栈传递
 */
#define asmlinkage CPP_ASMLINKAGE __attribute__((regparm(0)))
#define FASTCALL(x)	x __attribute__((regparm(3)))
#define fastcall	__attribute__((regparm(3)))

#define prevent_tail_call(ret) __asm__ ("" : "=r" (ret) : "0" (ret))

#ifdef CONFIG_X86_ALIGNMENT_16
#define __ALIGN .align 16,0x90
#define __ALIGN_STR ".align 16,0x90"
#endif

#endif
