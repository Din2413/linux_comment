/*
 * Wrapper functions for accessing the file_struct fd array.
 */

#ifndef __LINUX_FILE_H
#define __LINUX_FILE_H

#include <asm/atomic.h>
#include <linux/posix_types.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

/*
 * The default fd array needs to be at least BITS_PER_LONG,
 * as this is the granularity returned by copy_fdset().
 */
#define NR_OPEN_DEFAULT BITS_PER_LONG

/*
 * The embedded_fd_set is a small fd_set,
 * suitable for most tasks (which open <= BITS_PER_LONG files)
 */
struct embedded_fd_set {
	unsigned long fds_bits[1];
};

struct fdtable {
	/* 文件对象的当前最大数目 */
	unsigned int max_fds;
	/* 指向文件对象指针数组的指针 */
	struct file ** fd;      /* current fd array */
	/* 指向指向exec()时需要关闭的文件描述符的指针 */
	fd_set *close_on_exec;
	/* 指向打开文件描述符的指针 */
	fd_set *open_fds;
	struct rcu_head rcu;
	struct fdtable *next;
};

/*
 * Open file table structure
 * 进程当前打开的文件表
 */
struct files_struct {
  /*
   * read mostly part 共享该表的进程数目
   */
	atomic_t count;
	/**
	 * 进程当前打开文件的文件描述符表，初始时默认指向files_struct结构的fdtab字段
	 * 最大可以保存32个文件描述符，当超过限制时，需要重新分配fatable结构对象并将fdtab拷贝过去，并设置fdt指向
	 */
	struct fdtable *fdt;
	/* 打开文件的文件描述符表的初始集合 */
	struct fdtable fdtab;
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	/* 所分配的最大文件描述符加1 */
	int next_fd;
	/* 指向指向exec()时需要关闭的文件描述符的初始集合 */
	struct embedded_fd_set close_on_exec_init;
	/* 文件描述符的初始集合 */
	struct embedded_fd_set open_fds_init;
	/* 文件对象指针的初始数组 */
	struct file * fd_array[NR_OPEN_DEFAULT];
};

#define files_fdtable(files) (rcu_dereference((files)->fdt))

extern struct kmem_cache *filp_cachep;

extern void FASTCALL(__fput(struct file *));
extern void FASTCALL(fput(struct file *));

struct file_operations;
struct vfsmount;
struct dentry;
extern int init_file(struct file *, struct vfsmount *mnt,
		struct dentry *dentry, mode_t mode,
		const struct file_operations *fop);
extern struct file *alloc_file(struct vfsmount *, struct dentry *dentry,
		mode_t mode, const struct file_operations *fop);

static inline void fput_light(struct file *file, int fput_needed)
{
	if (unlikely(fput_needed))
		fput(file);
}

extern struct file * FASTCALL(fget(unsigned int fd));
extern struct file * FASTCALL(fget_light(unsigned int fd, int *fput_needed));
extern void FASTCALL(set_close_on_exec(unsigned int fd, int flag));
extern void put_filp(struct file *);
extern int get_unused_fd(void);
extern int get_unused_fd_flags(int flags);
extern void FASTCALL(put_unused_fd(unsigned int fd));
struct kmem_cache;

extern int expand_files(struct files_struct *, int nr);
extern void free_fdtable_rcu(struct rcu_head *rcu);
extern void __init files_defer_init(void);

static inline void free_fdtable(struct fdtable *fdt)
{
	call_rcu(&fdt->rcu, free_fdtable_rcu);
}

static inline struct file * fcheck_files(struct files_struct *files, unsigned int fd)
{
	struct file * file = NULL;
	struct fdtable *fdt = files_fdtable(files);

	if (fd < fdt->max_fds)
		file = rcu_dereference(fdt->fd[fd]);
	return file;
}

/*
 * Check whether the specified fd has an open file.
 */
#define fcheck(fd)	fcheck_files(current->files, fd)

extern void FASTCALL(fd_install(unsigned int fd, struct file * file));

struct task_struct;

struct files_struct *get_files_struct(struct task_struct *);
void FASTCALL(put_files_struct(struct files_struct *fs));
void reset_files_struct(struct task_struct *, struct files_struct *);

extern struct kmem_cache *files_cachep;

#endif /* __LINUX_FILE_H */
