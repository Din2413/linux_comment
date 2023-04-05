#ifndef _LINUX_FS_STRUCT_H
#define _LINUX_FS_STRUCT_H

struct dentry;
struct vfsmount;

/* 进程与文件系统相互作用的数据 */
struct fs_struct {
	atomic_t count;
	rwlock_t lock;
	int umask;
	/*
	 * 每个进程都有它自己当前的工作目录和它自己的根目录
	 * root表示根目录的目录项对象、pwd表示当前工作目录的目录项对象、altroot表示模拟根目录的目录项
	 * rootmnt表示根目录所安装的文件系统对象、pwdmnt表示当前工作目录所安装的文件系统对象、altrootmnt表示模拟根目录所安装的文件系统对象
	 */
	struct dentry * root, * pwd, * altroot;
	struct vfsmount * rootmnt, * pwdmnt, * altrootmnt;
};

#define INIT_FS {				\
	.count		= ATOMIC_INIT(1),	\
	.lock		= RW_LOCK_UNLOCKED,	\
	.umask		= 0022, \
}

extern struct kmem_cache *fs_cachep;

extern void exit_fs(struct task_struct *);
extern void set_fs_altroot(void);
extern void set_fs_root(struct fs_struct *, struct vfsmount *, struct dentry *);
extern void set_fs_pwd(struct fs_struct *, struct vfsmount *, struct dentry *);
extern struct fs_struct *copy_fs_struct(struct fs_struct *);
extern void put_fs_struct(struct fs_struct *);

#endif /* _LINUX_FS_STRUCT_H */
