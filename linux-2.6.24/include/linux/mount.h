/*
 *
 * Definitions for mount interface. This describes the in the kernel build 
 * linkedlist with mounted filesystems.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 * Version: $Id: mount.h,v 2.0 1996/11/17 16:48:14 mvw Exp mvw $
 *
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H
#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

struct super_block;
struct vfsmount;
struct dentry;
struct mnt_namespace;

#define MNT_NOSUID	0x01
#define MNT_NODEV	0x02
#define MNT_NOEXEC	0x04
#define MNT_NOATIME	0x08
#define MNT_NODIRATIME	0x10
#define MNT_RELATIME	0x20

#define MNT_SHRINKABLE	0x100

#define MNT_SHARED	0x1000	/* if the vfsmount is a shared mount */
#define MNT_UNBINDABLE	0x2000	/* if the vfsmount is a unbindable mount */
#define MNT_PNODE_MASK	0x3000	/* propagation flag mask */

/**
 * 已安装文件系统描述符
 * 1、Linux同一文件系统被安装多次是可能的，多次安装的文件系统可通过多个安装点访问，但文件系统是唯一的
 * 2、把多个文件系统安装堆叠再同一个安装点也是可能的，新安装的文件系统隐藏前一个安装的文件系统，但是已经使用先前安装文件系统的文件的进程可以继续使用
 * 3、安装的文件系统形成一个树形结构，子文件系统可以安装在父文件系统的目录上
 */
struct vfsmount {
	/* 散列表链表指针，由父文件系统的vfsmount描述符和安装点目录项对象索引 */
	struct list_head mnt_hash;
	/* 指向父文件系统，当前文件系统安装在其上 */
	struct vfsmount *mnt_parent;	/* fs we are mounted on */
	/* 指向当前文件系统安装点目录的dentry */
	struct dentry *mnt_mountpoint;	/* dentry of mountpoint */
	/* 指向当前文件系统根目录的dentry */
	struct dentry *mnt_root;	/* root of the mounted tree */
	/* 指向当前文件系统的超级块对象 */
	struct super_block *mnt_sb;	/* pointer to superblock */
	/* 对于每个已安装文件系统，所有已安装的子文件系统组成一个双向循环链表，由mnt_mounts字段指向 */
	struct list_head mnt_mounts;	/* list of children, anchored here */
	/* 挂接到所属父文件系统的所有已安装子文件系统双向循环链表上 */
	struct list_head mnt_child;	/* and going through their mnt_child */
	int mnt_flags;
	/* 4 bytes hole on 64bits arches */
	char *mnt_devname;		/* Name of device e.g. /dev/dsk/hda1 */
	/**
	 * 每个命名空间，所有属于此命名空间的vfsmount描述符组成一个双向循环链表
	 * mnt_namespace结构的list字段存放链表的头，mnt_list字段包含链表中指向相邻元素的指针
	 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct vfsmount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	/*
	 * We put mnt_count & mnt_expiry_mark at the end of struct vfsmount
	 * to let these frequently modified fields in a separate cache line
	 * (so that reads of mnt_flags wont ping-pong on SMP machines)
	 */
	/* 引用计数 */
	atomic_t mnt_count;
	int mnt_expiry_mark;		/* true if marked for expiry */
	int mnt_pinned;
};

static inline struct vfsmount *mntget(struct vfsmount *mnt)
{
	if (mnt)
		atomic_inc(&mnt->mnt_count);
	return mnt;
}

extern void mntput_no_expire(struct vfsmount *mnt);
extern void mnt_pin(struct vfsmount *mnt);
extern void mnt_unpin(struct vfsmount *mnt);

static inline void mntput(struct vfsmount *mnt)
{
	if (mnt) {
		mnt->mnt_expiry_mark = 0;
		mntput_no_expire(mnt);
	}
}

extern void free_vfsmnt(struct vfsmount *mnt);
extern struct vfsmount *alloc_vfsmnt(const char *name);
extern struct vfsmount *do_kern_mount(const char *fstype, int flags,
				      const char *name, void *data);

struct file_system_type;
extern struct vfsmount *vfs_kern_mount(struct file_system_type *type,
				      int flags, const char *name,
				      void *data);

struct nameidata;

extern int do_add_mount(struct vfsmount *newmnt, struct nameidata *nd,
			int mnt_flags, struct list_head *fslist);

extern void mark_mounts_for_expiry(struct list_head *mounts);
extern void shrink_submounts(struct vfsmount *mountpoint, struct list_head *mounts);

extern spinlock_t vfsmount_lock;
extern dev_t name_to_dev_t(char *name);

#endif
#endif /* _LINUX_MOUNT_H */
