#ifndef _NAMESPACE_H_
#define _NAMESPACE_H_
#ifdef __KERNEL__

#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>

/**
 * 文件系统命名空间
 */
struct mnt_namespace {
	atomic_t		count;
	struct vfsmount *	root;
	/* 属于该命名空间的、所有已挂载的文件系统描述符vfsmount形成一个双向循环链表，list指向该链表头 */
	struct list_head	list;
	wait_queue_head_t poll;
	int event;
};

extern struct mnt_namespace *copy_mnt_ns(unsigned long, struct mnt_namespace *,
		struct fs_struct *);
extern void __put_mnt_ns(struct mnt_namespace *ns);

static inline void put_mnt_ns(struct mnt_namespace *ns)
{
	if (atomic_dec_and_lock(&ns->count, &vfsmount_lock))
		/* releases vfsmount_lock */
		__put_mnt_ns(ns);
}

static inline void exit_mnt_ns(struct task_struct *p)
{
	struct mnt_namespace *ns = p->nsproxy->mnt_ns;
	if (ns)
		put_mnt_ns(ns);
}

static inline void get_mnt_ns(struct mnt_namespace *ns)
{
	atomic_inc(&ns->count);
}

#endif
#endif
