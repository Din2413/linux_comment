#ifndef _LINUX_NAMEI_H
#define _LINUX_NAMEI_H

#include <linux/dcache.h>
#include <linux/linkage.h>

struct vfsmount;

struct open_intent {
	int	flags;
	int	create_mode;
	struct file *file;
};

enum { MAX_NESTED_LINKS = 8 };

/* 存放文件路径查找操作的结果 */
struct nameidata {
	/* 所解析的最后一个路径分量的目录项对象 */
	struct dentry	*dentry;
	/* 所解析的最后一个路径分量的已安装文件系统对象 */
	struct vfsmount *mnt;
	/* 路径名的最后一个分量 */
	struct qstr	last;
	unsigned int	flags;
	int		last_type;
	/* 符号连接嵌套的当前级别 */
	unsigned	depth;
	char *saved_names[MAX_NESTED_LINKS + 1];

	/* Intent data */
	union {
		struct open_intent open;
	} intent;
};

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

/*
 * Type of the last component on LOOKUP_PARENT
 */
enum {LAST_NORM, LAST_ROOT, LAST_DOT, LAST_DOTDOT, LAST_BIND};

/*
 * The bitmask for a lookup event:
 *  - follow links at the end
 *  - require a directory
 *  - ending slashes ok even for nonexistent files
 *  - internal "there are more path compnents" flag
 *  - locked when lookup done with dcache_lock held
 *  - dentry cache is untrusted; force a real lookup
 */
/**
 * 文件路径名查找标志
 * LOOKUP_FOLLOW：如果最后一个分量是符号链接，则解释（追踪）它
 * LOOKUP_DIRECTORY：最后一个分量必须是目录
 * LOOKUP_CONTINUE：在路径名中还有文件名要检查
 * LOOKUP_PARENT：查找最后一个分量名所在的目录
 * LOOKUP_NOALT：不考虑模拟根目录
 * LOOKUP_OPEN：试图打开一个文件
 * LOOKUP_CREATE：试图创建一个文件（如果不存在）
 * LOOKUP_ACCESS：试图为一个文件检查用户的权限
 */
#define LOOKUP_FOLLOW		 1
#define LOOKUP_DIRECTORY	 2
#define LOOKUP_CONTINUE		 4
#define LOOKUP_PARENT		16
#define LOOKUP_NOALT		32
#define LOOKUP_REVAL		64
/*
 * Intent data
 */
#define LOOKUP_OPEN		(0x0100)
#define LOOKUP_CREATE		(0x0200)
#define LOOKUP_ACCESS		(0x0400)
#define LOOKUP_CHDIR		(0x0800)

extern int FASTCALL(__user_walk(const char __user *, unsigned, struct nameidata *));
extern int FASTCALL(__user_walk_fd(int dfd, const char __user *, unsigned, struct nameidata *));
#define user_path_walk(name,nd) \
	__user_walk_fd(AT_FDCWD, name, LOOKUP_FOLLOW, nd)
#define user_path_walk_link(name,nd) \
	__user_walk_fd(AT_FDCWD, name, 0, nd)
extern int FASTCALL(path_lookup(const char *, unsigned, struct nameidata *));
extern int vfs_path_lookup(struct dentry *, struct vfsmount *,
			   const char *, unsigned int, struct nameidata *);
extern void path_release(struct nameidata *);
extern void path_release_on_umount(struct nameidata *);

extern int __user_path_lookup_open(const char __user *, unsigned lookup_flags, struct nameidata *nd, int open_flags);
extern int path_lookup_open(int dfd, const char *name, unsigned lookup_flags, struct nameidata *, int open_flags);
extern struct file *lookup_instantiate_filp(struct nameidata *nd, struct dentry *dentry,
		int (*open)(struct inode *, struct file *));
extern struct file *nameidata_to_filp(struct nameidata *nd, int flags);
extern void release_open_intent(struct nameidata *);

extern struct dentry *lookup_one_len(const char *, struct dentry *, int);
extern struct dentry *lookup_one_noperm(const char *, struct dentry *);

extern int follow_down(struct vfsmount **, struct dentry **);
extern int follow_up(struct vfsmount **, struct dentry **);

extern struct dentry *lock_rename(struct dentry *, struct dentry *);
extern void unlock_rename(struct dentry *, struct dentry *);

static inline void nd_set_link(struct nameidata *nd, char *path)
{
	nd->saved_names[nd->depth] = path;
}

static inline char *nd_get_link(struct nameidata *nd)
{
	return nd->saved_names[nd->depth];
}

#endif /* _LINUX_NAMEI_H */
