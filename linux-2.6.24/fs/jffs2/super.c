/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/mount.h>
#include <linux/jffs2.h>
#include <linux/pagemap.h>
#include <linux/mtd/super.h>
#include <linux/ctype.h>
#include <linux/namei.h>
#include "compr.h"
#include "nodelist.h"

static void jffs2_put_super(struct super_block *);

static struct kmem_cache *jffs2_inode_cachep;

/*
 * jffs2文件系统创建inode对象的函数
 * inode与super_block一样，也是VFS虚拟文件系统中的通用数据结构，用于表示文件的通用信息，如：权限、大小、创建时间等
 * 不同类型的文件系统中数据的组织、存储格式不同，索引文件文件数据的机制显然应该放到文件系统的特定数据结构中
 * 如：jffs2文件系统的jffs2_inode_info，其中vfs_inode字段指向与之对应的通用文件节点inode
 */
static struct inode *jffs2_alloc_inode(struct super_block *sb)
{
	struct jffs2_inode_info *ei;
	ei = (struct jffs2_inode_info *)kmem_cache_alloc(jffs2_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void jffs2_destroy_inode(struct inode *inode)
{
	kmem_cache_free(jffs2_inode_cachep, JFFS2_INODE_INFO(inode));
}

static void jffs2_i_init_once(struct kmem_cache *cachep, void *foo)
{
	struct jffs2_inode_info *ei = (struct jffs2_inode_info *) foo;

	init_MUTEX(&ei->sem);
	inode_init_once(&ei->vfs_inode);
}

static int jffs2_sync_fs(struct super_block *sb, int wait)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(sb);

	down(&c->alloc_sem);
	jffs2_flush_wbuf_pad(c);
	up(&c->alloc_sem);
	return 0;
}

static const struct super_operations jffs2_super_operations =
{
	/* 创建inode */
	.alloc_inode =	jffs2_alloc_inode,
	/* 销毁inode */
	.destroy_inode =jffs2_destroy_inode,
	/* 读取inode */
	.read_inode =	jffs2_read_inode,
	.put_super =	jffs2_put_super,
	.write_super =	jffs2_write_super,
	.statfs =	jffs2_statfs,
	.remount_fs =	jffs2_remount_fs,
	.clear_inode =	jffs2_clear_inode,
	.dirty_inode =	jffs2_dirty_inode,
	.sync_fs =	jffs2_sync_fs,
};

/*
 * fill in the superblock
 */
static int jffs2_fill_super(struct super_block *sb, void *data, int silent)
{
	struct jffs2_sb_info *c;

	D1(printk(KERN_DEBUG "jffs2_get_sb_mtd():"
		  " New superblock for device %d (\"%s\")\n",
		  sb->s_mtd->index, sb->s_mtd->name));

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return -ENOMEM;

	c->mtd = sb->s_mtd;
	c->os_priv = sb;
	sb->s_fs_info = c;

	/* Initialize JFFS2 superblock locks, the further initialization will
	 * be done later */
	init_MUTEX(&c->alloc_sem);
	init_MUTEX(&c->erase_free_sem);
	init_waitqueue_head(&c->erase_wait);
	init_waitqueue_head(&c->inocache_wq);
	spin_lock_init(&c->erase_completion_lock);
	spin_lock_init(&c->inocache_lock);

	/* 设置超级块函数指针，用于读取、写回inode */
	sb->s_op = &jffs2_super_operations;
	sb->s_flags = sb->s_flags | MS_NOATIME;
	sb->s_xattr = jffs2_xattr_handlers;
#ifdef CONFIG_JFFS2_FS_POSIX_ACL
	sb->s_flags |= MS_POSIXACL;
#endif
	return jffs2_do_fill_super(sb, data, silent);
}

/*
 * jffs2挂载时回调函数，用于初始化super_block结构
 *
 * super_block是虚拟文件系统通用框架中用于表示文件系统超级块的数据结构
 * 每类文件系统都存在独特于其他文件系统的特定信息，这部分则存储在文件系统的特定超级块结构中，
 * 比如jffs2的struct jffs2_sb_info，该特定结构由super_block的s_fs_info指向
 */
static int jffs2_get_sb(struct file_system_type *fs_type,
			int flags, const char *dev_name,
			void *data, struct vfsmount *mnt)
{
	/* jffs2文件系统是为mtd设备（nor/nand flash）专门设计实现的，调用get_sb_mtd指定挂载设备类型为mtd，并最终回调jffs2_fill_super */
	return get_sb_mtd(fs_type, flags, dev_name, data, jffs2_fill_super,
			  mnt);
}

static void jffs2_put_super (struct super_block *sb)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(sb);

	D2(printk(KERN_DEBUG "jffs2: jffs2_put_super()\n"));

	down(&c->alloc_sem);
	jffs2_flush_wbuf_pad(c);
	up(&c->alloc_sem);

	jffs2_sum_exit(c);

	jffs2_free_ino_caches(c);
	jffs2_free_raw_node_refs(c);
	if (jffs2_blocks_use_vmalloc(c))
		vfree(c->blocks);
	else
		kfree(c->blocks);
	jffs2_flash_cleanup(c);
	kfree(c->inocache_list);
	jffs2_clear_xattr_subsystem(c);
	if (c->mtd->sync)
		c->mtd->sync(c->mtd);

	D1(printk(KERN_DEBUG "jffs2_put_super returning\n"));
}

static void jffs2_kill_sb(struct super_block *sb)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(sb);
	if (!(sb->s_flags & MS_RDONLY))
		jffs2_stop_garbage_collect_thread(c);
	kill_mtd_super(sb);
	kfree(c);
}

/**
 * 闪存设备的最小寻址单位是字节(byte)，而不是磁盘上的扇区(sector)，读可以从闪存的任意偏移进行，
 * 一块闪存处于干净状态时，每一位都是逻辑1，写操作可以将逻辑1置成逻辑0，但把逻辑0置成逻辑1却不能按位操作，而只能按擦写块进行擦写操作，
 * 闪存的使用寿命是由擦写块的最大可擦写次数决定的，超过了最大可擦写次数，这个擦写块就被标记成坏块，
 * 为避免某个擦写块被过度擦写，在尽量小的影响性能的前提下，应使擦写操作均匀分布在每个擦写块上（磨损均衡）。
 *
 * 将磁盘文件系统(如ext2)运行在闪存上的很自然的方法就是在文件系统和闪存之间提供一个闪存转换层(Flash Translation Layer)，
 * 转换层将底层的闪存模拟成一个具有512字节扇区大小的标准块设备(block device，mtdblock就是基于这种机制实现的)。
 * 但为了解决低效率、磨损不均衡、掉电数据损坏等问题，转换层不能简单的将扇区一对一地映射到mtd的某一固定区域（磁盘in-place更新方式），
 * 并且转换层还必须能够理解上层文件系统的语义（改写、追加等），否则无法实现磨损均衡和垃圾回收机制。这就必须对写请求进行解析，从而带来写操作性能的下降。
 *
 * jffs就是为了解决上述问题，重新实现的一个特别针对闪存设备的文件系统。
 *
 * JFFS2是一种日志结构文件系统（采样out-of-place的方式对闪存数据进行更新，而不是磁盘的in-place的更新方式），设计用于嵌入式系统中的闪存设备
 * 它不像旧闪存解决方案那样在闪存设备上使用一种转换层来模拟普通硬盘驱动器，而是将文件系统直接放在闪存芯片上。
 */
static struct file_system_type jffs2_fs_type = {
	.owner =	THIS_MODULE,
	.name =		"jffs2",
	.get_sb =	jffs2_get_sb,
	.kill_sb =	jffs2_kill_sb,
};

static int __init init_jffs2_fs(void)
{
	int ret;

	/* Paranoia checks for on-medium structures. If we ask GCC
	   to pack them with __attribute__((packed)) then it _also_
	   assumes that they're not aligned -- so it emits crappy
	   code on some architectures. Ideally we want an attribute
	   which means just 'no padding', without the alignment
	   thing. But GCC doesn't have that -- we have to just
	   hope the structs are the right sizes, instead. */
	BUILD_BUG_ON(sizeof(struct jffs2_unknown_node) != 12);
	BUILD_BUG_ON(sizeof(struct jffs2_raw_dirent) != 40);
	BUILD_BUG_ON(sizeof(struct jffs2_raw_inode) != 68);
	BUILD_BUG_ON(sizeof(struct jffs2_raw_summary) != 32);

	printk(KERN_INFO "JFFS2 version 2.2."
#ifdef CONFIG_JFFS2_FS_WRITEBUFFER
	       " (NAND)"
#endif
#ifdef CONFIG_JFFS2_SUMMARY
	       " (SUMMARY) "
#endif
	       " © 2001-2006 Red Hat, Inc.\n");

	/* 初始化jffs2_inode_info slab缓存 */
	jffs2_inode_cachep = kmem_cache_create("jffs2_i",
					     sizeof(struct jffs2_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     jffs2_i_init_once);
	if (!jffs2_inode_cachep) {
		printk(KERN_ERR "JFFS2 error: Failed to initialise inode cache\n");
		return -ENOMEM;
	}
	/* 初始化jffs2压缩算法，jffs2文件系统支持数据压缩存储，意味着实际可写入的数据量可以超过文件系统挂载的分区大小 */
	ret = jffs2_compressors_init();
	if (ret) {
		printk(KERN_ERR "JFFS2 error: Failed to initialise compressors\n");
		goto out;
	}
	ret = jffs2_create_slab_caches();
	if (ret) {
		printk(KERN_ERR "JFFS2 error: Failed to initialise slab caches\n");
		goto out_compressors;
	}
	/* 注册jffs2文件系统类型 */
	ret = register_filesystem(&jffs2_fs_type);
	if (ret) {
		printk(KERN_ERR "JFFS2 error: Failed to register filesystem\n");
		goto out_slab;
	}
	return 0;

 out_slab:
	jffs2_destroy_slab_caches();
 out_compressors:
	jffs2_compressors_exit();
 out:
	kmem_cache_destroy(jffs2_inode_cachep);
	return ret;
}

static void __exit exit_jffs2_fs(void)
{
	unregister_filesystem(&jffs2_fs_type);
	jffs2_destroy_slab_caches();
	jffs2_compressors_exit();
	kmem_cache_destroy(jffs2_inode_cachep);
}

module_init(init_jffs2_fs);
module_exit(exit_jffs2_fs);

MODULE_DESCRIPTION("The Journalling Flash File System, v2");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL"); // Actually dual-licensed, but it doesn't matter for
		       // the sake of this tag. It's Free Software.
