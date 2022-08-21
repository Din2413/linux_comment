/*
 * $Id: mtd_blkdevs.c,v 1.27 2005/11/07 11:14:20 gleixner Exp $
 *
 * (C) 2003 David Woodhouse <dwmw2@infradead.org>
 *
 * Interface to Linux 2.5 block layer for MTD 'translation layers'.
 *
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/mtd/blktrans.h>
#include <linux/mtd/mtd.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/freezer.h>
#include <linux/spinlock.h>
#include <linux/hdreg.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <asm/uaccess.h>

#include "mtdcore.h"

static LIST_HEAD(blktrans_majors);

struct mtd_blkcore_priv {
	struct task_struct *thread;
	struct request_queue *rq;
	spinlock_t queue_lock;
};

static int do_blktrans_request(struct mtd_blktrans_ops *tr,
			       struct mtd_blktrans_dev *dev,
			       struct request *req)
{
	unsigned long block, nsect;
	char *buf;

	block = req->sector << 9 >> tr->blkshift;
	nsect = req->current_nr_sectors << 9 >> tr->blkshift;

	buf = req->buffer;

	if (!blk_fs_request(req))
		return 0;

	if (req->sector + req->current_nr_sectors > get_capacity(req->rq_disk))
		return 0;

	switch(rq_data_dir(req)) {
	case READ:
		for (; nsect > 0; nsect--, block++, buf += tr->blksize)
			if (tr->readsect(dev, block, buf))
				return 0;
		return 1;

	case WRITE:
		if (!tr->writesect)
			return 0;

		for (; nsect > 0; nsect--, block++, buf += tr->blksize)
			if (tr->writesect(dev, block, buf))
				return 0;
		return 1;

	default:
		printk(KERN_NOTICE "Unknown request %u\n", rq_data_dir(req));
		return 0;
	}
}

static int mtd_blktrans_thread(void *arg)
{
	struct mtd_blktrans_ops *tr = arg;
	struct request_queue *rq = tr->blkcore_priv->rq;

	/* we might get involved when memory gets low, so use PF_MEMALLOC */
	current->flags |= PF_MEMALLOC;

	spin_lock_irq(rq->queue_lock);
	while (!kthread_should_stop()) {
		struct request *req;
		struct mtd_blktrans_dev *dev;
		int res = 0;

		req = elv_next_request(rq);

		if (!req) {
			set_current_state(TASK_INTERRUPTIBLE);
			spin_unlock_irq(rq->queue_lock);
			schedule();
			spin_lock_irq(rq->queue_lock);
			continue;
		}

		dev = req->rq_disk->private_data;
		tr = dev->tr;

		spin_unlock_irq(rq->queue_lock);

		mutex_lock(&dev->lock);
		res = do_blktrans_request(tr, dev, req);
		mutex_unlock(&dev->lock);

		spin_lock_irq(rq->queue_lock);

		end_request(req, res);
	}
	spin_unlock_irq(rq->queue_lock);

	return 0;
}

static void mtd_blktrans_request(struct request_queue *rq)
{
	struct mtd_blktrans_ops *tr = rq->queuedata;
	wake_up_process(tr->blkcore_priv->thread);
}


static int blktrans_open(struct inode *i, struct file *f)
{
	struct mtd_blktrans_dev *dev;
	struct mtd_blktrans_ops *tr;
	int ret = -ENODEV;

	dev = i->i_bdev->bd_disk->private_data;
	tr = dev->tr;

	if (!try_module_get(dev->mtd->owner))
		goto out;

	if (!try_module_get(tr->owner))
		goto out_tr;

	/* FIXME: Locking. A hot pluggable device can go away
	   (del_mtd_device can be called for it) without its module
	   being unloaded. */
	dev->mtd->usecount++;

	ret = 0;
	if (tr->open && (ret = tr->open(dev))) {
		dev->mtd->usecount--;
		module_put(dev->mtd->owner);
	out_tr:
		module_put(tr->owner);
	}
 out:
	return ret;
}

static int blktrans_release(struct inode *i, struct file *f)
{
	struct mtd_blktrans_dev *dev;
	struct mtd_blktrans_ops *tr;
	int ret = 0;

	dev = i->i_bdev->bd_disk->private_data;
	tr = dev->tr;

	if (tr->release)
		ret = tr->release(dev);

	if (!ret) {
		dev->mtd->usecount--;
		module_put(dev->mtd->owner);
		module_put(tr->owner);
	}

	return ret;
}

static int blktrans_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	struct mtd_blktrans_dev *dev = bdev->bd_disk->private_data;

	if (dev->tr->getgeo)
		return dev->tr->getgeo(dev, geo);
	return -ENOTTY;
}

static int blktrans_ioctl(struct inode *inode, struct file *file,
			      unsigned int cmd, unsigned long arg)
{
	struct mtd_blktrans_dev *dev = inode->i_bdev->bd_disk->private_data;
	struct mtd_blktrans_ops *tr = dev->tr;

	switch (cmd) {
	case BLKFLSBUF:
		if (tr->flush)
			return tr->flush(dev);
		/* The core code did the work, we had nothing to do. */
		return 0;
	default:
		return -ENOTTY;
	}
}

/**
 * 字符设备使用file_operations告诉系统对它们的操作接口
 * 块设备则使用block_device_operations
 *
 * 块设备操作函数集合未提供读写接口，因为读写操作是由request函数处理的
 */
static struct block_device_operations mtd_blktrans_ops = {
	.owner		= THIS_MODULE,
	/* 块设备被打开或关闭时调用 */
	.open		= blktrans_open,
	.release	= blktrans_release,
	/* 实现ioctl系统调用的函数，块设备层会首先截取大量的标准请求 */
	.ioctl		= blktrans_ioctl,
	.getgeo		= blktrans_getgeo,
};

int add_mtd_blktrans_dev(struct mtd_blktrans_dev *new)
{
	struct mtd_blktrans_ops *tr = new->tr;
	struct list_head *this;
	int last_devnum = -1;
	struct gendisk *gd;

	if (mutex_trylock(&mtd_table_mutex)) {
		mutex_unlock(&mtd_table_mutex);
		BUG();
	}

	/* 判断mtd设备的模拟块设备是否已创建，若未创建则将mtd设备按index从小到大挂在mtd_blktrans_ops的devs成员指向的双向链表 */
	list_for_each(this, &tr->devs) {
		struct mtd_blktrans_dev *d = list_entry(this, struct mtd_blktrans_dev, list);
		if (new->devnum == -1) {
			/* Use first free number */
			if (d->devnum != last_devnum+1) {
				/* Found a free devnum. Plug it in here */
				new->devnum = last_devnum+1;
				list_add_tail(&new->list, &d->list);
				goto added;
			}
		} else if (d->devnum == new->devnum) {
			/* Required number taken */
			return -EBUSY;
		} else if (d->devnum > new->devnum) {
			/* Required number was free */
			list_add_tail(&new->list, &d->list);
			goto added;
		}
		last_devnum = d->devnum;
	}
	if (new->devnum == -1)
		new->devnum = last_devnum+1;

	if ((new->devnum << tr->part_bits) > 256) {
		return -EBUSY;
	}

	mutex_init(&new->lock);
	list_add_tail(&new->list, &tr->devs);
 added:
	if (!tr->writesect)
		new->readonly = 1;

	/**
	 * 分配一个gendisk结构体的实例，表示一个磁盘设备
	 * 一个驱动器至少使用一个次设备号，如果驱动器是可被分区的，要为每个可能的分区分配一个次设备号
	 */
	gd = alloc_disk(1 << tr->part_bits);
	if (!gd) {
		list_del(&new->list);
		return -ENOMEM;
	}
	gd->major = tr->major;
	gd->first_minor = (new->devnum) << tr->part_bits;
	/* mtd块设备操作函数集合 */
	gd->fops = &mtd_blktrans_ops;

	if (tr->part_bits)
		if (new->devnum < 26)
			snprintf(gd->disk_name, sizeof(gd->disk_name),
				 "%s%c", tr->name, 'a' + new->devnum);
		else
			snprintf(gd->disk_name, sizeof(gd->disk_name),
				 "%s%c%c", tr->name,
				 'a' - 1 + new->devnum / 26,
				 'a' + new->devnum % 26);
	else
		snprintf(gd->disk_name, sizeof(gd->disk_name),
			 "%s%d", tr->name, new->devnum);

	/* 2.5 has capacity in units of 512 bytes while still
	   having BLOCK_SIZE_BITS set to 10. Just to keep us amused. */
	/* 块设备容量，以512字节的扇区为单位的个数 */
	set_capacity(gd, (new->size * tr->blksize) >> 9);

	gd->private_data = new;
	new->blkcore_priv = gd;
	/* mtd块设备请求队列（同一转换层的模拟块设备共用一个请求队列），管理该设备的I/O请求 */
	gd->queue = tr->blkcore_priv->rq;

	if (new->readonly)
		set_disk_ro(gd, 1);

	/* 将gendisk结构体实例注册到系统中 */
	add_disk(gd);

	return 0;
}

int del_mtd_blktrans_dev(struct mtd_blktrans_dev *old)
{
	if (mutex_trylock(&mtd_table_mutex)) {
		mutex_unlock(&mtd_table_mutex);
		BUG();
	}

	list_del(&old->list);

	del_gendisk(old->blkcore_priv);
	put_disk(old->blkcore_priv);

	return 0;
}

/* 移除mtd设备时（del_mtd_device）回调 */
static void blktrans_notify_remove(struct mtd_info *mtd)
{
	struct list_head *this, *this2, *next;

	/* 遍历所有注册的mtd块设备转换层，调用remove_dev接口删除各个转换层内对应创建的mtd块设备 */
	list_for_each(this, &blktrans_majors) {
		struct mtd_blktrans_ops *tr = list_entry(this, struct mtd_blktrans_ops, list);

		list_for_each_safe(this2, next, &tr->devs) {
			struct mtd_blktrans_dev *dev = list_entry(this2, struct mtd_blktrans_dev, list);

			if (dev->mtd == mtd)
				tr->remove_dev(dev);
		}
	}
}

/* 新增mtd设备时（add_mtd_device）回调 */
static void blktrans_notify_add(struct mtd_info *mtd)
{
	struct list_head *this;

	if (mtd->type == MTD_ABSENT)
		return;

	/* 遍历所有注册的mtd块设备转换层，调用add_mtd接口为每个转换层创建对应的mtd块设备 */
	list_for_each(this, &blktrans_majors) {
		struct mtd_blktrans_ops *tr = list_entry(this, struct mtd_blktrans_ops, list);

		tr->add_mtd(tr, mtd);
	}

}

static struct mtd_notifier blktrans_notifier = {
	.add = blktrans_notify_add,
	.remove = blktrans_notify_remove,
};

int register_mtd_blktrans(struct mtd_blktrans_ops *tr)
{
	int ret, i;

	/* Register the notifier if/when the first device type is
	   registered, to prevent the link/init ordering from fucking      
	   us over. */
	/**
	 * 注册mtd设备状态（add、remove）变更的通知器
	 * 只在首个mtd块设备转换层注册时，add、remove回调会对所有的转换层遍历处理，对应块设备添加、删除
	 */
	if (!blktrans_notifier.list.next)
		register_mtd_user(&blktrans_notifier);

	tr->blkcore_priv = kzalloc(sizeof(*tr->blkcore_priv), GFP_KERNEL);
	if (!tr->blkcore_priv)
		return -ENOMEM;

	mutex_lock(&mtd_table_mutex);

	/* 注册块设备驱动并申请主设备号，此时还没创建设备节点，即/dev目录下还不存在设备文件 */
	ret = register_blkdev(tr->major, tr->name);
	if (ret) {
		printk(KERN_WARNING "Unable to register %s block device on major %d: %d\n",
		       tr->name, tr->major, ret);
		kfree(tr->blkcore_priv);
		mutex_unlock(&mtd_table_mutex);
		return ret;
	}
	spin_lock_init(&tr->blkcore_priv->queue_lock);

	/* 初始化块设备请求队列 */
	tr->blkcore_priv->rq = blk_init_queue(mtd_blktrans_request, &tr->blkcore_priv->queue_lock);
	if (!tr->blkcore_priv->rq) {
		unregister_blkdev(tr->major, tr->name);
		kfree(tr->blkcore_priv);
		mutex_unlock(&mtd_table_mutex);
		return -ENOMEM;
	}

	tr->blkcore_priv->rq->queuedata = tr;
	blk_queue_hardsect_size(tr->blkcore_priv->rq, tr->blksize);
	tr->blkshift = ffs(tr->blksize) - 1;

	tr->blkcore_priv->thread = kthread_run(mtd_blktrans_thread, tr,
			"%sd", tr->name);
	if (IS_ERR(tr->blkcore_priv->thread)) {
		blk_cleanup_queue(tr->blkcore_priv->rq);
		unregister_blkdev(tr->major, tr->name);
		kfree(tr->blkcore_priv);
		mutex_unlock(&mtd_table_mutex);
		return PTR_ERR(tr->blkcore_priv->thread);
	}

	INIT_LIST_HEAD(&tr->devs);
	list_add(&tr->list, &blktrans_majors);

	/* 为已创建的mtd设备调用通知器的add回调，创建对应的mtd块设备 */
	for (i=0; i<MAX_MTD_DEVICES; i++) {
		if (mtd_table[i] && mtd_table[i]->type != MTD_ABSENT)
			tr->add_mtd(tr, mtd_table[i]);
	}

	mutex_unlock(&mtd_table_mutex);

	return 0;
}

int deregister_mtd_blktrans(struct mtd_blktrans_ops *tr)
{
	struct list_head *this, *next;

	mutex_lock(&mtd_table_mutex);

	/* Clean up the kernel thread */
	kthread_stop(tr->blkcore_priv->thread);

	/* Remove it from the list of active majors */
	list_del(&tr->list);

	list_for_each_safe(this, next, &tr->devs) {
		struct mtd_blktrans_dev *dev = list_entry(this, struct mtd_blktrans_dev, list);
		tr->remove_dev(dev);
	}

	/* 清除块设备请求队列 */
	blk_cleanup_queue(tr->blkcore_priv->rq);
	unregister_blkdev(tr->major, tr->name);

	mutex_unlock(&mtd_table_mutex);

	kfree(tr->blkcore_priv);

	BUG_ON(!list_empty(&tr->devs));
	return 0;
}

static void __exit mtd_blktrans_exit(void)
{
	/* No race here -- if someone's currently in register_mtd_blktrans
	   we're screwed anyway. */
	if (blktrans_notifier.list.next)
		unregister_mtd_user(&blktrans_notifier);
}

module_exit(mtd_blktrans_exit);

EXPORT_SYMBOL_GPL(register_mtd_blktrans);
EXPORT_SYMBOL_GPL(deregister_mtd_blktrans);
EXPORT_SYMBOL_GPL(add_mtd_blktrans_dev);
EXPORT_SYMBOL_GPL(del_mtd_blktrans_dev);

MODULE_AUTHOR("David Woodhouse <dwmw2@infradead.org>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Common interface to block layer for MTD 'translation layers'");
