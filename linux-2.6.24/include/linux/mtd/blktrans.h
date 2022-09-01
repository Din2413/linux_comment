/*
 * $Id: blktrans.h,v 1.6 2005/11/07 11:14:54 gleixner Exp $
 *
 * (C) 2003 David Woodhouse <dwmw2@infradead.org>
 *
 * Interface to Linux block layer for MTD 'translation layers'.
 *
 */

#ifndef __MTD_TRANS_H__
#define __MTD_TRANS_H__

#include <linux/mutex.h>

struct hd_geometry;
struct mtd_info;
struct mtd_blktrans_ops;
struct file;
struct inode;

/**
 * mtd设备对应的模拟块设备描述符结构，在同一个转换层中每个mtd设备对应一个mtd_blktrans_dev对象
 * 用于记录模拟的块设备对应的mtd设备、总大小等独特信息
 *
 * 同一转换层下的mtd设备对应的所有模拟块设备对象由list成员挂在mtd_bliktrans_ops对象的devs双向链表上
 */
struct mtd_blktrans_dev {
	/* 所属的mtd块设备转换层的通用信息对象 */
	struct mtd_blktrans_ops *tr;
	struct list_head list;
	/* 模拟块设备对应的mtd设备 */
	struct mtd_info *mtd;
	struct mutex lock;
	int devnum;
	unsigned long size;
	int readonly;
	void *blkcore_priv; /* gendisk in 2.5, devfs_handle in 2.4 */
};

struct blkcore_priv; /* Differs for 2.4 and 2.5 kernels; private */

/**
 * mtd块设备转换层的通用信息结构，每注册一类mtd块设备转换层便创建一个对应的mtd_blktrans_ops对象
 * 用于记录模拟的块设备扇区大小、扇区读写函数指针等通用信息
 *
 * 所有的mtd块设备转换层通用信息数据对象由list成员挂在blktrans_majors双向链表上
 */
struct mtd_blktrans_ops {
	char *name;
	/* mtdblock块设备主设备号 */
	int major;
	int part_bits;
	/* 模拟的常规块设备的扇区大小 */
	int blksize;
	int blkshift;

	/* Access functions */
	/* 常规块设备的读写扇区的接口 */
	int (*readsect)(struct mtd_blktrans_dev *dev,
		    unsigned long block, char *buffer);
	int (*writesect)(struct mtd_blktrans_dev *dev,
		     unsigned long block, char *buffer);

	/* Block layer ioctls */
	int (*getgeo)(struct mtd_blktrans_dev *dev, struct hd_geometry *geo);
	int (*flush)(struct mtd_blktrans_dev *dev);

	/* Called with mtd_table_mutex held; no race with add/remove */
	int (*open)(struct mtd_blktrans_dev *dev);
	int (*release)(struct mtd_blktrans_dev *dev);

	/* Called on {de,}registration and on subsequent addition/removal
	   of devices, with mtd_table_mutex held. */
	/* mtd设备注册或注销时回调，创建或销毁mtd设备对应的模拟块设备 */
	void (*add_mtd)(struct mtd_blktrans_ops *tr, struct mtd_info *mtd);
	void (*remove_dev)(struct mtd_blktrans_dev *dev);

	struct list_head devs;
	struct list_head list;
	struct module *owner;

	struct mtd_blkcore_priv *blkcore_priv;
};

extern int register_mtd_blktrans(struct mtd_blktrans_ops *tr);
extern int deregister_mtd_blktrans(struct mtd_blktrans_ops *tr);
extern int add_mtd_blktrans_dev(struct mtd_blktrans_dev *dev);
extern int del_mtd_blktrans_dev(struct mtd_blktrans_dev *dev);


#endif /* __MTD_TRANS_H__ */
