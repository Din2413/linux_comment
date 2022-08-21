/*
 * NET		Generic infrastructure for Network protocols.
 *
 *		Definitions for request_sock 
 *
 * Authors:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 * 		From code originally in include/net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _REQUEST_SOCK_H
#define _REQUEST_SOCK_H

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include <net/sock.h>

struct request_sock;
struct sk_buff;
struct dst_entry;
struct proto;

/* 连接请求块的处理函数 */
struct request_sock_ops {
	int		family;
	int		obj_size;
	/* 创建分配连接请求块的高速缓存slab */
	struct kmem_cache	*slab;
	/* 发送SYN+ACK的函数指针 */
	int		(*rtx_syn_ack)(struct sock *sk,
				       struct request_sock *req,
				       struct dst_entry *dst);
	/* 发送ACK的函数指针 */
	void		(*send_ack)(struct sk_buff *skb,
				    struct request_sock *req);
	/* 发送RST的函数指针 */
	void		(*send_reset)(struct sock *sk,
				      struct sk_buff *skb);
	/* 析构函数，在释放连接请求块时调用 */
	void		(*destructor)(struct request_sock *req);
};

/* struct request_sock - mini sock to represent a connection request
 */
/**
 * 用来构成inet_request_sock结构
 * 主要描述对端的MSS、本端的接收窗口大小以及控制连接操作的信息，比如超时时间等
 */
struct request_sock {
	struct request_sock		*dl_next; /* Must be first member! */
	/* 客户端连接请求段中通告的MSS，如果无通告，则默认为RFC中建议的536 */
	u16				mss;
	/* 发送SYN+ACK段的次数，在达到系统设定的上限时，取消连接操作 */
	u8				retrans;
	u8				__pad;
	/* 标识本端的最大通告窗口，在生成SYN+ACK段时计算该值 */
	/* The following two fields can be easily recomputed I think -AK */
	u32				window_clamp; /* window clamp at creation time */
	/* 标识在连接建立时本端的接收窗口大小，在生成SYN+ACK段时计算该值 */
	u32				rcv_wnd;	  /* rcv_wnd offered first time */
	u32				ts_recent;
	/* 服务端收到连接请求，并发送SYN+ACK段作为应答后，等待客户端确认的超时时间，一旦超时，会重新发送SYN+ACK段 */
	unsigned long			expires;
	/* 处理连接请求的函数指针表 */
	const struct request_sock_ops	*rsk_ops;
	/* 指向对应状态的传输控制块，在连接建立之前无效，三次握手后会创建对应的传输控制块，而此时连接请求块也完成了历史使命，调用accept将该请求块取走并释放 */
	struct sock			*sk;
	u32				secid;
	u32				peer_secid;
};

static inline struct request_sock *reqsk_alloc(const struct request_sock_ops *ops)
{
	struct request_sock *req = kmem_cache_alloc(ops->slab, GFP_ATOMIC);

	if (req != NULL)
		req->rsk_ops = ops;

	return req;
}

static inline void __reqsk_free(struct request_sock *req)
{
	kmem_cache_free(req->rsk_ops->slab, req);
}

static inline void reqsk_free(struct request_sock *req)
{
	req->rsk_ops->destructor(req);
	__reqsk_free(req);
}

extern int sysctl_max_syn_backlog;

/** struct listen_sock - listen state
 *
 * @max_qlen_log - log_2 of maximal queued SYNs/REQUESTs
 */
struct listen_sock {
	/* 实际分配用来保存SYN请求连接的request_sock结构数组的长度，其值为nr_table_entries以2为底的对数 */
	u8			max_qlen_log;
	/* 3 bytes hole, try to use */
	/* 当前连接请求块数目 */
	int			qlen;
	/**
	 * 当前未重传过SYN+ACK段的请求块数目
	 * 如果每次建立链接都很顺利，三次握手的段没有重传，则qlen_young和qlenshi一致的，有SYN+ACK段重传时会递减
	 */
	int			qlen_young;
	/**
	 * 用来记录连接建立定时器处理函数下次被激活时需处理的连接请求块散列表入口
	 * 在本次处理结束时将当前的入口保存到该字段中，下次处理时就从该入口开始处理
	 */
	int			clock_hand;
	/* 用来计算SYN请求块散列表键值的随机数，该值在reqsk_queue_alloc()中随机生成 */
	u32			hash_rnd;
	/* 实际分配用来保存SYN请求连接的request_sock结构数组的长度 */
	u32			nr_table_entries;
	/* 指向未完成连接请求块request_sock的散列表，在listen系统调用中创建 */
	struct request_sock	*syn_table[0];
};

/** struct request_sock_queue - queue of request_socks
 *
 * @rskq_accept_head - FIFO head of established children
 * @rskq_accept_tail - FIFO tail of established children
 * @rskq_defer_accept - User waits for some data after accept()
 * @syn_wait_lock - serializer
 *
 * %syn_wait_lock is necessary only to avoid proc interface having to grab the main
 * lock sock while browsing the listening hash (otherwise it's deadlock prone).
 *
 * This lock is acquired in read mode only from listening_get_next() seq_file
 * op and it's acquired in write mode _only_ from code that is actively
 * changing rskq_accept_head. All readers that are holding the master sock lock
 * don't need to grab this lock in read mode too as rskq_accept_head. writes
 * are always protected from the main sock lock.
 */
/**
 * 保存未完成连接和已完成但未被accept的TCP请求控制块
 * 1、当服务端进入LISTEN状态后，便可接收客户端的连接请求；
 * 2、接收到客户端的SYN请求后，服务端发送SYN+ACK回应，并创建请求控制块（保存双方初始序号等）链入listen_opt的syn_table散列表中；
 * 3、再次接收到客户端的ACK回应后，才为连接真正创建一个TCP传输控制块，并挂载到连接请求块的sk成员上，同时将已经完成连接的请求块移动到rskq_qccept_head队列中，等到accept调用；
 * 4、accept系统调用从rskq_accept_head队列中取走请求传输控制块，与套接口相关联后释放该连接请求块;
 */
struct request_sock_queue {
	/* 指向已完成连接但未被accept的连接请求块链表的头部和尾部 */
	struct request_sock	*rskq_accept_head;
	struct request_sock	*rskq_accept_tail;
	rwlock_t		syn_wait_lock;
	u8			rskq_defer_accept;
	/* 3 bytes hole, try to pack */
	/**
	 * 保存连接状态中的连接请求块
	 * 在TCP传输控制块创建之初，listen_opt是未被分配的，即值为NULL
	 * listen系统调用使TCP进入LISTEN状态，同时还创建listen_opt为SYN_RECV状态的请求连接控制块分配空间
	*/
	struct listen_sock	*listen_opt;
};

extern int reqsk_queue_alloc(struct request_sock_queue *queue,
			     unsigned int nr_table_entries);

extern void __reqsk_queue_destroy(struct request_sock_queue *queue);
extern void reqsk_queue_destroy(struct request_sock_queue *queue);

static inline struct request_sock *
	reqsk_queue_yank_acceptq(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	queue->rskq_accept_head = NULL;
	return req;
}

static inline int reqsk_queue_empty(struct request_sock_queue *queue)
{
	return queue->rskq_accept_head == NULL;
}

static inline void reqsk_queue_unlink(struct request_sock_queue *queue,
				      struct request_sock *req,
				      struct request_sock **prev_req)
{
	write_lock(&queue->syn_wait_lock);
	*prev_req = req->dl_next;
	write_unlock(&queue->syn_wait_lock);
}

static inline void reqsk_queue_add(struct request_sock_queue *queue,
				   struct request_sock *req,
				   struct sock *parent,
				   struct sock *child)
{
	req->sk = child;
	sk_acceptq_added(parent);

	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_head = req;
	else
		queue->rskq_accept_tail->dl_next = req;

	queue->rskq_accept_tail = req;
	req->dl_next = NULL;
}

static inline struct request_sock *reqsk_queue_remove(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	BUG_TRAP(req != NULL);

	queue->rskq_accept_head = req->dl_next;
	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_tail = NULL;

	return req;
}

static inline struct sock *reqsk_queue_get_child(struct request_sock_queue *queue,
						 struct sock *parent)
{
	struct request_sock *req = reqsk_queue_remove(queue);
	struct sock *child = req->sk;

	BUG_TRAP(child != NULL);

	sk_acceptq_removed(parent);
	__reqsk_free(req);
	return child;
}

static inline int reqsk_queue_removed(struct request_sock_queue *queue,
				      struct request_sock *req)
{
	struct listen_sock *lopt = queue->listen_opt;

	if (req->retrans == 0)
		--lopt->qlen_young;

	return --lopt->qlen;
}

static inline int reqsk_queue_added(struct request_sock_queue *queue)
{
	struct listen_sock *lopt = queue->listen_opt;
	const int prev_qlen = lopt->qlen;

	lopt->qlen_young++;
	lopt->qlen++;
	return prev_qlen;
}

static inline int reqsk_queue_len(const struct request_sock_queue *queue)
{
	return queue->listen_opt != NULL ? queue->listen_opt->qlen : 0;
}

static inline int reqsk_queue_len_young(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen_young;
}

static inline int reqsk_queue_is_full(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen >> queue->listen_opt->max_qlen_log;
}

static inline void reqsk_queue_hash_req(struct request_sock_queue *queue,
					u32 hash, struct request_sock *req,
					unsigned long timeout)
{
	struct listen_sock *lopt = queue->listen_opt;

	req->expires = jiffies + timeout;
	req->retrans = 0;
	req->sk = NULL;
	req->dl_next = lopt->syn_table[hash];

	write_lock(&queue->syn_wait_lock);
	lopt->syn_table[hash] = req;
	write_unlock(&queue->syn_wait_lock);
}

#endif /* _REQUEST_SOCK_H */
