// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/anon_inodes.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/poll.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "kevent.h"

#define KEVENT_SLOT_ALIGN 8U
#define KEVENT_ANON_NAME "[kevent]"

struct kevent_ring {
	struct kref ref;
	struct rcu_head rcu;
	spinlock_t lock;
	/* the anon inode fd holds the only reader */
	struct mutex read_lock;
	wait_queue_head_t read_wait;
	u8 *buf;
	u32 slot_size;
	u32 max_queued;
	u32 max_payload;
	u32 head;
	u32 count;
	u64 next_seq;
	u64 pushed;
	u64 dropped;
	u64 first_drop_seq;
	u64 last_drop_seq;
	bool closed;
	bool fd_open;
};

static struct kevent_ring *kevent_live;
static DEFINE_MUTEX(kevent_lock);

static size_t kevent_slot_offset(struct kevent_ring *ring, u32 index)
{
	return (size_t)index * (size_t)ring->slot_size;
}

static void kevent_note_drop(struct kevent_ring *ring, u64 seq)
{
	if (!ring->dropped) {
		ring->first_drop_seq = seq;
	}
	ring->dropped++;
	ring->last_drop_seq = seq;
}

static bool kevent_has_data(struct kevent_ring *ring)
{
	unsigned long irq_flags;
	bool has_data;

	spin_lock_irqsave(&ring->lock, irq_flags);
	has_data = ring->count != 0;
	spin_unlock_irqrestore(&ring->lock, irq_flags);

	return has_data;
}

static void kevent_ring_free(struct kref *ref)
{
	struct kevent_ring *ring = container_of(ref, struct kevent_ring, ref);

	kvfree(ring->buf);
	kfree_rcu(ring, rcu);
}

static struct kevent_ring *kevent_ref(void)
{
	struct kevent_ring *ring;

	rcu_read_lock();
	ring = rcu_dereference(kevent_live);
	if (ring && !kref_get_unless_zero(&ring->ref)) {
		ring = NULL;
	}
	rcu_read_unlock();

	return ring;
}

static int kevent_wait_data(struct kevent_ring *ring, unsigned int f_flags)
{
	int ret;

	for (;;) {
		if (kevent_has_data(ring)) {
			return 0;
		}
		if (READ_ONCE(ring->closed)) {
			return 0;
		}
		if (f_flags & O_NONBLOCK) {
			return -EAGAIN;
		}
		ret = wait_event_interruptible(ring->read_wait,
					       READ_ONCE(ring->closed) ||
					       kevent_has_data(ring));
		if (ret) {
			return ret;
		}
	}
}

static bool kevent_peek(struct kevent_ring *ring, struct kevent_hdr *hdr,
			u8 **slot)
{
	unsigned long irq_flags;
	u8 *entry;

	spin_lock_irqsave(&ring->lock, irq_flags);
	if (!ring->count) {
		spin_unlock_irqrestore(&ring->lock, irq_flags);
		return false;
	}
	entry = ring->buf + kevent_slot_offset(ring, ring->head);
	memcpy(hdr, entry, sizeof(*hdr));
	*slot = entry;
	spin_unlock_irqrestore(&ring->lock, irq_flags);

	return true;
}

static void kevent_consume(struct kevent_ring *ring)
{
	unsigned long irq_flags;

	spin_lock_irqsave(&ring->lock, irq_flags);
	ring->head++;
	if (ring->head >= ring->max_queued) {
		ring->head = 0;
	}
	ring->count--;
	spin_unlock_irqrestore(&ring->lock, irq_flags);
}

static ssize_t kevent_read(struct file *file, char __user *buf, size_t count,
			   loff_t *ppos)
{
	struct kevent_ring *ring = file->private_data;
	struct kevent_hdr hdr;
	size_t need;
	u8 *slot = NULL;
	ssize_t ret;
	int err;

	(void)ppos;

	if (!count) {
		return 0;
	}

	err = mutex_lock_interruptible(&ring->read_lock);
	if (err) {
		return err;
	}

	err = kevent_wait_data(ring, file->f_flags);
	if (err) {
		ret = err;
		goto out;
	}
	if (!kevent_peek(ring, &hdr, &slot)) {
		ret = 0;
		goto out;
	}

	need = sizeof(hdr) + (size_t)hdr.len;
	if (count < need) {
		ret = -EMSGSIZE;
		goto out;
	}

	/*
	 * the peeked slot stays untouched while it is queued: push never
	 * overwrites a queued slot and only this reader moves head, so the
	 * payload can be copied out without holding the lock
	 */
	if (copy_to_user(buf, &hdr, sizeof(hdr))) {
		ret = -EFAULT;
		goto out;
	}
	if (hdr.len && copy_to_user(buf + sizeof(hdr), slot + sizeof(hdr),
				    hdr.len)) {
		ret = -EFAULT;
		goto out;
	}

	kevent_consume(ring);
	ret = (ssize_t)need;

out:
	mutex_unlock(&ring->read_lock);
	return ret;
}

static __poll_t kevent_poll(struct file *file, poll_table *wait)
{
	struct kevent_ring *ring = file->private_data;
	__poll_t mask = 0;
	unsigned long irq_flags;

	poll_wait(file, &ring->read_wait, wait);

	spin_lock_irqsave(&ring->lock, irq_flags);
	if (ring->count) {
		mask |= EPOLLIN | EPOLLRDNORM;
	}
	if (ring->closed) {
		mask |= EPOLLHUP;
	}
	spin_unlock_irqrestore(&ring->lock, irq_flags);

	return mask;
}

static void kevent_fd_unclaim(struct kevent_ring *ring)
{
	unsigned long irq_flags;

	spin_lock_irqsave(&ring->lock, irq_flags);
	ring->fd_open = false;
	spin_unlock_irqrestore(&ring->lock, irq_flags);

	kref_put(&ring->ref, kevent_ring_free);
}

static int kevent_fd_claim(struct kevent_ring *ring)
{
	unsigned long irq_flags;
	int ret = 0;

	spin_lock_irqsave(&ring->lock, irq_flags);
	if (ring->closed) {
		ret = -EPIPE;
	} else if (ring->fd_open) {
		ret = -EBUSY;
	} else {
		ring->fd_open = true;
		kref_get(&ring->ref);
	}
	spin_unlock_irqrestore(&ring->lock, irq_flags);

	return ret;
}

static int kevent_release(struct inode *inode, struct file *file)
{
	(void)inode;

	kevent_fd_unclaim(file->private_data);

	return 0;
}

static const struct file_operations kevent_fops = {
	.owner = THIS_MODULE,
	.read = kevent_read,
	.poll = kevent_poll,
	.release = kevent_release,
	.llseek = noop_llseek,
};

int kevent_init(u32 max_queued, u32 max_payload)
{
	struct kevent_ring *ring;
	u64 slot_size;

	if (!max_queued) {
		return -EINVAL;
	}

	slot_size = (u64)sizeof(struct kevent_hdr) + (u64)max_payload;
	if (slot_size > (u64)U32_MAX - (u64)KEVENT_SLOT_ALIGN) {
		return -EINVAL;
	}
	/* keep the u64 fields of every slot aligned */
	slot_size = (slot_size + KEVENT_SLOT_ALIGN - 1U) &
		    ~((u64)KEVENT_SLOT_ALIGN - 1U);

	ring = kzalloc(sizeof(*ring), GFP_KERNEL);
	if (!ring) {
		return -ENOMEM;
	}

	ring->buf = kvmalloc_array((size_t)max_queued, (size_t)slot_size,
				   GFP_KERNEL);
	if (!ring->buf) {
		kfree(ring);
		return -ENOMEM;
	}

	kref_init(&ring->ref);
	spin_lock_init(&ring->lock);
	mutex_init(&ring->read_lock);
	init_waitqueue_head(&ring->read_wait);
	ring->slot_size = (u32)slot_size;
	ring->max_queued = max_queued;
	ring->max_payload = max_payload;
	ring->next_seq = 1;

	mutex_lock(&kevent_lock);
	if (kevent_live) {
		mutex_unlock(&kevent_lock);
		kvfree(ring->buf);
		kfree(ring);
		return -EBUSY;
	}
	rcu_assign_pointer(kevent_live, ring);
	mutex_unlock(&kevent_lock);

	return 0;
}

void kevent_exit(void)
{
	struct kevent_ring *ring;
	unsigned long irq_flags;

	mutex_lock(&kevent_lock);
	ring = kevent_live;
	if (!ring) {
		mutex_unlock(&kevent_lock);
		return;
	}
	rcu_assign_pointer(kevent_live, NULL);
	mutex_unlock(&kevent_lock);

	spin_lock_irqsave(&ring->lock, irq_flags);
	ring->closed = true;
	spin_unlock_irqrestore(&ring->lock, irq_flags);

	wake_up_interruptible_poll(&ring->read_wait, EPOLLHUP);

	kref_put(&ring->ref, kevent_ring_free);
}

int kevent_push(u16 type, u16 flags, const void *payload, u32 len)
{
	struct kevent_ring *ring;
	struct kevent_hdr *hdr;
	unsigned long irq_flags;
	u8 *entry;
	u32 index;
	u64 seq;
	bool wake = false;
	int ret = 0;

	if (len && !payload) {
		return -EINVAL;
	}

	ring = kevent_ref();
	if (!ring) {
		return -EPIPE;
	}

	spin_lock_irqsave(&ring->lock, irq_flags);
	if (ring->closed) {
		ret = -EPIPE;
		goto out;
	}

	seq = ring->next_seq++;
	if (len > ring->max_payload || ring->count == ring->max_queued) {
		kevent_note_drop(ring, seq);
		ret = len > ring->max_payload ? -EMSGSIZE : -ENOSPC;
		goto out;
	}

	index = ring->head + ring->count;
	if (index >= ring->max_queued) {
		index -= ring->max_queued;
	}
	entry = ring->buf + kevent_slot_offset(ring, index);
	hdr = (struct kevent_hdr *)entry;
	hdr->type = type;
	hdr->flags = flags;
	hdr->len = len;
	hdr->seq = seq;
	hdr->ts_ns = ktime_get_ns();
	if (len) {
		memcpy(entry + sizeof(*hdr), payload, len);
	}
	ring->count++;
	ring->pushed++;
	wake = true;

out:
	spin_unlock_irqrestore(&ring->lock, irq_flags);

	if (wake) {
		wake_up_interruptible_poll(&ring->read_wait,
					   EPOLLIN | EPOLLRDNORM);
	}

	kref_put(&ring->ref, kevent_ring_free);

	return ret;
}

void kevent_drop(void)
{
	struct kevent_ring *ring;
	unsigned long irq_flags;

	ring = kevent_ref();
	if (!ring) {
		return;
	}

	spin_lock_irqsave(&ring->lock, irq_flags);
	if (!ring->closed) {
		kevent_note_drop(ring, ring->next_seq++);
	}
	spin_unlock_irqrestore(&ring->lock, irq_flags);

	kref_put(&ring->ref, kevent_ring_free);
}

void kevent_get_stat(struct kevent_stat *out)
{
	struct kevent_ring *ring;
	unsigned long irq_flags;

	if (!out) {
		return;
	}

	memset(out, 0, sizeof(*out));

	ring = kevent_ref();
	if (!ring) {
		return;
	}

	spin_lock_irqsave(&ring->lock, irq_flags);
	out->pushed = ring->pushed;
	out->dropped = ring->dropped;
	out->first_drop_seq = ring->first_drop_seq;
	out->last_drop_seq = ring->last_drop_seq;
	spin_unlock_irqrestore(&ring->lock, irq_flags);

	kref_put(&ring->ref, kevent_ring_free);
}

int kevent_install_fd(const char *name, unsigned int fd_flags)
{
	struct kevent_ring *ring;
	struct file *filp;
	int fd;
	int ret;

	if (!name) {
		name = KEVENT_ANON_NAME;
	}

	mutex_lock(&kevent_lock);
	ring = kevent_live;
	if (!ring) {
		mutex_unlock(&kevent_lock);
		return -EPIPE;
	}
	ret = kevent_fd_claim(ring);
	mutex_unlock(&kevent_lock);
	if (ret) {
		return ret;
	}

	fd = get_unused_fd_flags(fd_flags);
	if (fd < 0) {
		kevent_fd_unclaim(ring);
		return fd;
	}

	filp = anon_inode_getfile(name, &kevent_fops, ring,
				  O_RDONLY | (int)fd_flags);
	if (IS_ERR(filp)) {
		put_unused_fd(fd);
		kevent_fd_unclaim(ring);
		return (int)PTR_ERR(filp);
	}

	fd_install(fd, filp);

	return fd;
}

struct kevent_capture {
	long (*user_read)(void *dst, const void __user *src, size_t size);
	int (*remote_read)(struct task_struct *task, unsigned long addr,
			   void *buf, int len, unsigned int gup_flags);
	struct mm_struct *(*task_mm)(struct task_struct *task);
	void (*mm_put)(struct mm_struct *mm);
	int (*domain)(struct task_struct *task, char *out, u32 size);
};

struct kevent_record {
	struct kevent_event ev;
	char tail[KEVENT_EVENT_TAIL_MAX];
};

static struct kevent_capture kevent_cap;
static bool kevent_cap_on;

/*
 * Every indirect call to a resolved symbol sits in a __nocfi function, the
 * stored prototypes are the kernel ones of 5.10 up to 6.12.
 */
static __nocfi long kevent_user_read(void *dst, const void __user *src,
				     size_t size)
{
	return kevent_cap.user_read(dst, src, size);
}

static __nocfi int kevent_remote_read(struct task_struct *task,
				      unsigned long addr, void *buf, int len)
{
	return kevent_cap.remote_read(task, addr, buf, len, 0);
}

static __nocfi struct mm_struct *kevent_task_mm(struct task_struct *task)
{
	return kevent_cap.task_mm(task);
}

static __nocfi void kevent_mm_put(struct mm_struct *mm)
{
	kevent_cap.mm_put(mm);
}

int kevent_capture_init(const struct kevent_capture_config *config)
{
	struct kevent_capture cap;
	unsigned long addr;

	if (!config || !config->resolve) {
		return -EINVAL;
	}

	memset(&cap, 0, sizeof(cap));

	addr = config->resolve("copy_from_user_nofault");
	if (!addr) {
		return -ENODATA;
	}
	cap.user_read = (long (*)(void *, const void __user *, size_t))addr;

	addr = config->resolve("access_process_vm");
	if (!addr) {
		return -ENODATA;
	}
	cap.remote_read =
		(int (*)(struct task_struct *, unsigned long, void *, int,
			 unsigned int))addr;

	addr = config->resolve("get_task_mm");
	if (!addr) {
		return -ENODATA;
	}
	cap.task_mm = (struct mm_struct *(*)(struct task_struct *))addr;

	addr = config->resolve("mmput");
	if (!addr) {
		return -ENODATA;
	}
	cap.mm_put = (void (*)(struct mm_struct *))addr;

	cap.domain = config->domain;
	/* the live state changes only once every symbol resolved */
	kevent_cap = cap;
	kevent_cap_on = true;

	return 0;
}

void kevent_capture_exit(void)
{
	kevent_cap_on = false;
	memset(&kevent_cap, 0, sizeof(kevent_cap));
}

void kevent_event_init(struct kevent_event *ev, u16 type, s32 result)
{
	if (!ev) {
		return;
	}

	memset(ev, 0, sizeof(*ev));
	ev->type = type;
	ev->size = (u16)sizeof(*ev);
	ev->result = result;
}

void kevent_event_identity(struct kevent_event *ev, struct task_struct *task)
{
	u32 i;

	if (!ev || !task) {
		return;
	}

	BUILD_BUG_ON(KEVENT_COMM_LEN != TASK_COMM_LEN);

	ev->pid = (u32)task_pid_nr(task);
	ev->tgid = (u32)task_tgid_nr(task);
	ev->ppid = (u32)task_ppid_nr(task);
	ev->uid = task_uid(task).val;
	ev->euid = task_euid(task).val;
	ev->gid = task_cred_xxx(task, gid).val;
	ev->egid = task_cred_xxx(task, egid).val;
	memcpy(ev->comm, task->comm, KEVENT_COMM_LEN);

	if (!kevent_cap_on || !kevent_cap.domain) {
		return;
	}

	if (kevent_cap.domain(task, ev->domain, KEVENT_DOMAIN_LEN)) {
		ev->flags |= KEVENT_EVF_DOMAIN_FAIL;
		ev->domain[0] = '\0';
		return;
	}

	for (i = 0; i < KEVENT_DOMAIN_LEN; i++) {
		if (!ev->domain[i]) {
			break;
		}
	}
	if (i == KEVENT_DOMAIN_LEN) {
		ev->flags |= KEVENT_EVF_DOMAIN_LONG;
		ev->domain[0] = '\0';
	}
}

static u32 kevent_read_range(struct task_struct *task, bool local,
			     unsigned long addr, char *dst, u32 size)
{
	int got;

	if (!size) {
		return 0;
	}

	if (local) {
		return kevent_user_read(dst, (const void __user *)addr,
					size) ? 0U : size;
	}

	got = kevent_remote_read(task, addr, dst, (int)size);

	return got > 0 ? (u32)got : 0;
}

u32 kevent_event_argv(struct kevent_event *ev, struct task_struct *task,
		      char *tail, u32 tail_size)
{
	struct mm_struct *mm = NULL;
	unsigned long start;
	unsigned long end;
	u64 len;
	u32 avail;
	u32 take;
	u32 got;
	bool local = false;

	if (!ev) {
		return 0;
	}

	ev->flags &= ~KEVENT_EVF_ARGV_MASK;
	ev->argv_len = 0;

	if (!tail || !tail_size) {
		ev->flags |= KEVENT_EVF_ARGV_NONE;
		return 0;
	}
	tail[0] = '\0';

	if (!task || !kevent_cap_on) {
		ev->flags |= KEVENT_EVF_ARGV_NONE;
		return 0;
	}

	if (task->mm == READ_ONCE(current->mm)) {
		local = true;
		mm = current->mm;
	} else if (in_atomic() || irqs_disabled()) {
		ev->flags |= KEVENT_EVF_ARGV_NONE;
		return 0;
	} else {
		mm = kevent_task_mm(task);
	}
	if (!mm) {
		ev->flags |= KEVENT_EVF_ARGV_NONE;
		return 0;
	}

#ifdef MMCF_AARCH32
	if (mm->context.flags & MMCF_AARCH32) {
		ev->flags |= KEVENT_EVF_COMPAT;
	}
#endif

	start = READ_ONCE(mm->arg_start);
	end = READ_ONCE(mm->arg_end);

	/*
	 * exec installs the argument range in two steps, setup_arg_pages sets
	 * arg_start while the fresh mm still has arg_end zero, so that window
	 * reads as an end below the start and is flagged instead of copied
	 */
	if (!start && !end) {
		ev->flags |= KEVENT_EVF_ARGV_EMPTY;
		goto out;
	}
	if (end < start) {
		ev->flags |= KEVENT_EVF_ARGV_INVALID;
		goto out;
	}

	/*
	 * the kernel keeps the arguments of the last exec as one NUL
	 * terminated string after another, so the flattened argv is that
	 * range itself and no pointer array is walked
	 */
	len = (u64)end - (u64)start;
	avail = tail_size - 1U;
	if (len > (u64)avail) {
		take = avail;
		ev->flags |= KEVENT_EVF_ARGV_TRUNC;
	} else {
		take = (u32)len;
	}

	got = kevent_read_range(task, local, start, tail, take);
	if (got != take) {
		ev->flags |= KEVENT_EVF_ARGV_FAULT;
	}
	if (got) {
		tail[got] = '\0';
		if (tail[got - 1] == '\0') {
			ev->argv_len = got;
		} else {
			ev->argv_len = got + 1U;
		}
	} else {
		ev->argv_len = 0;
	}

	if (READ_ONCE(task->mm) != mm || READ_ONCE(mm->arg_start) != start ||
	    READ_ONCE(mm->arg_end) != end) {
		ev->flags |= KEVENT_EVF_ARGV_RACE;
	}

out:
	if (!local) {
		kevent_mm_put(mm);
	}

	return ev->argv_len;
}

int kevent_emit_event(struct task_struct *task, u16 type, s32 result,
		      const void *extra, u32 extra_len)
{
	struct kevent_record rec;
	u32 used;

	if (extra_len && !extra) {
		return -EINVAL;
	}
	if (extra_len > KEVENT_EVENT_TAIL_MAX) {
		return -EMSGSIZE;
	}

	BUILD_BUG_ON(offsetof(struct kevent_record, tail) !=
		     sizeof(struct kevent_event));

	kevent_event_init(&rec.ev, type, result);
	kevent_event_identity(&rec.ev, task);
	used = kevent_event_argv(&rec.ev, task, rec.tail,
				 KEVENT_EVENT_TAIL_MAX - extra_len);
	if (extra_len) {
		memcpy(rec.tail + used, extra, extra_len);
		rec.ev.extra_len = extra_len;
	}

	return kevent_push(rec.ev.type, 0, &rec,
			   (u32)sizeof(rec.ev) + used + extra_len);
}
