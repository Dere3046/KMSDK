// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/version.h>

#include "hk.h"
#include "kfile.h"

static struct cred *kf_cred;
static struct cred *(*kf_prepare_creds)(void);
static const struct cred *(*kf_override_creds)(const struct cred *);
static void (*kf_revert_creds)(const struct cred *);
static struct file *(*kf_filp_open)(const char *, int, umode_t);
static ssize_t (*kf_kernel_read)(struct file *, void *, size_t, loff_t *);
static ssize_t (*kf_kernel_write)(struct file *, const void *, size_t,
				  loff_t *);
static int (*kf_filp_close)(struct file *, fl_owner_t);
static int (*kf_kern_path)(const char *, unsigned int, struct path *);
static void (*kf_path_put)(struct path *);
static struct file *(*kf_dentry_open)(const struct path *, int,
				      const struct cred *);

static __nocfi const struct cred *kf_call_override(const struct cred *c)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	return override_creds(c);
#else
	return kf_override_creds(c);
#endif
}

static __nocfi void kf_call_revert(const struct cred *c)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
	revert_creds(c);
#else
	kf_revert_creds(c);
#endif
}

static __nocfi struct file *kf_call_filp_open(const char *p, int f, umode_t m)
{
	return kf_filp_open(p, f, m);
}

static __nocfi ssize_t kf_call_read(struct file *f, void *b, size_t l,
				    loff_t *o)
{
	return kf_kernel_read(f, b, l, o);
}

static __nocfi ssize_t kf_call_write(struct file *f, const void *b, size_t l,
				     loff_t *o)
{
	return kf_kernel_write(f, b, l, o);
}

static __nocfi int kf_call_close(struct file *f)
{
	return kf_filp_close(f, NULL);
}

static __nocfi int kf_call_kern_path(const char *p, unsigned int f,
				     struct path *path)
{
	return kf_kern_path(p, f, path);
}

static __nocfi void kf_call_path_put(struct path *p)
{
	kf_path_put(p);
}

static __nocfi struct cred *kf_call_prepare(void)
{
	return kf_prepare_creds();
}

static __nocfi struct file *kf_call_dentry_open(const struct path *p, int f,
					       const struct cred *c)
{
	return kf_dentry_open(p, f, c);
}

int kfile_init(void)
{
	unsigned long addr;
	struct cred *c;

	addr = hk_resolve("prepare_creds");
	if (!addr)
		return -ENODATA;
	kf_prepare_creds = (struct cred *(*)(void))addr;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	addr = hk_resolve("override_creds");
	if (!addr)
		return -ENODATA;
	kf_override_creds = (const struct cred *(*)(const struct cred *))addr;

	addr = hk_resolve("revert_creds");
	if (!addr)
		return -ENODATA;
	kf_revert_creds = (void (*)(const struct cred *))addr;
#endif

	c = kf_call_prepare();
	if (!c)
		return -ENOMEM;
	c->cap_inheritable = CAP_FULL_SET;
	c->cap_permitted = CAP_FULL_SET;
	c->cap_effective = CAP_FULL_SET;
	c->cap_bset = CAP_FULL_SET;
	c->cap_ambient = CAP_FULL_SET;
	kf_cred = c;

	addr = hk_resolve("filp_open");
	if (!addr)
		return -ENODATA;
	kf_filp_open = (struct file *(*)(const char *, int, umode_t))addr;

	addr = hk_resolve("kernel_read");
	if (!addr)
		return -ENODATA;
	kf_kernel_read = (ssize_t (*)(struct file *, void *, size_t,
				      loff_t *))addr;

	addr = hk_resolve("kernel_write");
	if (!addr)
		return -ENODATA;
	kf_kernel_write = (ssize_t (*)(struct file *, const void *, size_t,
				       loff_t *))addr;

	addr = hk_resolve("filp_close");
	if (!addr)
		return -ENODATA;
	kf_filp_close = (int (*)(struct file *, fl_owner_t))addr;

	addr = hk_resolve("kern_path");
	if (!addr)
		return -ENODATA;
	kf_kern_path = (int (*)(const char *, unsigned int,
				struct path *))addr;

	addr = hk_resolve("path_put");
	if (!addr)
		return -ENODATA;
	kf_path_put = (void (*)(struct path *))addr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
	addr = hk_resolve("dentry_open_nonotify");
#else
	addr = hk_resolve("dentry_open");
#endif
	if (!addr)
		return -ENODATA;
	kf_dentry_open = (struct file *(*)(const struct path *, int,
					   const struct cred *))addr;
	return 0;
}

void kfile_exit(void)
{
	kfile_rc_exit();
	if (kf_cred)
		put_cred(kf_cred);
	kf_cred = NULL;
	kf_prepare_creds = NULL;
	kf_override_creds = NULL;
	kf_revert_creds = NULL;
	kf_filp_open = NULL;
	kf_kernel_read = NULL;
	kf_kernel_write = NULL;
	kf_filp_close = NULL;
	kf_kern_path = NULL;
	kf_path_put = NULL;
	kf_dentry_open = NULL;
}

ssize_t kfile_read(const char *path, void *buf, size_t len)
{
	const struct cred *saved;
	struct file *fp;
	loff_t off = 0;
	ssize_t ret;

	if (!kf_cred)
		return -ENODATA;

	saved = kf_call_override(kf_cred);
	fp = kf_call_filp_open(path, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		kf_call_revert(saved);
		return PTR_ERR(fp);
	}
	ret = kf_call_read(fp, buf, len, &off);
	kf_call_close(fp);
	kf_call_revert(saved);
	return ret;
}

ssize_t kfile_write(const char *path, const void *buf, size_t len,
		    umode_t mode)
{
	const struct cred *saved;
	struct file *fp;
	loff_t off = 0;
	ssize_t ret;

	if (!kf_cred)
		return -ENODATA;

	saved = kf_call_override(kf_cred);
	fp = kf_call_filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (IS_ERR(fp)) {
		kf_call_revert(saved);
		return PTR_ERR(fp);
	}
	ret = kf_call_write(fp, buf, len, &off);
	kf_call_close(fp);
	kf_call_revert(saved);
	return ret;
}

int kfile_exist(const char *path)
{
	const struct cred *saved;
	struct path p;
	int ret;

	if (!kf_cred)
		return -ENODATA;

	saved = kf_call_override(kf_cred);
	ret = kf_call_kern_path(path, 0, &p);
	if (!ret)
		kf_call_path_put(&p);
	kf_call_revert(saved);
	return ret;
}

struct kfile_handle {
	struct file *fp;
};

struct kfile_handle *kfile_open(const char *path, bool nonotify)
{
	const struct cred *saved;
	struct kfile_handle *h;
	struct path p;
	struct file *fp;
	int flags = O_RDONLY | O_NOATIME;
	int ret;

	if (!path || !kf_cred || !kf_dentry_open)
		return ERR_PTR(-ENODATA);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
	if (nonotify)
		flags |= __FMODE_NONOTIFY;
#else
	(void)nonotify;
#endif

	h = kzalloc(sizeof(*h), GFP_KERNEL);
	if (!h)
		return ERR_PTR(-ENOMEM);

	saved = kf_call_override(kf_cred);
	ret = kf_call_kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret) {
		kf_call_revert(saved);
		kfree(h);
		return ERR_PTR(ret);
	}
	fp = kf_call_dentry_open(&p, flags, kf_cred);
	kf_call_path_put(&p);
	kf_call_revert(saved);
	if (IS_ERR(fp)) {
		kfree(h);
		return ERR_CAST(fp);
	}

	h->fp = fp;
	return h;
}

void kfile_close(struct kfile_handle *h)
{
	if (!h)
		return;
	if (h->fp)
		kf_call_close(h->fp);
	kfree(h);
}

loff_t kfile_size(struct kfile_handle *h)
{
	if (!h || !h->fp)
		return -EINVAL;
	return i_size_read(file_inode(h->fp));
}

ssize_t kfile_pread(struct kfile_handle *h, void *buf, size_t len, loff_t pos)
{
	if (!h || !h->fp || !buf)
		return -EINVAL;
	if (pos < 0)
		return -EINVAL;
	return kf_call_read(h->fp, buf, len, &pos);
}

struct file *kfile_filp(struct kfile_handle *h)
{
	if (!h)
		return NULL;
	return h->fp;
}

#define KFILE_RC_MAX 4
#define KFILE_RC_LINE_MAX 64

/*
 * one slot per proxied file, the file object points at ops, a copy of its
 * own table with read and read_iter replaced
 * size is the inode size taken at install time, the payload occupies the
 * position range from size to size plus length, so the read position alone
 * tells how much of the payload was served
 */
struct kfile_rc_slot {
	struct file *file;
	const struct file_operations *orig_ops;
	ssize_t (*orig_read)(struct file *, char __user *, size_t, loff_t *);
	ssize_t (*orig_read_iter)(struct kiocb *, struct iov_iter *);
	const char *content;
	size_t length;
	loff_t size;
	struct file_operations ops;
};

static struct kfile_rc_slot kfile_rc_slots[KFILE_RC_MAX];
static struct kfile_rc_cfg kfile_rc_cfg;
static bool kfile_rc_ready;
static bool kfile_rc_on;

static void kfile_rc_log(const char *text, long value)
{
	char line[KFILE_RC_LINE_MAX];

	if (!kfile_rc_cfg.log)
		return;
	snprintf(line, sizeof(line), "[kfile] %s: %ld\n", text, value);
	kfile_rc_cfg.log(line, kfile_rc_cfg.priv);
}

/* a slot is identified by the file_operations installed on the file, so a
 * lookup never reads through a file pointer that could be stale
 */
static struct kfile_rc_slot *kfile_rc_lookup(struct file *file)
{
	int i;

	if (!file)
		return NULL;
	for (i = 0; i < KFILE_RC_MAX; i++) {
		if (kfile_rc_slots[i].file &&
		    file->f_op == &kfile_rc_slots[i].ops)
			return &kfile_rc_slots[i];
	}
	return NULL;
}

static ssize_t kfile_rc_tail(struct kfile_rc_slot *slot, char __user *buf,
			     size_t count, loff_t *pos)
{
	loff_t offset;
	size_t length;

	offset = *pos - slot->size;
	if (offset < 0 || offset >= (loff_t)slot->length)
		return 0;
	length = slot->length - (size_t)offset;
	if (length > count)
		length = count;
	if (!length)
		return 0;
	if (copy_to_user(buf, slot->content + offset, length))
		return -EFAULT;
	*pos += length;
	return length;
}

static ssize_t kfile_rc_tail_iter(struct kfile_rc_slot *slot,
				  struct iov_iter *to, loff_t *pos)
{
	loff_t offset;
	size_t length;
	size_t copied;

	offset = *pos - slot->size;
	if (offset < 0 || offset >= (loff_t)slot->length)
		return 0;
	length = slot->length - (size_t)offset;
	if (length > iov_iter_count(to))
		length = iov_iter_count(to);
	if (!length)
		return 0;
	copied = copy_to_iter(slot->content + offset, length, to);
	*pos += copied;
	return copied;
}

/* the original read runs to its end of file first, the payload is served
 * past that point, a short read leaves the tail for the next call
 */
static __nocfi ssize_t kfile_rc_read(struct file *file, char __user *buf,
				     size_t count, loff_t *pos)
{
	struct kfile_rc_slot *slot;
	ssize_t ret;

	slot = kfile_rc_lookup(file);
	if (!slot)
		return -EIO;

	ret = slot->orig_read(file, buf, count, pos);
	if (ret)
		return ret;
	return kfile_rc_tail(slot, buf, count, pos);
}

static __nocfi ssize_t kfile_rc_read_iter(struct kiocb *iocb,
					  struct iov_iter *to)
{
	struct kfile_rc_slot *slot;
	ssize_t ret;

	slot = kfile_rc_lookup(iocb->ki_filp);
	if (!slot)
		return -EIO;

	ret = slot->orig_read_iter(iocb, to);
	if (ret)
		return ret;
	return kfile_rc_tail_iter(slot, to, &iocb->ki_pos);
}

/* the f_op swap is the last step, every failure before it leaves the file
 * untouched and the caller releases the payload
 */
static int kfile_rc_install(struct file *file, const char *content,
			    size_t length)
{
	const struct file_operations *orig_ops;
	struct kfile_rc_slot *slot;
	int i;

	orig_ops = file->f_op;
	if (!orig_ops)
		return -EINVAL;
	if (!orig_ops->read && !orig_ops->read_iter)
		return -EOPNOTSUPP;

	slot = NULL;
	for (i = 0; i < KFILE_RC_MAX; i++) {
		if (!kfile_rc_slots[i].file) {
			slot = &kfile_rc_slots[i];
			break;
		}
	}
	if (!slot)
		return -ENOSPC;

	slot->file = file;
	slot->orig_ops = orig_ops;
	slot->orig_read = orig_ops->read;
	slot->orig_read_iter = orig_ops->read_iter;
	slot->content = content;
	slot->length = length;
	slot->size = i_size_read(file_inode(file));
	memcpy(&slot->ops, orig_ops, sizeof(slot->ops));
	if (slot->orig_read)
		slot->ops.read = kfile_rc_read;
	if (slot->orig_read_iter)
		slot->ops.read_iter = kfile_rc_read_iter;
	get_file(file);
	file->f_op = &slot->ops;
	return 0;
}

int kfile_rc_init(const struct kfile_rc_cfg *cfg)
{
	if (!cfg || !cfg->match_file || !cfg->content_get)
		return -EINVAL;
	if (kfile_rc_ready)
		return -EALREADY;

	kfile_rc_cfg = *cfg;
	kfile_rc_ready = true;
	return 0;
}

void kfile_rc_exit(void)
{
	kfile_rc_stop();
	memset(&kfile_rc_cfg, 0, sizeof(kfile_rc_cfg));
	kfile_rc_ready = false;
}

int kfile_rc_start(void)
{
	int ret;

	if (!kfile_rc_ready)
		return -ENODATA;
	if (kfile_rc_on)
		return 0;

	if (kfile_rc_cfg.hook_add) {
		ret = kfile_rc_cfg.hook_add(kfile_rc_cfg.priv);
		if (ret) {
			kfile_rc_log("hook refused", ret);
			return ret;
		}
	}

	kfile_rc_on = true;
	return 0;
}

int kfile_rc_stop(void)
{
	struct kfile_rc_slot *slot;
	int i;

	if (!kfile_rc_ready)
		return -ENODATA;
	if (!kfile_rc_on)
		return 0;

	/* a hook call arriving from here on finds nothing to install */
	kfile_rc_on = false;

	/* every proxy goes back in one pass, nothing in it can fail */
	for (i = 0; i < KFILE_RC_MAX; i++) {
		if (kfile_rc_slots[i].file)
			kfile_rc_slots[i].file->f_op = kfile_rc_slots[i].orig_ops;
	}
	for (i = 0; i < KFILE_RC_MAX; i++) {
		slot = &kfile_rc_slots[i];
		if (!slot->file)
			continue;
		fput(slot->file);
		if (kfile_rc_cfg.content_put)
			kfile_rc_cfg.content_put(slot->content, slot->length,
						 kfile_rc_cfg.priv);
		memset(slot, 0, sizeof(*slot));
	}

	if (kfile_rc_cfg.hook_remove)
		kfile_rc_cfg.hook_remove(kfile_rc_cfg.priv);
	return 0;
}

int kfile_rc_proxy(struct file *file)
{
	const char *content;
	size_t length = 0;
	int ret;

	if (!kfile_rc_ready || !kfile_rc_on)
		return -ENODATA;
	if (!file)
		return -EINVAL;
	if (!kfile_rc_cfg.match_file(file, kfile_rc_cfg.priv))
		return 0;
	if (kfile_rc_lookup(file))
		return 0;

	content = kfile_rc_cfg.content_get(&length, kfile_rc_cfg.priv);
	if (!content || !length) {
		kfile_rc_log("payload empty", -ENODATA);
		return -ENODATA;
	}

	ret = kfile_rc_install(file, content, length);
	if (ret) {
		if (kfile_rc_cfg.content_put)
			kfile_rc_cfg.content_put(content, length,
						 kfile_rc_cfg.priv);
		kfile_rc_log("proxy refused", ret);
		return ret;
	}

	kfile_rc_log("proxy installed", (long)length);
	return 1;
}

int kfile_rc_proxy_fd(int fd)
{
	struct file *file;
	int ret;

	if (fd < 0)
		return -EINVAL;
	file = fget((unsigned int)fd);
	if (!file)
		return 0;
	ret = kfile_rc_proxy(file);
	fput(file);
	return ret;
}

int kfile_rc_stat_size(struct file *file, loff_t *size)
{
	struct kfile_rc_slot *slot;

	if (!size)
		return -EINVAL;
	slot = kfile_rc_lookup(file);
	if (!slot)
		return 0;
	*size += slot->length;
	return 1;
}
