// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/capability.h>

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

static __nocfi const struct cred *kf_call_override(const struct cred *c)
{
	return kf_override_creds(c);
}

static __nocfi void kf_call_revert(const struct cred *c)
{
	kf_revert_creds(c);
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

int kfile_init(void)
{
	unsigned long addr;
	struct cred *c;

	addr = hk_resolve("prepare_creds");
	if (!addr)
		return -ENODATA;
	kf_prepare_creds = (struct cred *(*)(void))addr;

	addr = hk_resolve("override_creds");
	if (!addr)
		return -ENODATA;
	kf_override_creds = (const struct cred *(*)(const struct cred *))addr;

	addr = hk_resolve("revert_creds");
	if (!addr)
		return -ENODATA;
	kf_revert_creds = (void (*)(const struct cred *))addr;

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
	return 0;
}

void kfile_exit(void)
{
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
