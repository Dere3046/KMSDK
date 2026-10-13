// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

/*
 * the kernel consults its own module_blacklist before a module is laid out, so
 * this only merges names into that list. nothing is hooked and nothing in the
 * image is patched, which is why a platform that protects the image has nothing
 * to protect here
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "hk.h"
#include "hk_patch.h"
#include "moduleblacklist.h"

#define MBL_MAX 8

static char *mbl_own[MBL_MAX];
static char mbl_buf[256];
static char **mbl_native;
static char **mbl_merged;
static bool mbl_on;

int moduleblacklist_init(const struct mbl_cfg *cfg)
{
	unsigned long addr;

	if (!cfg || !cfg->resolve || !cfg->names || !cfg->names[0])
		return -EINVAL;
	addr = cfg->resolve("module_blacklist");
	if (!addr)
		return -ENOENT;
	mbl_native = (char **)addr;
	strscpy(mbl_buf, cfg->names, sizeof(mbl_buf));
	return 0;
}

bool moduleblacklist_contains(const char *name)
{
	char *cur;
	char **p;

	if (!name || !mbl_native)
		return false;
	if (copy_from_kernel_nofault(&p, mbl_native, sizeof(p)) || !p)
		return false;
	for (; ; p++) {
		if (copy_from_kernel_nofault(&cur, p, sizeof(cur)))
			return false;
		if (!cur)
			return false;
		if (!strcmp(cur, name))
			return true;
	}
}

/*
 * the names are merged with whatever the kernel already carries, and the pointer
 * is published in one release store so a reader never sees half of it. the result
 * is read back, because a platform that swallows the write would leave the list as
 * it was and the caller has to hear about that
 */
int moduleblacklist_start(void)
{
	char *cur;
	char **old;
	unsigned long count = 0;
	unsigned long i = 0;
	unsigned long len;
	char *tok;
	char *save;
	char **merged;
	int ret;

	if (mbl_on)
		return 0;
	if (!mbl_native)
		return -EINVAL;
	if (copy_from_kernel_nofault(&old, mbl_native, sizeof(old)))
		return -EFAULT;
	while (old && old[count]) {
		if (copy_from_kernel_nofault(&cur, &old[count], sizeof(cur)))
			return -EFAULT;
		if (!cur)
			break;
		if (count >= 512)
			return -E2BIG;
		count++;
	}

	len = strlen(mbl_buf);
	tok = mbl_buf;
	while (tok && *tok && i < MBL_MAX) {
		char *comma = strchr(tok, ',');

		if (comma)
			*comma = 0;
		if (*tok)
			mbl_own[i++] = tok;
		tok = comma ? comma + 1 : NULL;
	}
	(void)len;
	if (!i)
		return -EINVAL;

	merged = kzalloc(sizeof(char *) * (count + i + 1), GFP_KERNEL);
	if (!merged)
		return -ENOMEM;
	for (len = 0; len < count; len++) {
		if (copy_from_kernel_nofault(&cur, &old[len], sizeof(cur))) {
			kfree(merged);
			return -EFAULT;
		}
		merged[len] = cur;
	}
	for (count = 0; count < i; count++)
		merged[len + count] = mbl_own[count];
	mbl_merged = merged;

	{
		struct hk_write w = { .verify = true };

		ret = hk_write_run((void *)mbl_native, &merged, sizeof(merged),
				   &w);
	}
	if (ret) {
		kfree(merged);
		mbl_merged = NULL;
		return ret;
	}
	mbl_on = true;
	return 0;
}

void moduleblacklist_stop(void)
{
	/*
	 * the list is not put back: another loader may have merged into it since, and
	 * the kernel keeps its own pointer for the rest of the boot
	 */
	mbl_on = false;
}
