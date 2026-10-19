// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/types.h>

#include "hk.h"
#include "hk_ptr.h"
#include "vendorcompat.h"

#define VC_MAX 8

/*
 * one replaced entry. the slot is a pointer in a table, the original is what the
 * library put back on exit, and the name is kept so a report can say which entry
 * the kernel refused
 */
struct vc_slot {
	const char *name;
	void **slot;
	void *orig;
	void *repl;
};

static struct vc_slot g_vc[VC_MAX];
static unsigned int g_vc_count;
static DEFINE_MUTEX(g_vc_lock);

/*
 * the replacement every named entry gets: allow. the signature of the real entry
 * varies with the kernel, and this one is only reached through a table pointer, so
 * it takes no argument and answers allow
 */
static long vc_allow(void)
{
	return 0;
}

int vc_allow_entry(const char *name)
{
	struct vc_slot *s;
	void **slot;
	int ret;

	if (!name)
		return -EINVAL;

	mutex_lock(&g_vc_lock);
	if (g_vc_count >= VC_MAX) {
		mutex_unlock(&g_vc_lock);
		pr_warn("[vendorcompat] no slot left for %s\n", name);
		return -ENOSPC;
	}
	s = &g_vc[g_vc_count];
	s->name = name;
	s->slot = NULL;
	s->orig = NULL;
	s->repl = (void *)vc_allow;

	/*
	 * a vendor entry of this shape is published as a pointer in a table, so the
	 * address the resolver answers is the slot and not the code. hk_ptr_hook
	 * writes the pointer and keeps the original for the restore
	 */
	slot = (void **)hk_resolve(name);
	if (!slot) {
		mutex_unlock(&g_vc_lock);
		pr_warn("[vendorcompat] %s not found\n", name);
		return -ENODATA;
	}
	s->slot = slot;
	ret = hk_ptr_hook(slot, s->repl, &s->orig);
	if (ret) {
		mutex_unlock(&g_vc_lock);
		pr_warn("[vendorcompat] %s slot refused %d\n", name, ret);
		return ret;
	}
	g_vc_count++;
	mutex_unlock(&g_vc_lock);
	pr_info("[vendorcompat] %s replaced\n", name);
	return 0;
}

void vc_exit(void)
{
	unsigned int i;

	mutex_lock(&g_vc_lock);
	for (i = 0; i < g_vc_count; i++)
		hk_ptr_unhook(g_vc[i].slot);
	memset(g_vc, 0, sizeof(g_vc));
	g_vc_count = 0;
	mutex_unlock(&g_vc_lock);
}

unsigned int vc_active(void)
{
	return g_vc_count;
}
