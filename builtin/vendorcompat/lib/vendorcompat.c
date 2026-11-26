// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "hk.h"
#include "hk_inline.h"
#include "hk_kprobe.h"
#include "hk_patch.h"
#include "hk_redir.h"
#include "vendorcompat.h"

static const char *const g_route_names[] = {
	"none",
	"text",
	"kprobe",
	"slot",
};

/*
 * one replacement. the route decides which member is live, and the report keeps
 * what the probe saw so a consumer can log why a route was or was not offered
 */
struct vc_entry {
	struct list_head list;
	enum vc_route route;
	const char *sym;
	struct hk_redir redir;
};

static LIST_HEAD(g_vc_list);
static unsigned int g_vc_active;
static DEFINE_MUTEX(g_vc_lock);

const char *vc_route_name(enum vc_route route)
{
	if (route > VC_ROUTE_SLOT)
		return "?";
	return g_route_names[route];
}

/*
 * the route the engine can take for a symbol on this kernel. the order is the one
 * that changes least first: an entry whose page is writable is written, a kernel
 * that refuses that still gets the breakpoint route, and a symbol that cannot
 * carry a breakpoint either gets nothing
 */
static enum vc_route vc_pick(const char *sym, unsigned long addr,
			     struct vc_result *out)
{
	struct hk_kprobe_report probe;
	struct hk_route facts;

	if (hk_route_probe(addr, &facts))
		return VC_ROUTE_NONE;
	out->writable = facts.writable;
	out->block_map = facts.block_map;

	/*
	 * the text route needs an entry to change, not a page that is writable right
	 * now: the write layer takes the permission off the page itself, and module
	 * text is read only exactly like the image's is. a block mapping has no entry
	 * under it, which is the case that cannot be written whatever the permission
	 */
	if (!facts.block_map && (facts.kind == HK_VA_IMAGE_TEXT ||
				 facts.kind == HK_VA_VMALLOC))
		return VC_ROUTE_TEXT;

	if (!hk_kprobe_check_at(addr, &probe))
		return VC_ROUTE_KPROBE;
	return VC_ROUTE_NONE;
}

static void vc_apply_opts(struct hk_redir *redir, enum vc_route route,
			  const struct vc_opts *opts)
{
	if (!opts)
		return;
	if (route == VC_ROUTE_TEXT) {
		redir->ret_mode = opts->ret_mode;
		return;
	}
	redir->adjust = opts->adjust;
	redir->adjust_arg = opts->adjust_arg;
	redir->guard = opts->guard;
	redir->pin = opts->pin;
}

int vc_install_ex(const char *sym, const char *repl_sym,
		  const struct vc_opts *opts, struct vc_result *out)
{
	struct vc_entry *e;
	unsigned long addr;
	enum vc_route route;
	int ret;

	if (!sym || !repl_sym || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	out->route = VC_ROUTE_NONE;

	addr = hk_resolve(sym);
	if (!addr) {
		out->ret = -ENODATA;
		return -ENODATA;
	}
	route = vc_pick(sym, addr, out);
	if (route == VC_ROUTE_NONE) {
		out->ret = -EOPNOTSUPP;
		return -EOPNOTSUPP;
	}

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e) {
		out->ret = -ENOMEM;
		return -ENOMEM;
	}
	e->sym = sym;
	e->route = route;
	vc_apply_opts(&e->redir, route, opts);

	mutex_lock(&g_vc_lock);
	ret = hk_redir_install(&e->redir, sym, repl_sym, route == VC_ROUTE_TEXT ?
			       HK_REDIR_TEXT : HK_REDIR_KPROBE);
	/*
	 * a text route that refused is not the end: an entry too short for the window,
	 * or a write the kernel would not take, still leaves the breakpoint route,
	 * which changes nothing but the parked pc
	 */
	if (ret && route == VC_ROUTE_TEXT) {
		route = VC_ROUTE_KPROBE;
		e->route = route;
		memset(&e->redir, 0, sizeof(e->redir));
		vc_apply_opts(&e->redir, route, opts);
		ret = hk_redir_install(&e->redir, sym, repl_sym, HK_REDIR_KPROBE);
	}
	if (ret) {
		out->ret = ret;
		mutex_unlock(&g_vc_lock);
		kfree(e);
		pr_warn("[vendorcompat] %s on the %s route refused %d\n", sym,
			vc_route_name(route), ret);
		return ret;
	}
	list_add_tail(&e->list, &g_vc_list);
	WRITE_ONCE(g_vc_active, g_vc_active + 1);
	mutex_unlock(&g_vc_lock);
	out->route = route;
	out->ret = 0;
	pr_info("[vendorcompat] %s on the %s route\n", sym,
		vc_route_name(route));
	return 0;
}

int vc_install(const char *sym, const char *repl_sym, struct vc_result *out)
{
	return vc_install_ex(sym, repl_sym, NULL, out);
}

int vc_install_at_ex(unsigned long addr, unsigned long repl,
		     const struct vc_opts *opts, struct vc_result *out)
{
	struct vc_entry *e;
	int ret;

	if (!addr || !repl || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	out->route = VC_ROUTE_NONE;
	if (hk_kprobe_check_at(addr, NULL)) {
		out->ret = -EOPNOTSUPP;
		return -EOPNOTSUPP;
	}

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e) {
		out->ret = -ENOMEM;
		return -ENOMEM;
	}
	e->route = VC_ROUTE_KPROBE;
	vc_apply_opts(&e->redir, VC_ROUTE_KPROBE, opts);

	mutex_lock(&g_vc_lock);
	ret = hk_redir_install_at(&e->redir, addr, repl, HK_REDIR_KPROBE);
	if (ret) {
		out->ret = ret;
		mutex_unlock(&g_vc_lock);
		kfree(e);
		return ret;
	}
	list_add_tail(&e->list, &g_vc_list);
	WRITE_ONCE(g_vc_active, g_vc_active + 1);
	mutex_unlock(&g_vc_lock);
	out->route = VC_ROUTE_KPROBE;
	return 0;
}

int vc_install_at(unsigned long addr, unsigned long repl, struct vc_result *out)
{
	return vc_install_at_ex(addr, repl, NULL, out);
}

void vc_exit(void)
{
	struct vc_entry *e, *tmp;

	mutex_lock(&g_vc_lock);
	list_for_each_entry_safe_reverse(e, tmp, &g_vc_list, list) {
		int ret = hk_redir_remove(&e->redir);

		if (ret) {
			pr_warn("[vendorcompat] remove %s failed %d, keeping entry live\n",
				e->sym ? e->sym : "<addr>", ret);
			continue;
		}
		list_del(&e->list);
		WRITE_ONCE(g_vc_active, g_vc_active - 1);
		kfree(e);
	}
	mutex_unlock(&g_vc_lock);
}

unsigned int vc_active(void)
{
	return READ_ONCE(g_vc_active);
}

struct hk_redir *vc_handle(const char *sym)
{
	struct hk_redir *redir = NULL;
	struct vc_entry *e;

	if (!sym)
		return NULL;
	mutex_lock(&g_vc_lock);
	list_for_each_entry(e, &g_vc_list, list) {
		if (e->sym && !strcmp(e->sym, sym)) {
			redir = &e->redir;
			break;
		}
	}
	mutex_unlock(&g_vc_lock);
	return redir;
}
