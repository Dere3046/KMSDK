// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "type_info.h"
#include "btf.h"
#include "sepolicy.h"

#define SP_SYM_CLASSES 1
#define SP_SYM_TYPES 3
#define SP_AVTAB_ALLOWED 0x0001

struct sp_layout {
	long symtab;
	long symtab_size;
	long symtab_table;
	long symtab_nprim;
	long hashtab_htable;
	long hashtab_nel;
	long hashtab_size;
	long ht_key;
	long ht_datum;
	long ht_next;
	long avtab_htable;
	long avtab_nel;
	long avtab_nslot;
	long avtab_mask;
	long avtn_key;
	long avtn_next;
	long avkey_source;
	long avkey_target;
	long avkey_class;
	long avkey_specified;
	long avdata;
	long td_value;
	long cd_value;
	long cd_perms;
	long pd_value;
	long st_policy;
	unsigned long symtab_abs;
	unsigned long avtab_abs;
};

static struct ti_ctx *sp_btf;
static struct sp_layout sp_l;
static unsigned long sp_policydb;
static bool sp_ok;

static unsigned long (*sp_resolve)(const char *name);

static int sp_safe_read(void *dst, unsigned long src, size_t sz)
{
	return copy_from_kernel_nofault(dst, (void *)src, sz);
}

static int sp_off(u32 id, const char *member, long *out)
{
	u32 bit_off, bit_sz;
	int ret;

	ret = ti_member_off(sp_btf, id, member, &bit_off, &bit_sz);
	if (ret)
		return -ENODATA;
	*out = bit_off / 8;
	return 0;
}

static int sp_type(const char *name, u32 *id)
{
	return ti_type_by_name(sp_btf, name, BIT(BTF_KIND_STRUCT), id);
}

static int sp_fixed_layout(void)
{
	sp_l.symtab_size = 16;
	sp_l.symtab_table = 0;
	sp_l.symtab_nprim = 8;
	sp_l.hashtab_htable = 0;
	sp_l.hashtab_nel = 12;
	sp_l.hashtab_size = 8;
	sp_l.ht_key = 0;
	sp_l.ht_datum = 8;
	sp_l.ht_next = 16;
	sp_l.avtab_htable = 0;
	sp_l.avtab_nel = 8;
	sp_l.avtab_nslot = 12;
	sp_l.avtab_mask = 16;
	sp_l.avtn_key = 0;
	sp_l.avtn_next = 16;
	sp_l.avkey_source = 0;
	sp_l.avkey_target = 2;
	sp_l.avkey_class = 4;
	sp_l.avkey_specified = 8;
	sp_l.avdata = 0;
	sp_l.td_value = 0;
	sp_l.cd_value = 0;
	sp_l.cd_perms = 24;
	sp_l.pd_value = 0;
	return 0;
}

static int sp_anchor_scan(void)
{
	unsigned long st;
	unsigned long p;
	unsigned long q;
	u32 mask;
	u32 nslot;
	int i;
	int j;

	st = sp_resolve("selinux_state");
	if (!st)
		return -ENODATA;

	for (i = 0; i < 256; i += 8) {
		if (sp_safe_read(&p, st + i, 8))
			continue;
		if (!p)
			continue;

		for (j = 0; j < 4096; j += 8) {
			if (sp_safe_read(&mask, p + j + 16, 4))
				continue;
			if (mask < 15 || mask > 65535 ||
			    (mask & (mask + 1)) != 0)
				continue;
			if (sp_safe_read(&nslot, p + j + 12, 4))
				continue;
			if (nslot != mask + 1)
				continue;
			if (sp_safe_read(&q, p + j, 8))
				continue;
			if (!q)
				continue;
			sp_l.avtab_abs = p + j;
			break;
		}
		if (!sp_l.avtab_abs)
			continue;

		for (j = 0; j < 4096; j += 8) {
			unsigned long blk;
			u32 np;
			int k;
			int ok = 1;

			for (k = 0; k < 8; k++) {
				if (sp_safe_read(&blk, p + j + k * 16, 8) ||
				    sp_safe_read(&np, p + j + k * 16 + 8, 4)) {
					ok = 0;
					break;
				}
				if (blk && sp_safe_read(&mask, blk, 4))
					ok = 0;
			}
			if (!ok)
				continue;
			sp_l.symtab_abs = p + j;
			break;
		}
		if (sp_l.symtab_abs) {
			sp_policydb = 1;
			return 0;
		}
		sp_l.avtab_abs = 0;
	}
	return -ENODATA;
}

static int sp_btf_layout(void)
{
	u32 id;
	int ret;

	ret = sp_type("policydb", &id);
	if (ret)
		return ret;
	ret = sp_off(id, "symtab", &sp_l.symtab);
	if (ret)
		return ret;
	if (sp_type("symtab", &id))
		return -ENODATA;
	sp_l.symtab_size = ti_type_size(sp_btf, id);
	if (sp_type("hashtab", &id))
		return -ENODATA;
	ret = sp_off(id, "htable", &sp_l.hashtab_htable);
	if (ret)
		return ret;
	ret = sp_off(id, "nel", &sp_l.hashtab_nel);
	if (ret)
		return ret;
	ret = sp_off(id, "size", &sp_l.hashtab_size);
	if (ret)
		return ret;
	if (sp_type("hashtab_node", &id))
		return -ENODATA;
	ret = sp_off(id, "key", &sp_l.ht_key);
	if (ret)
		return ret;
	ret = sp_off(id, "datum", &sp_l.ht_datum);
	if (ret)
		return ret;
	ret = sp_off(id, "next", &sp_l.ht_next);
	if (ret)
		return ret;
	if (sp_type("avtab", &id))
		return -ENODATA;
	ret = sp_off(id, "htable", &sp_l.avtab_htable);
	if (ret)
		return ret;
	ret = sp_off(id, "nel", &sp_l.avtab_nel);
	if (ret)
		return ret;
	ret = sp_off(id, "nslot", &sp_l.avtab_nslot);
	if (ret)
		return ret;
	ret = sp_off(id, "mask", &sp_l.avtab_mask);
	if (ret)
		return ret;
	if (sp_type("avtab_node", &id))
		return -ENODATA;
	ret = sp_off(id, "key", &sp_l.avtn_key);
	if (ret)
		return ret;
	ret = sp_off(id, "next", &sp_l.avtn_next);
	if (ret)
		return ret;
	if (sp_type("avtab_key", &id))
		return -ENODATA;
	ret = sp_off(id, "source_type", &sp_l.avkey_source);
	if (ret)
		return ret;
	ret = sp_off(id, "target_type", &sp_l.avkey_target);
	if (ret)
		return ret;
	ret = sp_off(id, "target_class", &sp_l.avkey_class);
	if (ret)
		return ret;
	ret = sp_off(id, "specified", &sp_l.avkey_specified);
	if (ret)
		return ret;
	if (sp_type("avtab_datum", &id))
		return -ENODATA;
	ret = sp_off(id, "u", &sp_l.avdata);
	if (ret)
		return ret;
	if (sp_type("type_datum", &id))
		return -ENODATA;
	ret = sp_off(id, "value", &sp_l.td_value);
	if (ret)
		return ret;
	if (sp_type("class_datum", &id))
		return -ENODATA;
	ret = sp_off(id, "value", &sp_l.cd_value);
	if (ret)
		return ret;
	ret = sp_off(id, "permissions", &sp_l.cd_perms);
	if (ret)
		return ret;
	if (sp_type("perm_datum", &id))
		return -ENODATA;
	ret = sp_off(id, "value", &sp_l.pd_value);
	if (ret)
		return ret;
	if (sp_type("selinux_state", &id))
		return -ENODATA;
	ret = sp_off(id, "policy", &sp_l.st_policy);
	if (ret)
		return ret;

	sp_policydb = sp_resolve("selinux_state");
	if (!sp_policydb)
		return -ENODATA;
	sp_policydb = *(unsigned long *)(sp_policydb + sp_l.st_policy);
	if (!sp_policydb)
		pr_info("[sepolicy] policy not loaded yet\n");
	return 0;
}

int sepolicy_init(unsigned long (*resolve)(const char *name))
{
	struct ti_resolver res = {
		.name_to_addr = resolve,
	};
	int ret;

	if (!resolve)
		return -EINVAL;
	sp_resolve = resolve;

	if (ti_btf_available()) {
		if (!ti_ready()) {
			ret = ti_init(&res);
			if (ret)
				return ret;
		}
		sp_btf = ti_base();
		ret = sp_btf_layout();
		if (ret)
			return ret;
		sp_ok = true;
		return 0;
	}

	ret = sp_fixed_layout();
	if (ret)
		return ret;
	ret = sp_anchor_scan();
	if (ret) {
		pr_info("[sepolicy] anchor scan failed, no policy?\n");
		return ret;
	}
	sp_ok = true;
	return 0;
}

void sepolicy_exit(void)
{
	if (sp_btf)
		ti_exit();
	sp_btf = NULL;
	sp_ok = false;
	sp_resolve = NULL;
	memset(&sp_l, 0, sizeof(sp_l));
	sp_policydb = 0;
}

static void *sp_symtab(int idx)
{
	if (sp_l.symtab_abs)
		return (void *)(sp_l.symtab_abs + idx * sp_l.symtab_size);
	return (void *)(sp_policydb + sp_l.symtab + idx * sp_l.symtab_size);
}

static void *sp_sym_lookup(const char *name, int sym_idx)
{
	unsigned long tab;
	unsigned long n;
	u32 size;
	u32 i;

	tab = *(unsigned long *)((char *)sp_symtab(sym_idx) + sp_l.hashtab_htable);
	if (!tab)
		return NULL;
	size = *(u32 *)((char *)sp_symtab(sym_idx) + sp_l.hashtab_size);
	for (i = 0; i < size; i++) {
		for (n = *(unsigned long *)(tab + i * 8);
		     n; n = *(unsigned long *)(n + sp_l.ht_next)) {
			const char *k = *(const char **)(n + sp_l.ht_key);

			if (k && !strcmp(k, name))
				return (void *)(n + sp_l.ht_datum);
		}
	}
	return NULL;
}

static void *sp_class_perm(const char *c, const char *d)
{
	unsigned long perms;
	unsigned long tab;
	unsigned long n;
	u32 size;
	u32 i;
	void *cd;

	cd = sp_sym_lookup(c, SP_SYM_CLASSES);
	if (!cd)
		return NULL;
	perms = *(unsigned long *)(cd + sp_l.cd_perms);
	if (!perms)
		return NULL;
	tab = *(unsigned long *)(perms + sp_l.hashtab_htable);
	if (!tab)
		return NULL;
	size = *(u32 *)(perms + sp_l.hashtab_size);
	for (i = 0; i < size; i++) {
		for (n = *(unsigned long *)(tab + i * 8);
		     n; n = *(unsigned long *)(n + sp_l.ht_next)) {
			const char *k = *(const char **)(n + sp_l.ht_key);

			if (k && !strcmp(k, d))
				return (void *)(n + sp_l.ht_datum);
		}
	}
	return NULL;
}

struct sp_avtab_key {
	u16 source_type;
	u16 target_type;
	u16 target_class;
	u32 specified;
};

struct sp_avtab_datum {
	u32 data;
	void *xperms;
};

struct sp_avtab_node {
	struct sp_avtab_key key;
	struct sp_avtab_datum datum;
	struct sp_avtab_node *next;
};

static u32 sp_hash(const struct sp_avtab_key *key, u32 mask)
{
	return ((u32)key->source_type * 31 + (u32)key->target_type * 17 +
		(u32)key->target_class) & mask;
}

static unsigned long sp_avtab_base(void)
{
	if (sp_l.avtab_abs)
		return sp_l.avtab_abs;
	return sp_policydb + sp_l.avtab_htable;
}

int sepolicy_add_allow(const char *s, const char *t, const char *c,
		       const char *d)
{
	struct sp_avtab_key key;
	unsigned long avtab;
	unsigned long htable;
	unsigned long *slot;
	u32 mask;
	u32 nel;
	void *td;
	void *pd;
	void *node;

	if (!sp_ok || !s || !t || !c || !d)
		return -EINVAL;
	if (!sp_policydb)
		return -ENODATA;

	td = sp_sym_lookup(s, SP_SYM_TYPES);
	if (!td)
		return -ENOENT;
	pd = sp_class_perm(c, d);
	if (!pd)
		return -ENOENT;

	node = kzalloc(sizeof(struct sp_avtab_node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	key.source_type = *(u32 *)(td + sp_l.td_value);
	key.target_type = *(u32 *)(td + sp_l.td_value);
	key.target_class = *(u32 *)((char *)sp_sym_lookup(c, SP_SYM_CLASSES) +
				    sp_l.cd_value);
	key.specified = SP_AVTAB_ALLOWED;
	((struct sp_avtab_node *)node)->key = key;
	((struct sp_avtab_node *)node)->datum.data =
		*(u32 *)(pd + sp_l.pd_value);

	avtab = sp_avtab_base();
	htable = *(unsigned long *)avtab;
	mask = *(u32 *)(sp_avtab_base() + sp_l.avtab_mask - sp_l.avtab_htable);
	slot = (unsigned long *)(htable + sp_hash(&key, mask) * 8);
	((struct sp_avtab_node *)node)->next = (void *)*slot;
	*slot = (unsigned long)node;

	nel = *(u32 *)(sp_avtab_base() + sp_l.avtab_nel - sp_l.avtab_htable);
	*(u32 *)(sp_avtab_base() + sp_l.avtab_nel - sp_l.avtab_htable) =
		nel + 1;
	return 0;
}

int sepolicy_add_type(const char *type_name)
{
	unsigned long tab;
	unsigned long node;
	u32 nel;
	u32 value;

	if (!sp_ok || !type_name)
		return -EINVAL;
	if (!sp_policydb)
		return -ENODATA;

	tab = *(unsigned long *)((char *)sp_symtab(SP_SYM_TYPES) +
				 sp_l.hashtab_htable);
	if (!tab)
		return -ENODATA;
	nel = *(u32 *)((char *)sp_symtab(SP_SYM_TYPES) + sp_l.hashtab_nel);
	value = nel + 1;

	node = (unsigned long)kzalloc(64, GFP_KERNEL);
	if (!node)
		return -ENOMEM;
	*(const char **)(node + sp_l.ht_key) = kstrdup(type_name, GFP_KERNEL);
	*(u32 *)(node + sp_l.ht_datum) = value;
	*(unsigned long *)(node + sp_l.ht_next) = *(unsigned long *)tab;
	*(unsigned long *)tab = node;
	*(u32 *)((char *)sp_symtab(SP_SYM_TYPES) + sp_l.hashtab_nel) =
		nel + 1;
	return 0;
}
