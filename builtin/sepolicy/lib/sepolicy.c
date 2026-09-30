// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "type_info.h"
#include "sepolicy.h"

/* SYM_* indexes from security/selinux/ss/policydb.h */
#define SP_SYM_CLASSES 1
#define SP_SYM_ROLES 2
#define SP_SYM_TYPES 3
#define SP_SYM_USERS 4

#define SP_AVTAB_ALLOWED 0x0001
#define SP_AVTAB_AUDITALLOW 0x0002
#define SP_AVTAB_AUDITDENY 0x0004
#define SP_AVTAB_AV 0x0007
#define SP_AVTAB_TRANSITION 0x0010
#define SP_AVTAB_CHANGE 0x0020
#define SP_AVTAB_MEMBER 0x0040
#define SP_AVTAB_XPERMS_ALLOWED 0x0100
#define SP_AVTAB_XPERMS_AUDITALLOW 0x0200
#define SP_AVTAB_XPERMS_DONTAUDIT 0x0400
#define SP_AVTAB_XPERMS 0x0700
#define SP_XPERMS_IOCTLFUNCTION 0x01
#define SP_XPERMS_IOCTLDRIVER 0x02
#define SP_CEXPR_NAMES 5
#define SP_NETLINK_ROUTE (1u << 31)
#define SP_NETLINK_GETNEIGH (1u << 30)
#define SP_CONFIG_OFF 20
#define SP_POLICYDB_VERSION_XPERMS_IOCTL 30
#define SP_HASHTAB_MAX_NODES 0xffffffffU
#define SP_SECSID_NULL 0


/* BTF kind is a uapi ABI constant, kept local to avoid the enum
 * redefinition between the type_info btf.h and the kernel uapi one
 */
#define SP_BTF_KIND_STRUCT 4

/* local mirrors, these structs keep the same layout from 5.10 to 6.12 */
struct sp_hashtab_node {
	void *key;
	void *datum;
	struct sp_hashtab_node *next;
};

struct sp_hashtab {
	struct sp_hashtab_node **htable;
	u32 size;
	u32 nel;
};

struct sp_avtab_key {
	u16 source_type;
	u16 target_type;
	u16 target_class;
	u16 specified;
};

struct sp_avtab_datum {
	union {
		u32 data;
		void *xperms;
	} u;
};

struct sp_avtab_node {
	struct sp_avtab_key key;
	struct sp_avtab_datum datum;
	struct sp_avtab_node *next;
};

struct sp_avtab {
	struct sp_avtab_node **htable;
	u32 nel;
	u32 nslot;
	u32 mask;
};

struct sp_perms_data {
	u32 p[8];
};

struct sp_xperms {
	u8 specified;
	u8 driver;
	struct sp_perms_data perms;
};

struct sp_policy_file {
	char *data;
	size_t len;
};

struct sp_filename_trans_key {
	u32 ttype;
	u16 tclass;
	const char *name;
};

struct sp_layout {
	long pd_symtab;
	long pd_sym_val_to_name;
	long pd_te_avtab;
	long pd_te_cond_avtab;
	long pd_type_attr_map_array;
	long pd_type_val_to_struct;
	long pd_role_val_to_struct;
	long pd_class_val_to_struct;
	long pd_permissive_map;
	long pd_len;
	long pd_route;
	long pd_getneigh;
	long pd_policyvers;
	long pd_role_allow;
	long pd_process_class;
	long pd_process_trans_perms;
	long pd_filename_trans;
	long pd_ft_ttypes;
	long pd_ft_count;
	/* query side */
	long sy_table;
	long sy_nprim;
	long sp_policydb;
	long sp_sidtab;
	long sp_latest_granting;
	long st_policy;
	long st_policy_mutex;
	long st_avc;
	long td_value;
	long td_attribute;
	long td_bounds;
	long td_primary;
	long pdm_value;
	long cd_value;
	long cd_constraints;
	long cd_permissions;
	long cd_comdatum;
	long cm_permissions;
	long cn_expr;
	long cn_next;
	long cn_permissions;
	long ce_expr_type;
	long ce_names;
	long ce_type_names;
	long ce_next;
	long rd_value;
	long rd_types;
	long ra_role;
	long ra_new_role;
	long ra_next;
	long ud_value;
	long ft_stypes;
	long ft_otype;
	long ft_next;
	long se_context;
	long se_user;
	long se_role;
	long se_type;
	long se_len;
	long se_str;
	long se_range;
	long rl_level;
	long ll_cat;
	long size_symtab;
	long size_policydb;
	long size_policy;
	long size_ebitmap;
	long size_context;
	long size_mls_level;
	long size_sidtab;
};

struct sp_fns {
	struct sp_avtab_node *(*insert_nonunique)(struct sp_avtab *h,
						  struct sp_avtab_key *key,
						  struct sp_avtab_datum *datum);
	struct sp_avtab_node *(*search_node)(struct sp_avtab *h,
					     struct sp_avtab_key *key);
	struct sp_avtab_node *(*search_node_next)(struct sp_avtab_node *node,
						  int specified);
	int (*avtab_alloc)(struct sp_avtab *h, u32 nrules);
	void (*avtab_destroy)(struct sp_avtab *h);
	void *(*symtab_search)(void *s, const char *name);
	int (*symtab_insert)(void *s, char *name, void *datum);
	void (*policydb_destroy)(void *p);
	int (*policydb_read)(void *p, void *fp);
	int (*policydb_write)(void *p, void *fp);
	int (*ebitmap_set_bit)(void *e, unsigned long bit, int value);
	int (*ebitmap_get_bit)(void *e, unsigned long bit);
	/* both functions dropped the state argument in 6.6, callers cast per version */
	void *avc_reset;
	void (*policyload)(u32 seqno);
	void *status_policyload;
};

/*
 * Query symbols are optional: the rule path works without them. The kernel
 * functions that take a policy, a sidtab or a policydb pointer are reused as
 * they are, the replicated bodies below only cover what no symbol provides and
 * what those kernels inlined away.
 */
struct sp_query_fns {
	int (*context_parse)(void *pol, void *sidtab, char *scontext, void *ctx,
			     u32 def_sid);
	int (*context_to_string)(void *pol, void *ctx, char **scontext,
				 u32 *scontext_len);
	void (*context_destroy)(void *ctx);
	int (*mls_to_sid)(void *pol, char oldc, char *scontext, void *ctx,
			  void *sidtab, u32 def_sid);
	int (*context_valid)(void *pol, void *ctx);
	u32 (*mls_context_len)(void *pol, void *ctx);
	void (*mls_to_context)(void *pol, void *ctx, char **scontextp);
	int (*sidtab_to_sid)(void *sidtab, void *ctx, u32 *sid);
	void *(*sid_entry)(void *sidtab, u32 sid);
	int (*sidtab_init)(void *sidtab);
	void (*sidtab_destroy)(void *sidtab);
	int (*load_isids)(void *pol, void *sidtab);
	int (*compute_av)(void *pol, void *sctx, void *tctx, u16 tclass, void *avd,
			  void *xperms);
	int (*constraint_eval)(void *pol, void *sctx, void *tctx, void *xctx,
			       void *expr);
	void (*bounds_av)(void *pol, void *sctx, void *tctx, u16 tclass,
			  void *avd);
	void (*cond_av)(void *avtab, void *key, void *avd, void *xperms);
	void *(*filenametr_search)(void *pol, void *key);
	int (*hashtab_insert)(void *h, void **dst, void *key, void *datum);
	u32 (*name_hash)(const void *salt, const char *name, unsigned int len);
	void (*ebitmap_destroy)(void *e);
};

static struct ti_ctx *sp_btf;
static bool sp_ti_owner;
static struct sp_layout sp_l;
static struct sp_fns sp_f;
static struct sp_query_fns sp_q;
static u32 sp_caps;
static unsigned long (*sp_resolve)(const char *name);
static unsigned long sp_state_addr;
static void *sp_work;
static bool sp_ready;

static void *sp_read_ptr(void *base, long off)
{
	void *v;

	memcpy(&v, (char *)base + off, sizeof(v));
	return v;
}

static u16 sp_read_u16(void *base, long off)
{
	u16 v;

	memcpy(&v, (char *)base + off, sizeof(v));
	return v;
}

static u32 sp_read_u32(void *base, long off)
{
	u32 v;

	memcpy(&v, (char *)base + off, sizeof(v));
	return v;
}

static unsigned long sp_read_ulong(void *base, long off)
{
	unsigned long v;

	memcpy(&v, (char *)base + off, sizeof(v));
	return v;
}

static void sp_write_ptr(void *base, long off, void *v)
{
	memcpy((char *)base + off, &v, sizeof(v));
}

static void sp_write_u32(void *base, long off, u32 v)
{
	memcpy((char *)base + off, &v, sizeof(v));
}

static void sp_write_ulong(void *base, long off, unsigned long v)
{
	memcpy((char *)base + off, &v, sizeof(v));
}

static int sp_member(const char *type, const char *member, long *out)
{
	u32 id, bit_off, bit_sz;

	if (ti_type_by_name(sp_btf, type, BIT(SP_BTF_KIND_STRUCT), &id))
		return -ENODATA;
	if (ti_member_off(sp_btf, id, member, &bit_off, &bit_sz))
		return -ENODATA;
	*out = bit_off / 8;
	return 0;
}

static int sp_size(const char *type, long *out)
{
	u32 id;

	if (ti_type_by_name(sp_btf, type, BIT(SP_BTF_KIND_STRUCT), &id))
		return -ENODATA;
	*out = ti_type_size(sp_btf, id);
	return *out > 0 ? 0 : -ENODATA;
}

struct sp_name_off {
	const char *type;
	const char *member;
	long *out;
	bool optional;
};

static const struct sp_name_off sp_offsets[] = {
	{ "policydb", "symtab", &sp_l.pd_symtab, false },
	{ "policydb", "sym_val_to_name", &sp_l.pd_sym_val_to_name, false },
	{ "policydb", "te_avtab", &sp_l.pd_te_avtab, false },
	{ "policydb", "type_attr_map_array", &sp_l.pd_type_attr_map_array,
	  false },
	{ "policydb", "type_val_to_struct", &sp_l.pd_type_val_to_struct,
	  false },
	{ "policydb", "role_val_to_struct", &sp_l.pd_role_val_to_struct,
	  false },
	{ "policydb", "permissive_map", &sp_l.pd_permissive_map, false },
	{ "policydb", "len", &sp_l.pd_len, false },
	{ "policydb", "android_netlink_route", &sp_l.pd_route, true },
	{ "policydb", "android_netlink_getneigh", &sp_l.pd_getneigh, true },
	{ "policydb", "te_cond_avtab", &sp_l.pd_te_cond_avtab, true },
	{ "policydb", "policyvers", &sp_l.pd_policyvers, true },
	{ "policydb", "class_val_to_struct", &sp_l.pd_class_val_to_struct, true },
	{ "policydb", "role_allow", &sp_l.pd_role_allow, true },
	{ "policydb", "process_class", &sp_l.pd_process_class, true },
	{ "policydb", "process_trans_perms", &sp_l.pd_process_trans_perms, true },
	{ "policydb", "filename_trans", &sp_l.pd_filename_trans, true },
	{ "policydb", "filename_trans_ttypes", &sp_l.pd_ft_ttypes, true },
	{ "policydb", "compat_filename_trans_count", &sp_l.pd_ft_count, true },
	{ "symtab", "table", &sp_l.sy_table, false },
	{ "symtab", "nprim", &sp_l.sy_nprim, false },
	{ "selinux_policy", "policydb", &sp_l.sp_policydb, false },
	{ "selinux_policy", "sidtab", &sp_l.sp_sidtab, true },
	{ "selinux_policy", "latest_granting", &sp_l.sp_latest_granting, true },
	{ "selinux_state", "policy", &sp_l.st_policy, false },
	{ "selinux_state", "policy_mutex", &sp_l.st_policy_mutex, false },
	{ "selinux_state", "avc", &sp_l.st_avc, true },
	{ "type_datum", "value", &sp_l.td_value, false },
	{ "type_datum", "attribute", &sp_l.td_attribute, false },
	{ "type_datum", "bounds", &sp_l.td_bounds, true },
	{ "type_datum", "primary", &sp_l.td_primary, true },
	{ "role_datum", "types", &sp_l.rd_types, true },
	{ "perm_datum", "value", &sp_l.pdm_value, false },
	{ "class_datum", "value", &sp_l.cd_value, false },
	{ "class_datum", "constraints", &sp_l.cd_constraints, false },
	{ "class_datum", "permissions", &sp_l.cd_permissions, false },
	{ "class_datum", "comdatum", &sp_l.cd_comdatum, false },
	{ "common_datum", "permissions", &sp_l.cm_permissions, false },
	{ "constraint_node", "permissions", &sp_l.cn_permissions, true },
	{ "constraint_node", "expr", &sp_l.cn_expr, false },
	{ "constraint_node", "next", &sp_l.cn_next, false },
	{ "constraint_expr", "expr_type", &sp_l.ce_expr_type, false },
	{ "constraint_expr", "names", &sp_l.ce_names, false },
	{ "constraint_expr", "type_names", &sp_l.ce_type_names, false },
	{ "constraint_expr", "next", &sp_l.ce_next, false },
	{ "role_datum", "value", &sp_l.rd_value, true },
	{ "user_datum", "value", &sp_l.ud_value, true },
	{ "role_allow", "role", &sp_l.ra_role, true },
	{ "role_allow", "new_role", &sp_l.ra_new_role, true },
	{ "role_allow", "next", &sp_l.ra_next, true },
	{ "filename_trans_datum", "stypes", &sp_l.ft_stypes, true },
	{ "filename_trans_datum", "otype", &sp_l.ft_otype, true },
	{ "filename_trans_datum", "next", &sp_l.ft_next, true },
	{ "sidtab_entry", "context", &sp_l.se_context, true },
	{ "context", "user", &sp_l.se_user, true },
	{ "context", "role", &sp_l.se_role, true },
	{ "context", "type", &sp_l.se_type, true },
	{ "context", "len", &sp_l.se_len, true },
	{ "context", "str", &sp_l.se_str, true },
	{ "context", "range", &sp_l.se_range, true },
	{ "mls_range", "level", &sp_l.rl_level, true },
	{ "mls_level", "cat", &sp_l.ll_cat, true },
};

static const struct sp_name_off sp_sizes[] = {
	{ "symtab", NULL, &sp_l.size_symtab, false },
	{ "policydb", NULL, &sp_l.size_policydb, false },
	{ "selinux_policy", NULL, &sp_l.size_policy, false },
	{ "ebitmap", NULL, &sp_l.size_ebitmap, false },
	{ "context", NULL, &sp_l.size_context, true },
	{ "mls_level", NULL, &sp_l.size_mls_level, true },
	{ "sidtab", NULL, &sp_l.size_sidtab, true },
};

static int sp_layout_load(void)
{
	int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(sp_offsets); i++) {
		const struct sp_name_off *e = &sp_offsets[i];

		*e->out = -1;
		ret = sp_member(e->type, e->member, e->out);
		if (ret && !e->optional)
			return ret;
	}
	for (i = 0; i < ARRAY_SIZE(sp_sizes); i++) {
		const struct sp_name_off *e = &sp_sizes[i];

		*e->out = 0;
		ret = sp_size(e->type, e->out);
		if (ret && !e->optional)
			return ret;
	}
	return 0;
}

static __nocfi int sp_resolve_fns(void)
{
	sp_f.insert_nonunique = (void *)sp_resolve("avtab_insert_nonunique");
	sp_f.search_node = (void *)sp_resolve("avtab_search_node");
	sp_f.search_node_next = (void *)sp_resolve("avtab_search_node_next");
	sp_f.avtab_alloc = (void *)sp_resolve("avtab_alloc");
	sp_f.avtab_destroy = (void *)sp_resolve("avtab_destroy");
	sp_f.symtab_search = (void *)sp_resolve("symtab_search");
	sp_f.symtab_insert = (void *)sp_resolve("symtab_insert");
	sp_f.policydb_destroy = (void *)sp_resolve("policydb_destroy");
	sp_f.policydb_read = (void *)sp_resolve("policydb_read");
	sp_f.policydb_write = (void *)sp_resolve("policydb_write");
	sp_f.ebitmap_set_bit = (void *)sp_resolve("ebitmap_set_bit");
	sp_f.ebitmap_get_bit = (void *)sp_resolve("ebitmap_get_bit");
	sp_f.avc_reset = (void *)sp_resolve("avc_ss_reset");
	sp_f.policyload = (void *)sp_resolve("selnl_notify_policyload");
	sp_f.status_policyload =
		(void *)sp_resolve("selinux_status_update_policyload");

	if (!sp_f.insert_nonunique || !sp_f.search_node ||
	    !sp_f.search_node_next || !sp_f.avtab_alloc || !sp_f.avtab_destroy ||
	    !sp_f.symtab_search || !sp_f.symtab_insert ||
	    !sp_f.policydb_destroy || !sp_f.policydb_read ||
	    !sp_f.policydb_write || !sp_f.ebitmap_set_bit ||
	    !sp_f.ebitmap_get_bit)
		return -ENODATA;

	return 0;
}

/*
 * Both the plain and the replicated query paths are decided once here: the
 * kernel functions are preferred, the replications only fill the gaps that
 * inlining leaves, for example context_struct_compute_av on 6.1.
 */
static __nocfi void sp_resolve_query(void)
{
	sp_q.context_parse = (void *)sp_resolve("string_to_context_struct");
	sp_q.context_to_string = (void *)sp_resolve("context_struct_to_string");
	sp_q.context_destroy = (void *)sp_resolve("context_destroy");
	sp_q.mls_to_sid = (void *)sp_resolve("mls_context_to_sid");
	sp_q.context_valid = (void *)sp_resolve("policydb_context_isvalid");
	sp_q.mls_context_len = (void *)sp_resolve("mls_compute_context_len");
	sp_q.mls_to_context = (void *)sp_resolve("mls_sid_to_context");
	sp_q.sidtab_to_sid = (void *)sp_resolve("sidtab_context_to_sid");
	sp_q.sid_entry = (void *)sp_resolve("sidtab_search_entry");
	sp_q.sidtab_init = (void *)sp_resolve("sidtab_init");
	sp_q.sidtab_destroy = (void *)sp_resolve("sidtab_destroy");
	sp_q.load_isids = (void *)sp_resolve("policydb_load_isids");
	sp_q.compute_av = (void *)sp_resolve("context_struct_compute_av");
	sp_q.constraint_eval = (void *)sp_resolve("constraint_expr_eval");
	sp_q.bounds_av = (void *)sp_resolve("type_attribute_bounds_av");
	sp_q.cond_av = (void *)sp_resolve("cond_compute_av");
	sp_q.filenametr_search =
		(void *)sp_resolve("policydb_filenametr_search");
	sp_q.hashtab_insert = (void *)sp_resolve("__hashtab_insert");
	sp_q.name_hash = (void *)sp_resolve("full_name_hash");
	sp_q.ebitmap_destroy = (void *)sp_resolve("ebitmap_destroy");
}

static void sp_caps_update(void)
{
	bool ctx_free;
	bool parse;
	bool render;
	bool av_engine;

	ctx_free = sp_q.context_destroy != NULL ||
		   (sp_l.se_str >= 0 && sp_l.se_range >= 0 &&
		    sp_l.size_mls_level > 0 && sp_l.ll_cat >= 0 &&
		    sp_q.ebitmap_destroy != NULL);
	parse = sp_q.context_parse != NULL ||
		(sp_q.mls_to_sid != NULL && sp_q.context_valid != NULL &&
		 sp_l.se_user >= 0 && sp_l.se_role >= 0 && sp_l.rd_value >= 0 &&
		 sp_l.ud_value >= 0);
	render = sp_q.context_to_string != NULL ||
		 (sp_l.pd_sym_val_to_name >= 0 && sp_q.mls_context_len != NULL &&
		  sp_q.mls_to_context != NULL && sp_l.se_len >= 0 &&
		  sp_l.se_str >= 0 && sp_l.se_user >= 0 && sp_l.se_role >= 0 &&
		  sp_l.se_type >= 0);
	av_engine = sp_q.compute_av != NULL ||
		    (sp_q.constraint_eval != NULL &&
		     (sp_q.bounds_av != NULL || sp_l.td_bounds >= 0) &&
		     sp_l.pd_class_val_to_struct >= 0 &&
		     sp_l.cn_permissions >= 0 && sp_l.pd_role_allow >= 0 &&
		     sp_l.ra_role >= 0 && sp_l.ra_new_role >= 0 &&
		     sp_l.ra_next >= 0);

	sp_caps = 0;

	if (sp_l.sp_sidtab >= 0 && sp_l.size_context > 0 &&
	    sp_q.sidtab_to_sid && parse && ctx_free)
		sp_caps |= SEPOLICY_CAP_SID;

	if (sp_l.sp_sidtab >= 0 && sp_l.se_context >= 0 && sp_q.sid_entry &&
	    render)
		sp_caps |= SEPOLICY_CAP_SID_TO_CTX;

	if (sp_l.sp_sidtab >= 0 && sp_l.se_context >= 0 &&
	    sp_l.se_type >= 0 && sp_l.sp_latest_granting >= 0 &&
	    sp_q.sid_entry && av_engine)
		sp_caps |= SEPOLICY_CAP_AV;

	if (sp_l.sp_sidtab >= 0 && sp_l.size_sidtab > 0 && sp_q.sidtab_init &&
	    sp_q.sidtab_destroy && sp_q.load_isids)
		sp_caps |= SEPOLICY_CAP_BACKUP;

	if (sp_l.pd_filename_trans >= 0 && sp_l.pd_ft_ttypes >= 0 &&
	    sp_l.pd_ft_count >= 0 && sp_l.ft_stypes >= 0 &&
	    sp_l.ft_otype >= 0 && sp_l.ft_next >= 0 && sp_q.hashtab_insert &&
	    sp_q.name_hash)
		sp_caps |= SEPOLICY_CAP_FILENAME_TRANS;

	if (sp_l.rd_types >= 0 && sp_l.td_bounds >= 0 && sp_q.ebitmap_destroy)
		sp_caps |= SEPOLICY_CAP_DEL_TYPE;
}

static bool sp_cap(u32 bit)
{
	if (!sp_ready)
		return false;
	return (sp_caps & bit) != 0;
}

static void *sp_symtab_of(void *db, int idx)
{
	return (char *)db + sp_l.pd_symtab + (long)idx * sp_l.size_symtab;
}

static struct sp_hashtab *sp_table_of(void *db, int idx)
{
	return (struct sp_hashtab *)((char *)sp_symtab_of(db, idx) +
				     sp_l.sy_table);
}

static void *sp_avtab_of(void *db)
{
	return (char *)db + sp_l.pd_te_avtab;
}

static __nocfi void *sp_sym_lookup(void *db, int idx, const char *name)
{
	if (!name)
		return NULL;
	return sp_f.symtab_search(sp_symtab_of(db, idx), name);
}

static __nocfi void *sp_class_perm(void *db, void *cls, const char *perm)
{
	void *com;
	void *p;

	if (!cls || !perm)
		return NULL;

	p = sp_f.symtab_search((char *)cls + sp_l.cd_permissions, perm);
	if (p)
		return p;

	com = sp_read_ptr(cls, sp_l.cd_comdatum);
	if (!com)
		return NULL;
	return sp_f.symtab_search((char *)com + sp_l.cm_permissions, perm);
}

static bool sp_is_redundant(struct sp_avtab_node *node)
{
	if (node->key.specified & SP_AVTAB_XPERMS)
		return node->datum.u.xperms == NULL;
	if (!(node->key.specified & SP_AVTAB_AV))
		return false;
	if (node->key.specified & SP_AVTAB_AUDITDENY)
		return node->datum.u.data == ~0U;
	return node->datum.u.data == 0U;
}

static __nocfi void sp_remove_node(void *db, struct sp_avtab_node *node)
{
	struct sp_avtab removed;
	struct sp_avtab *avtab = sp_avtab_of(db);
	unsigned long shrink;
	int i;

	if (sp_f.avtab_alloc(&removed, 1))
		return;

	for (i = 0; i < avtab->nslot; i++) {
		struct sp_avtab_node *n;
		struct sp_avtab_node *prev = NULL;

		for (n = avtab->htable[i]; n; prev = n, n = n->next) {
			if (n != node)
				continue;

			if (prev)
				prev->next = n->next;
			else
				avtab->htable[i] = n->next;
			if (avtab->nel > 0)
				avtab->nel--;

			shrink = sizeof(struct sp_avtab_key) +
				 sizeof(struct sp_avtab_datum);
			if (n->key.specified & SP_AVTAB_XPERMS)
				shrink += sizeof(struct sp_xperms);
			if (sp_read_ulong(db, sp_l.pd_len) >= shrink)
				sp_write_ulong(db, sp_l.pd_len,
					       sp_read_ulong(db, sp_l.pd_len) -
						       shrink);

			n->next = NULL;
			removed.htable[0] = n;
			removed.nel = 1;
			sp_f.avtab_destroy(&removed);
			return;
		}
	}

	sp_f.avtab_destroy(&removed);
}

static __nocfi struct sp_avtab_node *sp_get_node(void *db, struct sp_avtab_key *key,
					 struct sp_xperms *xperms)
{
	struct sp_avtab *avtab = sp_avtab_of(db);
	struct sp_avtab_node *node;

	if (key->specified & SP_AVTAB_XPERMS) {
		node = sp_f.search_node(avtab, key);
		while (node) {
			struct sp_xperms *xp = node->datum.u.xperms;
			int i;

			if (xp && xp->specified == xperms->specified &&
			    xp->driver == xperms->driver) {
				/* repeated calls for the same driver merge, existing bits are never dropped */
				for (i = 0; i < ARRAY_SIZE(xp->perms.p); i++)
					xp->perms.p[i] |= xperms->perms.p[i];
				return node;
			}
			node = sp_f.search_node_next(node, key->specified);
		}
	} else {
		node = sp_f.search_node(avtab, key);
		if (node)
			return node;
	}

	{
		struct sp_avtab_datum datum = {};

		if (key->specified & SP_AVTAB_XPERMS) {
			struct sp_xperms *xp;

			xp = kzalloc(sizeof(*xp), GFP_KERNEL);
			if (!xp)
				return NULL;
			memcpy(xp, xperms, sizeof(*xp));
			datum.u.xperms = xp;
		} else {
			datum.u.data = key->specified == SP_AVTAB_AUDITDENY ?
					       ~0U :
					       0U;
		}

		node = sp_f.insert_nonunique(avtab, key, &datum);
		if (!node) {
			if (key->specified & SP_AVTAB_XPERMS)
				kfree(datum.u.xperms);
			return NULL;
		}

		sp_write_ulong(db, sp_l.pd_len,
			       sp_read_ulong(db, sp_l.pd_len) +
				       sizeof(struct sp_avtab_key) +
				       sizeof(struct sp_avtab_datum));
	}

	return node;
}

#define sp_strip_av(effect, invert) ((effect == SP_AVTAB_AUDITDENY) == !(invert))

static __nocfi void sp_add_rule_raw(void *db, void *src, void *tgt, void *cls,
			    void *perm, int effect, bool invert);

static __nocfi void sp_rule_iter(void *db, int idx, void *src, void *tgt, void *cls,
			 void *perm, int effect, bool invert)
{
	struct sp_hashtab *tab = sp_table_of(db, idx);
	u32 i;

	for (i = 0; i < tab->size; i++) {
		struct sp_hashtab_node *n;

		for (n = tab->htable[i]; n; n = n->next) {
			if (idx == SP_SYM_TYPES &&
			    !sp_strip_av(effect, invert)) {
				u32 attr;

				memcpy(&attr,
				       (char *)n->datum + sp_l.td_attribute,
				       sizeof(attr));
				if (!attr)
					continue;
			}
			sp_add_rule_raw(db, src ? src : n->datum,
					tgt ? tgt : n->datum,
					cls ? cls : n->datum, perm, effect,
					invert);
		}
	}
}

static __nocfi void sp_add_rule_raw(void *db, void *src, void *tgt, void *cls,
				    void *perm, int effect, bool invert)
{
	struct sp_avtab_key key;
	struct sp_avtab_node *node;

	if (!src) {
		sp_rule_iter(db, SP_SYM_TYPES, NULL, tgt, cls, perm, effect,
			     invert);
		return;
	}
	if (!tgt) {
		sp_rule_iter(db, SP_SYM_TYPES, src, NULL, cls, perm, effect,
			     invert);
		return;
	}
	if (!cls) {
		sp_rule_iter(db, SP_SYM_CLASSES, src, tgt, NULL, perm, effect,
			     invert);
		return;
	}

	key.source_type = sp_read_u32(src, sp_l.td_value);
	key.target_type = sp_read_u32(tgt, sp_l.td_value);
	key.target_class = sp_read_u32(cls, sp_l.cd_value);
	key.specified = effect;

	if (invert && effect != SP_AVTAB_AUDITDENY) {
		node = sp_f.search_node(sp_avtab_of(db), &key);
		if (!node)
			return;
	} else {
		node = sp_get_node(db, &key, NULL);
		if (!node)
			return;
	}

	if (invert) {
		if (perm)
			node->datum.u.data &=
				~(1U << (sp_read_u32(perm, sp_l.pdm_value) -
					 1));
		else
			node->datum.u.data = 0U;
	} else {
		if (perm)
			node->datum.u.data |=
				1U << (sp_read_u32(perm, sp_l.pdm_value) - 1);
		else
			node->datum.u.data = ~0U;
	}

	if (sp_is_redundant(node))
		sp_remove_node(db, node);
}

static void sp_xperm_set(int bit, u32 *p, bool invert)
{
	if (invert)
		p[bit >> 5] &= ~(1U << (bit & 0x1f));
	else
		p[bit >> 5] |= 1U << (bit & 0x1f);
}

static __nocfi void sp_add_xperm_raw(void *db, void *src, void *tgt, void *cls,
				     u16 low, u16 high, int effect, bool invert)
{
	struct sp_hashtab *tab;
	struct sp_hashtab_node *n;
	struct sp_avtab_key key;
	struct sp_xperms xperms;
	struct sp_avtab_node *node;
	u32 i;
	int b;

	if (!src || !tgt || !cls) {
		tab = sp_table_of(db, !cls ? SP_SYM_CLASSES :
						    SP_SYM_TYPES);
		for (i = 0; i < tab->size; i++) {
			for (n = tab->htable[i]; n; n = n->next) {
				if (!cls) {
					sp_add_xperm_raw(db, src, tgt, n->datum,
							 low, high, effect,
							 invert);
					continue;
				}
				{
					u32 attr;

					memcpy(&attr,
					       (char *)n->datum +
						       sp_l.td_attribute,
					       sizeof(attr));
					if (!attr && !invert)
						continue;
				}
				sp_add_xperm_raw(db, src ? src : n->datum,
						 tgt ? tgt : n->datum, cls,
						 low, high, effect, invert);
			}
		}
		return;
	}

	memset(&xperms, 0, sizeof(xperms));
	if ((low >> 8) != (high >> 8)) {
		xperms.specified = SP_XPERMS_IOCTLDRIVER;
		xperms.driver = 0;
	} else {
		xperms.specified = SP_XPERMS_IOCTLFUNCTION;
		xperms.driver = high >> 8;
	}

	if (xperms.specified == SP_XPERMS_IOCTLDRIVER) {
		for (b = low >> 8; b <= (high >> 8); b++)
			sp_xperm_set(b, xperms.perms.p, invert);
	} else {
		for (b = low & 0xff; b <= (high & 0xff); b++)
			sp_xperm_set(b, xperms.perms.p, invert);
	}

	key.source_type = sp_read_u32(src, sp_l.td_value);
	key.target_type = sp_read_u32(tgt, sp_l.td_value);
	key.target_class = sp_read_u32(cls, sp_l.cd_value);
	key.specified = effect;

	if (!invert) {
		/* existing nodes merge, fresh nodes are heap allocated inside get_node */
		sp_get_node(db, &key, &xperms);
		return;
	}

	/* a delete never creates, it only rewrites nodes of this spec */
	node = sp_f.search_node(sp_avtab_of(db), &key);
	while (node) {
		struct sp_xperms *xp = node->datum.u.xperms;

		if (xp && xp->specified == xperms.specified &&
		    xp->driver == xperms.driver)
			break;
		node = sp_f.search_node_next(node, key.specified);
	}
	if (!node)
		return;

	{
		struct sp_xperms *live = node->datum.u.xperms;

		for (i = 0; i < ARRAY_SIZE(live->perms.p); i++)
			live->perms.p[i] &= ~xperms.perms.p[i];

		for (i = 0; i < ARRAY_SIZE(live->perms.p); i++) {
			if (live->perms.p[i])
				return;
		}
	}
	sp_remove_node(db, node);
}

static __nocfi int sp_add_rule(void *db, const char *s, const char *t, const char *c,
		       const char *p, int effect, bool invert)
{
	void *src = NULL;
	void *tgt = NULL;
	void *cls = NULL;
	void *perm = NULL;

	if (s) {
		src = sp_sym_lookup(db, SP_SYM_TYPES, s);
		if (!src)
			return -ENOENT;
	}
	if (t) {
		tgt = sp_sym_lookup(db, SP_SYM_TYPES, t);
		if (!tgt)
			return -ENOENT;
	}
	if (c) {
		cls = sp_sym_lookup(db, SP_SYM_CLASSES, c);
		if (!cls)
			return -ENOENT;
	}
	if (p) {
		if (!c)
			return -EINVAL;
		perm = sp_class_perm(db, cls, p);
		if (!perm)
			return -ENOENT;
	}

	sp_add_rule_raw(db, src, tgt, cls, perm, effect, invert);
	return 0;
}

static __nocfi int sp_xperm_rule(void *db, const char *s, const char *t,
				 const char *c, const char *range, int effect,
				 bool invert)
{
	void *src = NULL;
	void *tgt = NULL;
	void *cls = NULL;
	u16 low = 0;
	u16 high = 0xffff;

	if (s) {
		src = sp_sym_lookup(db, SP_SYM_TYPES, s);
		if (!src)
			return -ENOENT;
	}
	if (t) {
		tgt = sp_sym_lookup(db, SP_SYM_TYPES, t);
		if (!tgt)
			return -ENOENT;
	}
	if (c) {
		cls = sp_sym_lookup(db, SP_SYM_CLASSES, c);
		if (!cls)
			return -ENOENT;
	}
	if (!cls)
		return -EINVAL;

	if (range) {
		if (strchr(range, '-'))
			sscanf(range, "%hx-%hx", &low, &high);
		else
			sscanf(range, "%hx", &low), high = low;
	}

	sp_add_xperm_raw(db, src, tgt, cls, low, high, effect, invert);
	return 0;
}

static void *sp_kvrealloc(void *p, size_t old_size, size_t new_size)
{
	void *np;

	if (new_size <= old_size)
		return p;
	np = kvmalloc(new_size, GFP_KERNEL);
	if (!np)
		return NULL;
	if (p) {
		memcpy(np, p, old_size);
		kvfree(p);
	}
	return np;
}

static __nocfi int sp_add_type(void *db, const char *name, bool attr)
{
	void *types = sp_symtab_of(db, SP_SYM_TYPES);
	void *type;
	void *arr;
	void *vals;
	void *names;
	char *key;
	u32 value;
	u32 nroles;
	int i;

	if (sp_f.symtab_search(types, name))
		return 0;

	value = sp_read_u32(types, sp_l.sy_nprim) + 1;

	type = kzalloc(64, GFP_KERNEL);
	if (!type)
		return -ENOMEM;
	sp_write_u32(type, sp_l.td_value, value);
	*((u8 *)type + sp_l.td_attribute) = attr ? 1 : 0;
	/* policydb_read only indexes a type whose primary flag is set */
	if (sp_l.td_primary >= 0)
		*((u8 *)type + sp_l.td_primary) = 1;

	key = kstrdup(name, GFP_KERNEL);
	if (!key) {
		kfree(type);
		return -ENOMEM;
	}
	if (sp_f.symtab_insert(types, key, type)) {
		kfree(key);
		kfree(type);
		return -EEXIST;
	}
	sp_write_u32(types, sp_l.sy_nprim, value);

	arr = sp_read_ptr(db, sp_l.pd_type_attr_map_array);
	arr = sp_kvrealloc(arr, (value - 1) * sp_l.size_ebitmap,
			   (size_t)value * sp_l.size_ebitmap);
	if (!arr)
		return -ENOMEM;
	sp_write_ptr(db, sp_l.pd_type_attr_map_array, arr);
	memset((char *)arr + (value - 1) * sp_l.size_ebitmap, 0,
	       sp_l.size_ebitmap);
	sp_f.ebitmap_set_bit((char *)arr + (value - 1) * sp_l.size_ebitmap,
			     value - 1, 1);

	vals = sp_read_ptr(db, sp_l.pd_type_val_to_struct);
	vals = sp_kvrealloc(vals, (value - 1) * sizeof(void *),
			    (size_t)value * sizeof(void *));
	if (!vals)
		return -ENOMEM;
	sp_write_ptr(db, sp_l.pd_type_val_to_struct, vals);
	sp_write_ptr(vals, (long)(value - 1) * sizeof(void *), type);

	names = sp_read_ptr(db, sp_l.pd_sym_val_to_name +
					 SP_SYM_TYPES * sizeof(void *));
	names = sp_kvrealloc(names, (value - 1) * sizeof(void *),
			     (size_t)value * sizeof(void *));
	if (!names)
		return -ENOMEM;
	sp_write_ptr(db, sp_l.pd_sym_val_to_name +
				 SP_SYM_TYPES * sizeof(void *),
		     names);
	sp_write_ptr(names, (long)(value - 1) * sizeof(void *), key);

	nroles = sp_read_u32(sp_symtab_of(db, SP_SYM_ROLES), sp_l.sy_nprim);
	for (i = 0; i < nroles; i++) {
		void *role;
		void *roles;

		roles = sp_read_ptr(db, sp_l.pd_role_val_to_struct);
		role = sp_read_ptr(roles, (long)i * sizeof(void *));
		if (role && sp_l.rd_types >= 0)
			sp_f.ebitmap_set_bit((char *)role + sp_l.rd_types,
					     value - 1, 1);
	}

	return 0;
}

/* the hashtab node is removed by key so the name string is released once */
static __nocfi void sp_symtab_remove(void *db, int idx, const char *name)
{
	struct sp_hashtab *tab = sp_table_of(db, idx);
	u32 i;

	for (i = 0; i < tab->size; i++) {
		struct sp_hashtab_node *n;
		struct sp_hashtab_node *prev = NULL;

		for (n = tab->htable[i]; n; prev = n, n = n->next) {
			if (strcmp((const char *)n->key, name))
				continue;
			if (prev)
				prev->next = n->next;
			else
				tab->htable[i] = n->next;
			if (tab->nel > 0)
				tab->nel--;
			kfree(n->key);
			kfree(n);
			return;
		}
	}
}

static __nocfi int sp_del_type(void *db, const char *name)
{
	void *types = sp_symtab_of(db, SP_SYM_TYPES);
	void *type;
	void *arr;
	void *vals;
	void *names;
	u32 value;
	u32 nroles;
	int i;

	if (!sp_cap(SEPOLICY_CAP_DEL_TYPE))
		return -ENODATA;

	type = sp_f.symtab_search(types, name);
	if (!type)
		return -ENOENT;

	value = sp_read_u32(type, sp_l.td_value);
	if (value != sp_read_u32(types, sp_l.sy_nprim))
		return -EBUSY;

	nroles = sp_read_u32(sp_symtab_of(db, SP_SYM_ROLES), sp_l.sy_nprim);
	for (i = 0; i < nroles; i++) {
		void *role;
		void *roles;

		roles = sp_read_ptr(db, sp_l.pd_role_val_to_struct);
		role = sp_read_ptr(roles, (long)i * sizeof(void *));
		if (role)
			sp_f.ebitmap_set_bit((char *)role + sp_l.rd_types,
					     value - 1, 0);
	}

	arr = sp_read_ptr(db, sp_l.pd_type_attr_map_array);
	sp_q.ebitmap_destroy((char *)arr + (value - 1) * sp_l.size_ebitmap);
	memset((char *)arr + (value - 1) * sp_l.size_ebitmap, 0,
	       sp_l.size_ebitmap);

	vals = sp_read_ptr(db, sp_l.pd_type_val_to_struct);
	sp_write_ptr(vals, (long)(value - 1) * sizeof(void *), NULL);

	names = sp_read_ptr(db, sp_l.pd_sym_val_to_name +
					 SP_SYM_TYPES * sizeof(void *));
	sp_write_ptr(names, (long)(value - 1) * sizeof(void *), NULL);

	sp_symtab_remove(db, SP_SYM_TYPES, name);
	sp_write_u32(types, sp_l.sy_nprim, value - 1);
	kfree(type);
	return 0;
}

static __nocfi int sp_del_typeattribute(void *db, const char *type, const char *attr)
{
	u32 type_val;
	u32 attr_val;
	struct sp_hashtab *tab = sp_table_of(db, SP_SYM_CLASSES);
	void *td;
	void *ad;
	void *sattr;
	u32 i;

	td = sp_sym_lookup(db, SP_SYM_TYPES, type);
	if (!td)
		return -ENOENT;
	ad = sp_sym_lookup(db, SP_SYM_TYPES, attr);
	if (!ad)
		return -ENOENT;
	if (sp_read_u32(ad, sp_l.td_attribute) != 1)
		return -EINVAL;

	type_val = sp_read_u32(td, sp_l.td_value);
	attr_val = sp_read_u32(ad, sp_l.td_value);

	sattr = sp_read_ptr(db, sp_l.pd_type_attr_map_array);
	sattr = (char *)sattr + (type_val - 1) * sp_l.size_ebitmap;
	sp_f.ebitmap_set_bit(sattr, attr_val - 1, 0);

	for (i = 0; i < tab->size; i++) {
		struct sp_hashtab_node *n;

		for (n = tab->htable[i]; n; n = n->next) {
			void *cn;

			cn = sp_read_ptr(n->datum, sp_l.cd_constraints);
			for (; cn; cn = sp_read_ptr(cn, sp_l.cn_next)) {
				void *e;

				e = sp_read_ptr(cn, sp_l.cn_expr);
				for (; e; e = sp_read_ptr(e, sp_l.ce_next)) {
					void *tn;

					if (sp_read_u32(e, sp_l.ce_expr_type) !=
					    SP_CEXPR_NAMES)
						continue;
					tn = sp_read_ptr(e, sp_l.ce_type_names);
					if (!tn)
						continue;
					if (sp_f.ebitmap_get_bit(tn,
								 attr_val - 1))
						sp_f.ebitmap_set_bit(
							(char *)e +
								sp_l.ce_names,
							type_val - 1, 0);
				}
			}
		}
	}
	return 0;
}

static __nocfi void sp_add_typeattribute_raw(void *db, void *type, void *attr)
{
	u32 type_val = sp_read_u32(type, sp_l.td_value);
	u32 attr_val = sp_read_u32(attr, sp_l.td_value);
	struct sp_hashtab *tab = sp_table_of(db, SP_SYM_CLASSES);
	void *sattr;
	u32 i;

	sattr = sp_read_ptr(db, sp_l.pd_type_attr_map_array);
	sattr = (char *)sattr + (type_val - 1) * sp_l.size_ebitmap;
	sp_f.ebitmap_set_bit(sattr, attr_val - 1, 1);

	for (i = 0; i < tab->size; i++) {
		struct sp_hashtab_node *n;

		for (n = tab->htable[i]; n; n = n->next) {
			void *cn;

			/* constraint expressions index by attribute name, a new type adds itself here */
			cn = sp_read_ptr(n->datum, sp_l.cd_constraints);
			for (; cn; cn = sp_read_ptr(cn, sp_l.cn_next)) {
				void *e;

				e = sp_read_ptr(cn, sp_l.cn_expr);
				for (; e; e = sp_read_ptr(e, sp_l.ce_next)) {
					void *tn;

					if (sp_read_u32(e, sp_l.ce_expr_type) !=
					    SP_CEXPR_NAMES)
						continue;
					tn = sp_read_ptr(e,
							 sp_l.ce_type_names);
					if (!tn)
						continue;
					if (sp_f.ebitmap_get_bit(tn,
								 attr_val - 1))
						sp_f.ebitmap_set_bit(
							(char *)e +
								sp_l.ce_names,
							type_val - 1, 1);
				}
			}
		}
	}
}

static __nocfi int sp_add_typeattribute(void *db, const char *type, const char *attr)
{
	void *td;
	void *ad;

	td = sp_sym_lookup(db, SP_SYM_TYPES, type);
	if (!td)
		return -ENOENT;
	ad = sp_sym_lookup(db, SP_SYM_TYPES, attr);
	if (!ad)
		return -ENOENT;
	if (sp_read_u32(ad, sp_l.td_attribute) != 1)
		return -EINVAL;

	sp_add_typeattribute_raw(db, td, ad);
	return 0;
}

static __nocfi int sp_set_permissive(void *db, const char *type, bool permissive)
{
	void *pm = (char *)db + sp_l.pd_permissive_map;
	struct sp_hashtab *tab = sp_table_of(db, SP_SYM_TYPES);
	void *td;
	u32 i;

	if (type) {
		td = sp_sym_lookup(db, SP_SYM_TYPES, type);
		if (!td)
			return -ENOENT;
		return sp_f.ebitmap_set_bit(pm, sp_read_u32(td, sp_l.td_value),
					    permissive ? 1 : 0) ?
			       -EINVAL :
			       0;
	}

	for (i = 0; i < tab->size; i++) {
		struct sp_hashtab_node *n;

		for (n = tab->htable[i]; n; n = n->next)
			sp_f.ebitmap_set_bit(pm,
					     sp_read_u32(n->datum,
							 sp_l.td_value),
					     permissive ? 1 : 0);
	}
	return 0;
}

static __nocfi int sp_type_rule(void *db, const char *s, const char *t,
				const char *c, const char *def, int effect)
{
	struct sp_avtab_key key;
	struct sp_avtab_node *node;
	void *src;
	void *tgt;
	void *cls;
	void *dfl;

	src = sp_sym_lookup(db, SP_SYM_TYPES, s);
	tgt = sp_sym_lookup(db, SP_SYM_TYPES, t);
	cls = sp_sym_lookup(db, SP_SYM_CLASSES, c);
	dfl = sp_sym_lookup(db, SP_SYM_TYPES, def);
	if (!src || !tgt || !cls || !dfl)
		return -ENOENT;

	key.source_type = sp_read_u32(src, sp_l.td_value);
	key.target_type = sp_read_u32(tgt, sp_l.td_value);
	key.target_class = sp_read_u32(cls, sp_l.cd_value);
	key.specified = effect;

	node = sp_get_node(db, &key, NULL);
	if (!node)
		return -ENOMEM;
	node->datum.u.data = sp_read_u32(dfl, sp_l.td_value);
	return 0;
}

/*
 * filename_trans carries object name transitions. The table hash and the
 * hashtab helpers are static inlines since 5.9, so the search body and the
 * bucket computation are repeated here and only __hashtab_insert is resolved.
 * The hash itself changed in 6.12 from a byte loop to full_name_hash with the
 * type values as salt; which generation a table was built with is read off the
 * table contents at run time instead of a version macro.
 */
static u32 sp_ft_hash_old(const void *k)
{
	const struct sp_filename_trans_key *ft = k;
	unsigned long hash = ft->ttype ^ ft->tclass;
	u32 i = 0;
	unsigned char focus;

	while ((focus = ft->name[i++]))
		hash = (hash + (focus << 4) + (focus >> 4)) * 11;
	return hash;
}

static __nocfi u32 sp_ft_hash_new(const void *k)
{
	const struct sp_filename_trans_key *ft = k;

	return sp_q.name_hash(
		(const void *)(unsigned long)(ft->ttype ^ ft->tclass),
		ft->name, strlen(ft->name));
}

static int sp_ft_cmp(const void *k1, const void *k2)
{
	const struct sp_filename_trans_key *ft1 = k1;
	const struct sp_filename_trans_key *ft2 = k2;
	int v;

	v = ft1->ttype - ft2->ttype;
	if (v)
		return v;

	v = ft1->tclass - ft2->tclass;
	if (v)
		return v;

	return strcmp(ft1->name, ft2->name);
}

static u32 sp_ft_hash(const void *key, int variant)
{
	if (variant == 2)
		return sp_ft_hash_new(key);
	return sp_ft_hash_old(key);
}

/* 1 old hash, 2 salted hash, 0 when the table cannot tell */
static int sp_ft_variant(void *db)
{
	struct sp_hashtab *tab = (void *)((char *)db + sp_l.pd_filename_trans);
	u32 i;

	if (!sp_q.name_hash)
		return 0;

	for (i = 0; i < tab->size; i++) {
		struct sp_hashtab_node *n;

		for (n = tab->htable[i]; n; n = n->next) {
			bool old_ok;
			bool new_ok;

			old_ok = (sp_ft_hash_old(n->key) & (tab->size - 1)) ==
				 i;
			new_ok = (sp_ft_hash_new(n->key) & (tab->size - 1)) ==
				 i;
			if (old_ok != new_ok)
				return new_ok ? 2 : 1;
		}
	}
	return 0;
}

static __nocfi void *sp_ft_search(void *db, struct sp_filename_trans_key *key)
{
	struct sp_hashtab *tab = (void *)((char *)db + sp_l.pd_filename_trans);
	struct sp_hashtab_node *cur;
	u32 hvalue;
	int variant;

	if (sp_q.filenametr_search)
		return sp_q.filenametr_search(db, key);

	variant = sp_ft_variant(db);
	if (!variant)
		return NULL;

	hvalue = sp_ft_hash(key, variant) & (tab->size - 1);
	for (cur = tab->htable[hvalue]; cur; cur = cur->next) {
		if (!sp_ft_cmp(key, cur->key))
			return cur->datum;
	}
	return NULL;
}

static __nocfi int sp_ft_insert(void *db, struct sp_filename_trans_key *key,
			void *datum, int variant)
{
	struct sp_hashtab *tab = (void *)((char *)db + sp_l.pd_filename_trans);
	struct sp_hashtab_node *prev = NULL;
	struct sp_hashtab_node *cur;
	void **dst;
	u32 hvalue;
	int cmp;

	if (!tab->size || tab->nel == SP_HASHTAB_MAX_NODES)
		return -EINVAL;

	hvalue = sp_ft_hash(key, variant) & (tab->size - 1);
	cur = tab->htable[hvalue];
	while (cur) {
		cmp = sp_ft_cmp(key, cur->key);
		if (cmp == 0)
			return -EEXIST;
		if (cmp < 0)
			break;
		prev = cur;
		cur = cur->next;
	}
	if (prev)
		dst = (void **)&prev->next;
	else
		dst = (void **)&tab->htable[hvalue];

	return sp_q.hashtab_insert(tab, dst, key, datum);
}

static __nocfi int sp_filename_trans(void *db, const char *s, const char *t,
				     const char *c, const char *def,
				     const char *name)
{
	struct sp_filename_trans_key *new_key;
	struct sp_filename_trans_key key;
	void *src;
	void *tgt;
	void *cls;
	void *dfl;
	void *trans;
	void *last = NULL;
	u32 src_val;
	int variant;
	int ret;

	if (!s || !t || !c || !def || !name)
		return -EINVAL;
	if (!sp_cap(SEPOLICY_CAP_FILENAME_TRANS))
		return -ENODATA;

	src = sp_sym_lookup(db, SP_SYM_TYPES, s);
	tgt = sp_sym_lookup(db, SP_SYM_TYPES, t);
	cls = sp_sym_lookup(db, SP_SYM_CLASSES, c);
	dfl = sp_sym_lookup(db, SP_SYM_TYPES, def);
	if (!src || !tgt || !cls || !dfl)
		return -ENOENT;

	variant = sp_ft_variant(db);
	if (!variant)
		return -ENODATA;

	src_val = sp_read_u32(src, sp_l.td_value);
	key.ttype = sp_read_u32(tgt, sp_l.td_value);
	key.tclass = sp_read_u32(cls, sp_l.cd_value);
	key.name = name;

	trans = sp_ft_search(db, &key);
	while (trans) {
		if (sp_f.ebitmap_get_bit((char *)trans + sp_l.ft_stypes,
					 src_val - 1)) {
			/* this source type is already carried, retarget it */
			sp_write_u32(trans, sp_l.ft_otype,
				     sp_read_u32(dfl, sp_l.td_value));
			return 0;
		}
		if (sp_read_u32(trans, sp_l.ft_otype) ==
		    sp_read_u32(dfl, sp_l.td_value))
			break;
		last = trans;
		trans = sp_read_ptr(trans, sp_l.ft_next);
	}

	if (trans) {
		ret = sp_f.ebitmap_set_bit((char *)trans + sp_l.ft_stypes,
					   src_val - 1, 1);
		return ret ? ret : 0;
	}

	trans = kzalloc((size_t)sp_l.ft_next + sizeof(void *), GFP_KERNEL);
	if (!trans)
		return -ENOMEM;
	new_key = kzalloc(sizeof(*new_key), GFP_KERNEL);
	if (!new_key) {
		kfree(trans);
		return -ENOMEM;
	}
	*new_key = key;
	new_key->name = kstrdup(name, GFP_KERNEL);
	if (!new_key->name) {
		kfree(new_key);
		kfree(trans);
		return -ENOMEM;
	}

	sp_write_ptr(trans, sp_l.ft_next, last);
	sp_write_u32(trans, sp_l.ft_otype, sp_read_u32(dfl, sp_l.td_value));

	ret = sp_ft_insert(db, new_key, trans, variant);
	if (ret) {
		kfree(new_key->name);
		kfree(new_key);
		kfree(trans);
		return ret;
	}

	ret = sp_f.ebitmap_set_bit((char *)trans + sp_l.ft_stypes,
				   src_val - 1, 1);
	if (ret)
		return ret;

	/* old policy versions write this count, new ones the table size */
	sp_write_u32(db, sp_l.pd_ft_count,
		     sp_read_u32(db, sp_l.pd_ft_count) + 1);

	/* services.c skips the lookup when the parent type bit is clear */
	return sp_f.ebitmap_set_bit((char *)db + sp_l.pd_ft_ttypes,
				    sp_read_u32(tgt, sp_l.td_value), 1);
}

/*
 * Optional companion rule set, the shape KernelSU applies to its own domain.
 * Every line is a source domain plus a class and one permission, a NULL
 * permission means the whole class. Kept as data so the switch stays with the
 * consumer.
 */
struct sp_rule_line {
	const char *src;
	const char *cls;
	const char *perm;
};

static const struct sp_rule_line sp_companion_rules[] = {
	{ "servicemanager", "dir", "search" },
	{ "servicemanager", "dir", "read" },
	{ "servicemanager", "file", "open" },
	{ "servicemanager", "file", "read" },
	{ "servicemanager", "process", "getattr" },
	{ "logd", "dir", "search" },
	{ "logd", "file", "read" },
	{ "logd", "file", "open" },
	{ "logd", "file", "getattr" },
	{ "hwservicemanager", "dir", "search" },
	{ "hwservicemanager", "file", "read" },
	{ "hwservicemanager", "file", "open" },
	{ "hwservicemanager", "process", "getattr" },
	{ "system_server", "process", "getpgid" },
	{ "system_server", "process", "sigkill" },
	{ "domain", "process", "sigchld" },
	{ "domain", "fd", "use" },
	{ "domain", "fifo_file", "write" },
	{ "domain", "fifo_file", "read" },
	{ "domain", "fifo_file", "open" },
	{ "domain", "fifo_file", "getattr" },
	{ "domain", "unix_stream_socket", "read" },
	{ "domain", "unix_stream_socket", "write" },
	{ "domain", "unix_stream_socket", "connectto" },
	{ "domain", "unix_stream_socket", "getopt" },
	{ "domain", "unix_stream_socket", "getattr" },
	{ "domain", "memfd_file", "execute" },
	{ "domain", "memfd_file", "getattr" },
	{ "domain", "memfd_file", "map" },
	{ "domain", "memfd_file", "read" },
	{ "domain", "memfd_file", "write" },
	{ "domain", "binder", NULL },
};

static const char *const sp_companion_attrs[] = {
	"domain",
	"mlstrustedsubject",
	"netdomain",
	"bluetoothdomain",
};

static const char *const sp_xperm_classes[] = {
	"blk_file",
	"fifo_file",
	"chr_file",
	"file",
};

static __nocfi int sp_apply_domain_rules(void *db, const char *domain,
					 const char *file)
{
	u32 i;
	int ret;

	ret = sp_add_type(db, domain, false);
	if (ret)
		return ret;

	for (i = 0; i < ARRAY_SIZE(sp_companion_attrs); i++) {
		ret = sp_add_typeattribute(db, domain, sp_companion_attrs[i]);
		/* trimmed policies drop some of the optional attributes */
		if (ret && i == 0)
			return ret;
	}

	if (file) {
		ret = sp_add_type(db, file, false);
		if (ret)
			return ret;
		sp_add_typeattribute(db, file, "file_type");
		sp_add_typeattribute(db, file, "mlstrustedobject");
		sp_add_rule(db, "domain", file, NULL, NULL, SP_AVTAB_ALLOWED,
			    false);
	}

	ret = sp_add_rule(db, domain, NULL, NULL, NULL, SP_AVTAB_ALLOWED,
			  false);
	if (ret)
		return ret;
	sp_add_rule(db, "init", domain, NULL, NULL, SP_AVTAB_ALLOWED, false);

	if (sp_l.pd_policyvers >= 0 &&
	    sp_read_u32(db, sp_l.pd_policyvers) >=
		    SP_POLICYDB_VERSION_XPERMS_IOCTL) {
		for (i = 0; i < ARRAY_SIZE(sp_xperm_classes); i++)
			sp_xperm_rule(db, domain, NULL, sp_xperm_classes[i],
				      NULL, SP_AVTAB_XPERMS_ALLOWED, false);
	}

	for (i = 0; i < ARRAY_SIZE(sp_companion_rules); i++) {
		const struct sp_rule_line *r = &sp_companion_rules[i];

		sp_add_rule(db, r->src, domain, r->cls, r->perm,
			    SP_AVTAB_ALLOWED, false);
	}
	return 0;
}

static void *sp_live(void)
{
	return sp_read_ptr((void *)sp_state_addr, sp_l.st_policy);
}

static __nocfi void sp_destroy_policy(void *pol)
{
	if (!pol)
		return;
	if (sp_f.policydb_destroy)
		sp_f.policydb_destroy((char *)pol + sp_l.sp_policydb);
	kfree(pol);
}

static __nocfi void *sp_dup_policy(void *old)
{
	struct sp_policy_file fp;
	void *db;
	void *data;
	void *pol;
	size_t alloc;
	size_t len;
	u32 nprim;
	int ret;

	if (!old)
		return ERR_PTR(-ENODATA);

	db = (char *)old + sp_l.sp_policydb;
	nprim = sp_read_u32(sp_symtab_of(db, SP_SYM_TYPES), sp_l.sy_nprim);
	alloc = sp_read_ulong(db, sp_l.pd_len) +
		(size_t)nprim * (sizeof(u32) + sizeof(u64));
	if (!alloc)
		return ERR_PTR(-ENODATA);

	data = vmalloc(alloc);
	if (!data)
		return ERR_PTR(-ENOMEM);

	fp.data = data;
	fp.len = alloc;
	ret = sp_f.policydb_write(db, &fp);
	if (ret) {
		vfree(data);
		return ERR_PTR(ret);
	}
	len = alloc - fp.len;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	/* the copy must carry the android netlink config bits or the read back drops them */
	if (len >= SP_CONFIG_OFF + sizeof(u32)) {
		u32 cfg;

		memcpy(&cfg, (char *)data + SP_CONFIG_OFF, sizeof(cfg));
		if (sp_l.pd_route >= 0 && sp_read_u32(db, sp_l.pd_route))
			cfg |= SP_NETLINK_ROUTE;
		if (sp_l.pd_getneigh >= 0 &&
		    sp_read_u32(db, sp_l.pd_getneigh))
			cfg |= SP_NETLINK_GETNEIGH;
		memcpy((char *)data + SP_CONFIG_OFF, &cfg, sizeof(cfg));
	}
#endif

	pol = kmemdup(old, sp_l.size_policy, GFP_KERNEL);
	if (!pol) {
		vfree(data);
		return ERR_PTR(-ENOMEM);
	}
	memset((char *)pol + sp_l.sp_policydb, 0, sp_l.size_policydb);

	fp.data = data;
	fp.len = len;
	ret = sp_f.policydb_read((char *)pol + sp_l.sp_policydb, &fp);
	if (ret) {
		kfree(pol);
		vfree(data);
		return ERR_PTR(ret);
	}
	sp_write_ulong((char *)pol + sp_l.sp_policydb, sp_l.pd_len, len);
	vfree(data);

	return pol;
}

/*
 * Queries against one policy pointer. Everything the kernel already exposes as
 * a function over a policydb, a sidtab or a context is called as it is: the
 * context string parse and render, the access vector computation and the
 * constraint walk. Only what no symbol provides is repeated below, and the
 * replications are used exactly when the matching symbol is missing, which for
 * context_struct_compute_av is the case on 6.1.
 */

static void *sp_db_of(void *pol)
{
	return (char *)pol + sp_l.sp_policydb;
}

static void *sp_sidtab_of(void *pol)
{
	if (sp_l.sp_sidtab < 0)
		return NULL;
	return sp_read_ptr(pol, sp_l.sp_sidtab);
}

static __nocfi void *sp_sid_context(void *pol, u32 sid)
{
	void *sidtab = sp_sidtab_of(pol);
	void *entry;

	if (!sidtab)
		return NULL;
	entry = sp_q.sid_entry(sidtab, sid);
	if (!entry)
		return NULL;
	return (char *)entry + sp_l.se_context;
}

static const char *sp_sym_name(void *db, int idx, u32 val)
{
	void *arr;

	if (!val)
		return NULL;
	arr = sp_read_ptr(db, sp_l.pd_sym_val_to_name +
				  (long)idx * sizeof(void *));
	if (!arr)
		return NULL;
	return sp_read_ptr(arr, (long)(val - 1) * sizeof(void *));
}

/* context_destroy is a static inline, a kernel may not carry a copy */
static __nocfi void sp_context_free(void *ctx)
{
	if (sp_q.context_destroy) {
		sp_q.context_destroy(ctx);
		return;
	}

	kfree(sp_read_ptr(ctx, sp_l.se_str));
	sp_q.ebitmap_destroy((char *)ctx + sp_l.se_range + sp_l.rl_level +
			     sp_l.ll_cat);
	sp_q.ebitmap_destroy((char *)ctx + sp_l.se_range + sp_l.rl_level +
			     sp_l.size_mls_level + sp_l.ll_cat);
	memset(ctx, 0, sp_l.size_context);
}

/* string_to_context_struct body, used when the kernel copy was inlined away */
static __nocfi int sp_context_parse(void *db, void *sidtab, char *scontext,
				    void *ctx, u32 def_sid)
{
	void *ud;
	void *role;
	void *type;
	char *field;
	char *p;
	char oldc;
	int ret;

	memset(ctx, 0, sp_l.size_context);

	p = scontext;
	field = p;
	while (*p && *p != ':')
		p++;
	if (!*p)
		return -EINVAL;
	*p++ = 0;
	ud = sp_sym_lookup(db, SP_SYM_USERS, field);
	if (!ud)
		return -EINVAL;
	sp_write_u32(ctx, sp_l.se_user, sp_read_u32(ud, sp_l.ud_value));

	field = p;
	while (*p && *p != ':')
		p++;
	if (!*p)
		return -EINVAL;
	*p++ = 0;
	role = sp_sym_lookup(db, SP_SYM_ROLES, field);
	if (!role)
		return -EINVAL;
	sp_write_u32(ctx, sp_l.se_role, sp_read_u32(role, sp_l.rd_value));

	field = p;
	while (*p && *p != ':')
		p++;
	oldc = *p;
	*p++ = 0;
	type = sp_sym_lookup(db, SP_SYM_TYPES, field);
	if (!type || sp_read_u32(type, sp_l.td_attribute))
		return -EINVAL;
	sp_write_u32(ctx, sp_l.se_type, sp_read_u32(type, sp_l.td_value));

	ret = sp_q.mls_to_sid(db, oldc, p, ctx, sidtab, def_sid);
	if (ret)
		return ret;
	if (!sp_q.context_valid(db, ctx))
		return -EINVAL;
	return 0;
}

/* context_struct_to_string body, same reason as the parse above */
static __nocfi int sp_context_render(void *db, void *ctx, char **scontext,
				     u32 *scontext_len)
{
	const char *user;
	const char *role;
	const char *type;
	char *buf;
	char *p;
	u32 len;

	*scontext = NULL;
	*scontext_len = 0;

	if (sp_read_u32(ctx, sp_l.se_len)) {
		*scontext_len = sp_read_u32(ctx, sp_l.se_len);
		*scontext = kstrdup(sp_read_ptr(ctx, sp_l.se_str), GFP_KERNEL);
		return *scontext ? 0 : -ENOMEM;
	}

	user = sp_sym_name(db, SP_SYM_USERS, sp_read_u32(ctx, sp_l.se_user));
	role = sp_sym_name(db, SP_SYM_ROLES, sp_read_u32(ctx, sp_l.se_role));
	type = sp_sym_name(db, SP_SYM_TYPES, sp_read_u32(ctx, sp_l.se_type));
	if (!user || !role || !type)
		return -EINVAL;

	len = strlen(user) + strlen(role) + strlen(type) + 3 +
	      sp_q.mls_context_len(db, ctx);
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	p = buf;
	p += sprintf(p, "%s:%s:%s", user, role, type);
	sp_q.mls_to_context(db, ctx, &p);
	*p = 0;

	*scontext = buf;
	*scontext_len = len;
	return 0;
}

static __nocfi int sp_context_to_string(void *db, void *ctx, char **scontext,
					u32 *scontext_len)
{
	if (sp_q.context_to_string)
		return sp_q.context_to_string(db, ctx, scontext, scontext_len);
	return sp_context_render(db, ctx, scontext, scontext_len);
}

/* A policy with type bounds needs the bounds pass, which some kernels inline */
static bool sp_has_bounds(void *db)
{
	struct sp_hashtab *tab = sp_table_of(db, SP_SYM_TYPES);
	u32 i;

	for (i = 0; i < tab->size; i++) {
		struct sp_hashtab_node *n;

		for (n = tab->htable[i]; n; n = n->next) {
			if (sp_read_u32(n->datum, sp_l.td_bounds))
				return true;
		}
	}
	return false;
}

/* context_struct_compute_av body for the kernels that inlined it away */
static __nocfi int sp_compute_av_repl(void *db, void *sctx, void *tctx,
				      u16 tclass, struct sepolicy_av_decision *avd)
{
	struct sp_avtab_key key;
	struct sp_avtab_node *node;
	void *attrs;
	void *sattr;
	void *tattr;
	void *cls;
	void *cn;
	u32 nprim;
	u32 i;
	u32 j;

	if (!tclass || tclass > sp_read_u32(sp_symtab_of(db, SP_SYM_CLASSES),
					    sp_l.sy_nprim))
		return -EINVAL;

	cls = sp_read_ptr(db, sp_l.pd_class_val_to_struct);
	cls = sp_read_ptr(cls, (long)(tclass - 1) * sizeof(void *));
	if (!cls)
		return -EINVAL;

	avd->allowed = 0;
	avd->auditallow = 0;
	avd->auditdeny = ~0U;

	nprim = sp_read_u32(sp_symtab_of(db, SP_SYM_TYPES), sp_l.sy_nprim);
	attrs = sp_read_ptr(db, sp_l.pd_type_attr_map_array);
	sattr = (char *)attrs +
		(long)(sp_read_u32(sctx, sp_l.se_type) - 1) * sp_l.size_ebitmap;
	tattr = (char *)attrs +
		(long)(sp_read_u32(tctx, sp_l.se_type) - 1) * sp_l.size_ebitmap;

	key.target_class = tclass;
	key.specified = SP_AVTAB_AV | SP_AVTAB_XPERMS;

	for (i = 0; i < nprim; i++) {
		if (!sp_f.ebitmap_get_bit(sattr, i))
			continue;
		for (j = 0; j < nprim; j++) {
			if (!sp_f.ebitmap_get_bit(tattr, j))
				continue;
			key.source_type = i + 1;
			key.target_type = j + 1;
			for (node = sp_f.search_node(sp_avtab_of(db), &key);
			     node;
			     node = sp_f.search_node_next(node, key.specified)) {
				if (node->key.specified == SP_AVTAB_ALLOWED)
					avd->allowed |= node->datum.u.data;
				else if (node->key.specified ==
					 SP_AVTAB_AUDITALLOW)
					avd->auditallow |= node->datum.u.data;
				else if (node->key.specified ==
					 SP_AVTAB_AUDITDENY)
					avd->auditdeny &= node->datum.u.data;
			}
			if (sp_q.cond_av)
				sp_q.cond_av((char *)db + sp_l.pd_te_cond_avtab,
					     &key, avd, NULL);
		}
	}

	for (cn = sp_read_ptr(cls, sp_l.cd_constraints); cn;
	     cn = sp_read_ptr(cn, sp_l.cn_next)) {
		u32 perms = sp_read_u32(cn, sp_l.cn_permissions);

		if ((perms & avd->allowed) &&
		    !sp_q.constraint_eval(db, sctx, tctx, NULL,
					  sp_read_ptr(cn, sp_l.cn_expr)))
			avd->allowed &= ~perms;
	}

	if (sp_l.pd_process_class >= 0 &&
	    sp_l.pd_process_trans_perms >= 0) {
		u32 srole = sp_read_u32(sctx, sp_l.se_role);
		u32 trole = sp_read_u32(tctx, sp_l.se_role);
		u32 trans = sp_read_u32(db, sp_l.pd_process_trans_perms);

		if (tclass == sp_read_u16(db, sp_l.pd_process_class) &&
		    (avd->allowed & trans) && srole != trole) {
			void *ra = sp_read_ptr(db, sp_l.pd_role_allow);

			for (; ra; ra = sp_read_ptr(ra, sp_l.ra_next)) {
				if (sp_read_u32(ra, sp_l.ra_role) == srole &&
				    sp_read_u32(ra, sp_l.ra_new_role) == trole)
					break;
			}
			if (!ra)
				avd->allowed &= ~trans;
		}
	}

	if (sp_q.bounds_av) {
		sp_q.bounds_av(db, sctx, tctx, tclass, avd);
	} else if (sp_l.td_bounds >= 0 && sp_has_bounds(db)) {
		return -ENODATA;
	}
	return 0;
}

static __nocfi int sp_policy_to_sid(void *pol, const char *scontext,
				    u32 scontext_len, u32 *sid)
{
	void *db;
	void *sidtab;
	void *ctx;
	char *copy;
	u32 len;
	int ret;

	if (!pol || !scontext || !sid)
		return -EINVAL;
	if (!sp_cap(SEPOLICY_CAP_SID))
		return -ENODATA;

	sidtab = sp_sidtab_of(pol);
	if (!sidtab)
		return -ENODATA;
	db = sp_db_of(pol);

	len = scontext_len;
	if (!len)
		len = strlen(scontext);
	copy = kmalloc(len + 1, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	memcpy(copy, scontext, len);
	copy[len] = 0;

	ctx = kzalloc(sp_l.size_context, GFP_KERNEL);
	if (!ctx) {
		kfree(copy);
		return -ENOMEM;
	}

	if (sp_q.context_parse)
		ret = sp_q.context_parse(db, sidtab, copy, ctx, SP_SECSID_NULL);
	else
		ret = sp_context_parse(db, sidtab, copy, ctx, SP_SECSID_NULL);
	if (!ret)
		ret = sp_q.sidtab_to_sid(sidtab, ctx, sid);
	sp_context_free(ctx);

	kfree(ctx);
	kfree(copy);
	return ret;
}

static __nocfi int sp_policy_sid_to_context(void *pol, u32 sid,
					    char **scontext,
					    u32 *scontext_len)
{
	void *ctx;

	if (!pol || !scontext || !scontext_len)
		return -EINVAL;
	if (!sp_cap(SEPOLICY_CAP_SID_TO_CTX))
		return -ENODATA;

	ctx = sp_sid_context(pol, sid);
	if (!ctx)
		return -EINVAL;
	return sp_context_to_string(sp_db_of(pol), ctx, scontext,
				    scontext_len);
}

static __nocfi int sp_policy_av(void *pol, u32 ssid, u32 tsid, u16 tclass,
				struct sepolicy_av_decision *avd)
{
	void *db;
	void *sctx;
	void *tctx;

	if (!pol || !avd)
		return -EINVAL;
	if (!sp_cap(SEPOLICY_CAP_AV))
		return -ENODATA;
	if (!sp_sidtab_of(pol))
		return -ENODATA;
	if (!tclass)
		return -EINVAL;

	sctx = sp_sid_context(pol, ssid);
	tctx = sp_sid_context(pol, tsid);
	if (!sctx || !tctx)
		return -EINVAL;

	db = sp_db_of(pol);
	memset(avd, 0, sizeof(*avd));
	avd->auditdeny = ~0U;
	avd->seqno = sp_read_u32(pol, sp_l.sp_latest_granting);
	if (sp_f.ebitmap_get_bit((char *)db + sp_l.pd_permissive_map,
				 sp_read_u32(sctx, sp_l.se_type)))
		avd->flags |= SEPOLICY_AV_FLAG_PERMISSIVE;

	if (sp_q.compute_av) {
		sp_q.compute_av(db, sctx, tctx, tclass, avd, NULL);
		return 0;
	}
	return sp_compute_av_repl(db, sctx, tctx, tclass, avd);
}

static __nocfi bool sp_policy_has_perm(void *pol, u32 ssid, u32 tsid,
				       u16 tclass, u32 perm)
{
	struct sepolicy_av_decision avd;

	if (sp_policy_av(pol, ssid, tsid, tclass, &avd))
		return false;
	if (avd.flags & SEPOLICY_AV_FLAG_PERMISSIVE)
		return true;
	return (avd.allowed & perm) != 0;
}

static __nocfi void *sp_backup_policy(void)
{
	void *pol;
	void *sidtab;
	int ret;

	if (!sp_cap(SEPOLICY_CAP_BACKUP))
		return NULL;

	pol = sp_dup_policy(sp_live());
	if (IS_ERR(pol))
		return NULL;

	sidtab = kzalloc(sp_l.size_sidtab, GFP_KERNEL);
	if (!sidtab) {
		sp_destroy_policy(pol);
		return NULL;
	}
	if (sp_q.sidtab_init(sidtab)) {
		kfree(sidtab);
		sp_destroy_policy(pol);
		return NULL;
	}
	sp_write_ptr(pol, sp_l.sp_sidtab, sidtab);

	/* only the initial SIDs are loaded, later contexts insert on demand */
	ret = sp_q.load_isids(sp_db_of(pol), sidtab);
	if (ret) {
		sp_q.sidtab_destroy(sidtab);
		kfree(sidtab);
		sp_destroy_policy(pol);
		return NULL;
	}
	return pol;
}

static __nocfi void sp_free_backup_policy(void *pol)
{
	void *sidtab;

	if (!pol)
		return;
	if (sp_l.sp_sidtab >= 0 && sp_q.sidtab_destroy) {
		sidtab = sp_read_ptr(pol, sp_l.sp_sidtab);
		if (sidtab) {
			sp_q.sidtab_destroy(sidtab);
			kfree(sidtab);
		}
	}
	sp_destroy_policy(pol);
}

static __nocfi void sp_reset_avc(void)
{
	if (!sp_f.avc_reset)
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	((int (*)(u32))sp_f.avc_reset)(0);
#else
	{
		void *avc;

		avc = sp_l.st_avc >= 0 ?
			      sp_read_ptr((void *)sp_state_addr, sp_l.st_avc) :
			      NULL;
		((int (*)(void *, u32))sp_f.avc_reset)(avc, 0);
	}
#endif
}

int __nocfi sepolicy_init(unsigned long (*resolve)(const char *name))
{
	struct ti_resolver res = {
		.name_to_addr = resolve,
	};
	int ret;

	if (!resolve)
		return -EINVAL;
	sp_resolve = resolve;

	if (!ti_ready()) {
		ret = ti_init(&res);
		if (ret)
			return ret;
		sp_ti_owner = true;
	}
	sp_btf = ti_base();
	if (!sp_btf)
		return -ENODATA;

	ret = sp_layout_load();
	if (ret) {
		pr_info("[sepolicy] layout unavailable: %d\n", ret);
		return ret;
	}
	ret = sp_resolve_fns();
	if (ret) {
		pr_info("[sepolicy] symbols unavailable: %d\n", ret);
		return ret;
	}

	sp_state_addr = resolve("selinux_state");
	if (!sp_state_addr)
		return -ENODATA;

	sp_resolve_query();
	sp_ready = true;
	sp_caps_update();
	return 0;
}

void sepolicy_exit(void)
{
	sepolicy_rollback();
	if (sp_ti_owner)
		ti_exit();
	sp_btf = NULL;
	sp_ti_owner = false;
	sp_ready = false;
	sp_caps = 0;
	sp_resolve = NULL;
	sp_state_addr = 0;
	memset(&sp_l, 0, sizeof(sp_l));
	memset(&sp_f, 0, sizeof(sp_f));
	memset(&sp_q, 0, sizeof(sp_q));
}

void *sepolicy_live_policy(void)
{
	if (!sp_ready)
		return NULL;
	return sp_live();
}

void *sepolicy_clone_policy(void)
{
	void *pol;

	if (!sp_ready)
		return NULL;
	pol = sp_dup_policy(sp_live());
	if (IS_ERR(pol))
		return NULL;
	return pol;
}

void sepolicy_free_policy(void *pol)
{
	if (!sp_ready)
		return;
	sp_destroy_policy(pol);
}

int sepolicy_snapshot(void)
{
	void *pol;

	if (!sp_ready)
		return -ENODATA;
	if (sp_work)
		return -EBUSY;

	pol = sp_dup_policy(sp_live());
	if (IS_ERR(pol))
		return PTR_ERR(pol);
	sp_work = pol;
	return 0;
}

int __nocfi sepolicy_commit(void)
{
	struct mutex *lock;
	void *state = (void *)sp_state_addr;
	void *old;

	if (!sp_ready)
		return -ENODATA;
	if (!sp_work)
		return -EINVAL;

	lock = (struct mutex *)((char *)state + sp_l.st_policy_mutex);
	mutex_lock(lock);
	old = sp_read_ptr(state, sp_l.st_policy);
	rcu_assign_pointer(*(void __rcu **)((char *)state + sp_l.st_policy),
			   sp_work);
	mutex_unlock(lock);
	synchronize_rcu();

	sp_work = NULL;
	sp_destroy_policy(old);

	sp_reset_avc();
	if (sp_f.policyload)
		sp_f.policyload(0);
	if (sp_f.status_policyload) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
		((void (*)(u32))sp_f.status_policyload)(0);
#else
		((void (*)(void *, u32))sp_f.status_policyload)(state, 0);
#endif
	}
	return 0;
}

void sepolicy_rollback(void)
{
	if (!sp_work)
		return;
	sp_destroy_policy(sp_work);
	sp_work = NULL;
}

void *sepolicy_work_db(void)
{
	if (!sp_work)
		return NULL;
	return (char *)sp_work + sp_l.sp_policydb;
}

int __nocfi sepolicy_add_allow(const char *s, const char *t, const char *c,
		       const char *p)
{
	if (!sp_work)
		return -EINVAL;
	return sp_add_rule(sepolicy_work_db(), s, t, c, p, SP_AVTAB_ALLOWED,
			   false);
}

int __nocfi sepolicy_del_allow(const char *s, const char *t, const char *c,
		       const char *p)
{
	if (!sp_work)
		return -EINVAL;
	return sp_add_rule(sepolicy_work_db(), s, t, c, p, SP_AVTAB_ALLOWED,
			   true);
}

int __nocfi sepolicy_add_auditallow(const char *s, const char *t, const char *c,
			    const char *p)
{
	if (!sp_work)
		return -EINVAL;
	return sp_add_rule(sepolicy_work_db(), s, t, c, p,
			   SP_AVTAB_AUDITALLOW, false);
}

int __nocfi sepolicy_add_dontaudit(const char *s, const char *t, const char *c,
			   const char *p)
{
	if (!sp_work)
		return -EINVAL;
	return sp_add_rule(sepolicy_work_db(), s, t, c, p, SP_AVTAB_AUDITDENY,
			   true);
}

int __nocfi sepolicy_add_xperm(const char *s, const char *t, const char *c,
		       const char *range)
{
	if (!sp_work)
		return -EINVAL;
	return sp_xperm_rule(sepolicy_work_db(), s, t, c, range,
			     SP_AVTAB_XPERMS_ALLOWED, false);
}

int __nocfi sepolicy_add_auditallowxperm(const char *s, const char *t,
				 const char *c, const char *range)
{
	if (!sp_work)
		return -EINVAL;
	return sp_xperm_rule(sepolicy_work_db(), s, t, c, range,
			     SP_AVTAB_XPERMS_AUDITALLOW, false);
}

int __nocfi sepolicy_add_dontauditxperm(const char *s, const char *t,
				const char *c, const char *range)
{
	if (!sp_work)
		return -EINVAL;
	return sp_xperm_rule(sepolicy_work_db(), s, t, c, range,
			     SP_AVTAB_XPERMS_DONTAUDIT, false);
}

int __nocfi sepolicy_del_xperm(const char *s, const char *t, const char *c,
		       const char *range)
{
	if (!sp_work)
		return -EINVAL;
	return sp_xperm_rule(sepolicy_work_db(), s, t, c, range,
			     SP_AVTAB_XPERMS_ALLOWED, true);
}

int __nocfi sepolicy_add_type(const char *name, bool attr)
{
	if (!sp_work || !name)
		return -EINVAL;
	return sp_add_type(sepolicy_work_db(), name, attr);
}

int __nocfi sepolicy_del_type(const char *name)
{
	if (!sp_work || !name)
		return -EINVAL;
	return sp_del_type(sepolicy_work_db(), name);
}

int __nocfi sepolicy_add_typeattribute(const char *type, const char *attr)
{
	if (!sp_work || !type || !attr)
		return -EINVAL;
	return sp_add_typeattribute(sepolicy_work_db(), type, attr);
}

int __nocfi sepolicy_del_typeattribute(const char *type, const char *attr)
{
	if (!sp_work || !type || !attr)
		return -EINVAL;
	return sp_del_typeattribute(sepolicy_work_db(), type, attr);
}

int __nocfi sepolicy_del_auditallow(const char *s, const char *t, const char *c,
			    const char *p)
{
	if (!sp_work)
		return -EINVAL;
	return sp_add_rule(sepolicy_work_db(), s, t, c, p,
			   SP_AVTAB_AUDITALLOW, true);
}

int __nocfi sepolicy_del_dontaudit(const char *s, const char *t, const char *c,
			   const char *p)
{
	if (!sp_work)
		return -EINVAL;
	return sp_add_rule(sepolicy_work_db(), s, t, c, p, SP_AVTAB_AUDITDENY,
			   false);
}

int __nocfi sepolicy_set_permissive(const char *type, bool permissive)
{
	if (!sp_work)
		return -EINVAL;
	return sp_set_permissive(sepolicy_work_db(), type, permissive);
}

int __nocfi sepolicy_type_transition(const char *s, const char *t, const char *c,
			     const char *def)
{
	if (!sp_work || !s || !t || !c || !def)
		return -EINVAL;
	return sp_type_rule(sepolicy_work_db(), s, t, c, def,
			    SP_AVTAB_TRANSITION);
}

int __nocfi sepolicy_type_change(const char *s, const char *t, const char *c,
			 const char *def)
{
	if (!sp_work || !s || !t || !c || !def)
		return -EINVAL;
	return sp_type_rule(sepolicy_work_db(), s, t, c, def, SP_AVTAB_CHANGE);
}

int __nocfi sepolicy_type_member(const char *s, const char *t, const char *c,
			 const char *def)
{
	if (!sp_work || !s || !t || !c || !def)
		return -EINVAL;
	return sp_type_rule(sepolicy_work_db(), s, t, c, def, SP_AVTAB_MEMBER);
}

int __nocfi sepolicy_filename_trans(const char *s, const char *t, const char *c,
			    const char *def, const char *name)
{
	if (!sp_work)
		return -EINVAL;
	return sp_filename_trans(sepolicy_work_db(), s, t, c, def, name);
}

int __nocfi sepolicy_apply_domain_rules(const char *domain, const char *file)
{
	if (!sp_work || !domain)
		return -EINVAL;
	return sp_apply_domain_rules(sepolicy_work_db(), domain, file);
}

bool sepolicy_type_exists(const char *type)
{
	if (!sp_work || !type)
		return false;
	return sp_sym_lookup(sepolicy_work_db(), SP_SYM_TYPES, type) != NULL;
}

bool sepolicy_query_ready(void)
{
	if (!(sp_caps & SEPOLICY_CAP_SID) ||
	    !(sp_caps & SEPOLICY_CAP_SID_TO_CTX) ||
	    !(sp_caps & SEPOLICY_CAP_AV))
		return false;
	return true;
}

u32 sepolicy_query_caps(void)
{
	return sp_caps;
}

void *sepolicy_backup_policy(void)
{
	return sp_backup_policy();
}

void sepolicy_free_backup_policy(void *pol)
{
	sp_free_backup_policy(pol);
}

int __nocfi sepolicy_policy_class_id(void *pol, const char *cls)
{
	void *cd;

	if (!sp_ready)
		return -ENODATA;
	if (!pol || !cls)
		return -EINVAL;
	cd = sp_sym_lookup(sp_db_of(pol), SP_SYM_CLASSES, cls);
	if (!cd)
		return -ENOENT;
	return sp_read_u32(cd, sp_l.cd_value);
}

int __nocfi sepolicy_policy_to_sid(void *pol, const char *scontext,
			   u32 scontext_len, u32 *sid)
{
	if (!sp_ready)
		return -ENODATA;
	return sp_policy_to_sid(pol, scontext, scontext_len, sid);
}

int __nocfi sepolicy_policy_sid_to_context(void *pol, u32 sid, char **scontext,
				   u32 *scontext_len)
{
	if (!sp_ready)
		return -ENODATA;
	return sp_policy_sid_to_context(pol, sid, scontext, scontext_len);
}

int __nocfi sepolicy_policy_av(void *pol, u32 ssid, u32 tsid, u16 tclass,
		       struct sepolicy_av_decision *avd)
{
	if (!sp_ready)
		return -ENODATA;
	return sp_policy_av(pol, ssid, tsid, tclass, avd);
}

bool __nocfi sepolicy_policy_has_perm(void *pol, u32 ssid, u32 tsid, u16 tclass,
			      u32 perm)
{
	if (!sp_ready)
		return false;
	return sp_policy_has_perm(pol, ssid, tsid, tclass, perm);
}
