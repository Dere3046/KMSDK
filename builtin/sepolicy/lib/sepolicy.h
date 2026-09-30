// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef SEPOLICY_H
#define SEPOLICY_H

#include <linux/types.h>

/*
 * Mechanism only: a policy copy plus rule primitives, the rule set is the
 * consumer choice. Every primitive works on the snapshot copy, commit swaps
 * the pointer. Layout comes from kernel BTF, init returns -ENODATA without it.
 */

int sepolicy_init(unsigned long (*resolve)(const char *name));
void sepolicy_exit(void);

int sepolicy_snapshot(void);
int sepolicy_commit(void);
void sepolicy_rollback(void);
void *sepolicy_work_db(void);

void *sepolicy_clone_policy(void);
void sepolicy_free_policy(void *pol);
void *sepolicy_live_policy(void);

/*
 * Rule primitives, all of them need a snapshot. A NULL source, target or class
 * expands over every entry of that symbol table, a NULL permission over the
 * whole class. Return values: 0 on success, -EINVAL without a snapshot or with
 * a NULL permission and no class, -ENOENT when a named symbol or permission is
 * absent, -ENOMEM when a node or a table could not grow.
 */
int sepolicy_add_allow(const char *s, const char *t, const char *c,
		       const char *p);
int sepolicy_del_allow(const char *s, const char *t, const char *c,
		       const char *p);
int sepolicy_add_auditallow(const char *s, const char *t, const char *c,
			    const char *p);
int sepolicy_del_auditallow(const char *s, const char *t, const char *c,
			    const char *p);
int sepolicy_add_dontaudit(const char *s, const char *t, const char *c,
			   const char *p);
int sepolicy_del_dontaudit(const char *s, const char *t, const char *c,
			   const char *p);
int sepolicy_add_xperm(const char *s, const char *t, const char *c,
		       const char *range);
int sepolicy_add_auditallowxperm(const char *s, const char *t, const char *c,
				 const char *range);
int sepolicy_add_dontauditxperm(const char *s, const char *t, const char *c,
				const char *range);
int sepolicy_del_xperm(const char *s, const char *t, const char *c,
		       const char *range);
int sepolicy_add_type(const char *name, bool attr);
int sepolicy_del_type(const char *name);
int sepolicy_add_typeattribute(const char *type, const char *attr);
int sepolicy_del_typeattribute(const char *type, const char *attr);
int sepolicy_set_permissive(const char *type, bool permissive);
int sepolicy_type_transition(const char *s, const char *t, const char *c,
			     const char *def);
int sepolicy_type_change(const char *s, const char *t, const char *c,
			 const char *def);
int sepolicy_type_member(const char *s, const char *t, const char *c,
			 const char *def);
bool sepolicy_type_exists(const char *type);

/*
 * filename_trans: a type transition selected by the object name, all five
 * arguments are required. Needs a policy whose filename transition table
 * already holds entries, since the hash generation of the running kernel is
 * read off them; an empty table returns -ENODATA instead of a wrong bucket.
 */
int sepolicy_filename_trans(const char *s, const char *t, const char *c,
			    const char *def, const char *name);

/*
 * genfscon is not supported: it labels a whole mount point through the
 * ocontext list and the sidtab, which is outside the rule primitives here.
 */

/*
 * Optional companion rule set, the KernelSU shape: the domain gets all
 * permissions, an unconstrained file type when file is not NULL, the ioctl
 * xperm set, the init allow and the servicemanager, logd, hwservicemanager,
 * binder and system_server companion allows. The caller decides when to apply
 * it, nothing calls it on its own. A permissive domain is a separate
 * sepolicy_set_permissive call. Returns 0 on success, -EINVAL without a
 * snapshot or without a domain name, -ENOENT when the domain or its required
 * attribute is missing from the policy.
 */
int sepolicy_apply_domain_rules(const char *domain, const char *file);

/*
 * Backup policy queries. What a consumer needs to answer selinuxfs context and
 * access reads from a policy that is no longer the live one is three
 * primitives, string to SID, SID to string and a SID triple to an access
 * vector; the SELinux math behind them is not reimplemented, init resolves the
 * kernel own functions and only fills the gaps that inlining leaves.
 */
struct sepolicy_av_decision {
	u32 allowed;
	u32 auditallow;
	u32 auditdeny;
	u32 seqno;
	u32 flags;
};

#define SEPOLICY_AV_FLAG_PERMISSIVE 0x0001

/* one bit per query primitive, for diagnostics and self tests */
#define SEPOLICY_CAP_SID 0x00000001
#define SEPOLICY_CAP_SID_TO_CTX 0x00000002
#define SEPOLICY_CAP_AV 0x00000004
#define SEPOLICY_CAP_BACKUP 0x00000008
#define SEPOLICY_CAP_FILENAME_TRANS 0x00000010
#define SEPOLICY_CAP_DEL_TYPE 0x00000020

/*
 * True when the string to SID, SID to string and access vector primitives are
 * all available on this kernel. A false answer does not disable the rule path.
 */
bool sepolicy_query_ready(void);

/*
 * The capability bits this kernel passed, same values as the SEPOLICY_CAP_*
 * defines. A missing bit makes the matching primitive answer -ENODATA.
 */
u32 sepolicy_query_caps(void);

/*
 * A copy of the live policy with a private sidtab holding the initial SIDs,
 * further contexts are inserted on demand. It survives a later commit, unlike
 * sepolicy_clone_policy, whose sidtab belongs to the policy it came from.
 * Returns NULL without a live policy or when the sidtab symbols are missing.
 * Release it with sepolicy_free_backup_policy before sepolicy_exit.
 */
void *sepolicy_backup_policy(void);
void sepolicy_free_backup_policy(void *pol);

/*
 * Class name to class value, for callers that build a query from names.
 * Returns the value (1 based), -EINVAL or -ENOENT.
 */
int sepolicy_policy_class_id(void *pol, const char *cls);

/*
 * Context string to SID, a length of 0 means strlen. The policy sidtab is
 * written to, so the same context maps to the same SID afterwards. Returns 0,
 * -EINVAL for an unparsable or invalid context, -ENODATA when the query
 * symbols or the layout are missing, -ENOMEM, or the sidtab error (-ESTALE on
 * a frozen sidtab).
 */
int sepolicy_policy_to_sid(void *pol, const char *scontext, u32 scontext_len,
			   u32 *sid);

/*
 * SID to its canonical context string, the caller kfree()s it. scontext_len
 * counts the terminating NUL, the same convention as context_struct_to_string.
 * Returns 0, -EINVAL for an unknown SID, -ENODATA, -ENOMEM.
 */
int sepolicy_policy_sid_to_context(void *pol, u32 sid, char **scontext,
				   u32 *scontext_len);

/*
 * Access vector for a SID triple, the permissive flag of the source type is
 * reported in flags and tclass must not be 0. Returns 0, -EINVAL for an
 * unknown SID or an invalid class, -ENODATA when the kernel neither exposes
 * context_struct_compute_av nor the pieces to recompose it, or when the policy
 * carries type bounds and the bounds pass is not available.
 */
int sepolicy_policy_av(void *pol, u32 ssid, u32 tsid, u16 tclass,
		       struct sepolicy_av_decision *avd);

/*
 * Single permission test over the same access vector: a permissive source type
 * answers true. False also covers every error, use sepolicy_policy_av when the
 * reason matters.
 */
bool sepolicy_policy_has_perm(void *pol, u32 ssid, u32 tsid, u16 tclass,
			      u32 perm);

#endif
