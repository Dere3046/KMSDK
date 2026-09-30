// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
#include <linux/security.h>
#endif

#include "selinuxid.h"

#define SID_ZYGOTE_CONTEXT "u:r:zygote:s0"
#define SID_INIT_CONTEXT "u:r:init:s0"

#define SID_PER_USER_RANGE 100000
#define SID_FIRST_APPLICATION_UID 10000
#define SID_LAST_APPLICATION_UID 19999
#define SID_FIRST_ISOLATED_UID 99000
#define SID_LAST_ISOLATED_UID 99999

#define SID_SLOT_DOMAIN 0
#define SID_SLOT_FILE 1
#define SID_SLOT_ZYGOTE 2
#define SID_SLOT_INIT 3
#define SID_FIXED_SLOTS 4

#define SID_CACHE_SLOTS 16
#define SID_CONTEXT_MAX 64

/*
 * selinux_state opens with disabled then enforcing while
 * CONFIG_SECURITY_SELINUX_DISABLE exists, which covers 5.10 to 6.1, and with
 * enforcing alone from 6.6 on, checkreqprot and the policy tail moved between
 * releases and are never touched here.
 */
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
#define SID_STATE_OFF_DISABLED 0
#define SID_STATE_OFF_ENFORCING 1
#else
#define SID_STATE_OFF_ENFORCING 0
#endif

/*
 * task_security_struct up to 6.12 and cred_security_struct from 6.18 carry the
 * same six u32 in the same order, the 6.18 task_security_struct is a separate
 * avc cache in the task blob and is never touched here.
 */
struct sid_cred_security {
	u32 osid;
	u32 sid;
	u32 exec_sid;
	u32 create_sid;
	u32 keycreate_sid;
	u32 sockcreate_sid;
};

/*
 * inode_security_struct, its head is unchanged from 5.10 through 6.18.
 */
struct sid_inode_security {
	struct inode *inode;
	struct list_head list;
	u32 task_sid;
	u32 sid;
	u16 sclass;
	unsigned char initialized;
	spinlock_t lock;
};

struct sid_cache_entry {
	char context[SID_CONTEXT_MAX];
	u32 sid;
};

static struct sid_config sid_cfg;
static const char *sid_fixed_context[SID_FIXED_SLOTS];
static u32 sid_fixed_sid[SID_FIXED_SLOTS];
static struct sid_cache_entry sid_cache[SID_CACHE_SLOTS];
static unsigned int sid_cache_next;
static DEFINE_MUTEX(sid_lock);

static unsigned long sid_state_address;
static int sid_blob_cred;
static int sid_blob_inode;

/*
 * 6.14 replaced the context and length pair with struct lsm_context.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
static int (*sid_fn_secid_to_secctx)(u32 secid, char **secdata, u32 *seclen);
static void (*sid_fn_release_secctx)(char *secdata, u32 seclen);
#else
static int (*sid_fn_secid_to_secctx)(u32 secid, struct lsm_context *cp);
static void (*sid_fn_release_secctx)(struct lsm_context *cp);
#endif
static int (*sid_fn_secctx_to_secid)(const char *secdata, u32 seclen,
				     u32 *secid);

/*
 * The GKI export table keeps copy_from_kernel_nofault and drops
 * copy_to_kernel_nofault, both are resolved through the consumer callback like
 * every other symbol instead of being linked.
 */
static long (*sid_fn_read_nofault)(void *dst, const void *src, size_t size);
static long (*sid_fn_write_nofault)(void *dst, const void *src, size_t size);

static unsigned long __nocfi sid_resolve(const char *name)
{
	return sid_cfg.resolve(name);
}

static bool __nocfi sid_read_kernel(const void *address, void *buffer,
				    size_t size)
{
	if (!sid_fn_read_nofault) {
		return false;
	}
	return sid_fn_read_nofault(buffer, address, size) == 0;
}

static bool __nocfi sid_write_kernel(void *address, const void *buffer,
				     size_t size)
{
	if (!sid_fn_write_nofault) {
		return false;
	}
	return sid_fn_write_nofault(address, buffer, size) == 0;
}

static int __nocfi sid_call_secctx_to_secid(const char *secdata, u32 seclen,
					    u32 *secid)
{
	return sid_fn_secctx_to_secid(secdata, seclen, secid);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
static int __nocfi sid_call_secid_to_secctx(u32 secid, char **secdata,
					    u32 *seclen)
{
	return sid_fn_secid_to_secctx(secid, secdata, seclen);
}

static void __nocfi sid_call_release_secctx(char *secdata, u32 seclen)
{
	sid_fn_release_secctx(secdata, seclen);
}
#else
static int __nocfi sid_call_secid_to_secctx(u32 secid, struct lsm_context *cp)
{
	return sid_fn_secid_to_secctx(secid, cp);
}

static void __nocfi sid_call_release_secctx(struct lsm_context *cp)
{
	sid_fn_release_secctx(cp);
}
#endif

/*
 * Both blobs put the SELinux part at the offset selinux_blob_sizes reports,
 * the offset is read once at init because the table is __ro_after_init.
 */
static char *sid_cred_security(const struct cred *cred)
{
	if (!cred || !cred->security) {
		return NULL;
	}
	return (char *)cred->security + sid_blob_cred;
}

static char *sid_inode_security(const struct inode *inode)
{
	if (!inode || !inode->i_security) {
		return NULL;
	}
	return (char *)inode->i_security + sid_blob_inode;
}

static void sid_reset(void)
{
	memset(&sid_cfg, 0, sizeof(sid_cfg));
	memset(sid_fixed_context, 0, sizeof(sid_fixed_context));
	memset(sid_fixed_sid, 0, sizeof(sid_fixed_sid));
	memset(sid_cache, 0, sizeof(sid_cache));
	sid_cache_next = 0;
	sid_state_address = 0;
	sid_blob_cred = 0;
	sid_blob_inode = 0;
	sid_fn_secid_to_secctx = NULL;
	sid_fn_release_secctx = NULL;
	sid_fn_secctx_to_secid = NULL;
	sid_fn_read_nofault = NULL;
	sid_fn_write_nofault = NULL;
}

static int sid_lookup_policy(const char *context, u32 *sid)
{
	u32 value = 0;
	int error;

	error = sid_call_secctx_to_secid(context, strlen(context), &value);
	if (error) {
		return error;
	}
	if (!value) {
		return -ENOENT;
	}
	*sid = value;
	return 0;
}

int sid_init(const struct sid_config *config)
{
	unsigned long address;
	int blob[2];
	int error;

	if (!config || !config->resolve) {
		return -EINVAL;
	}
	if (sid_cfg.resolve) {
		return -EALREADY;
	}

	sid_cfg = *config;
	sid_fixed_context[SID_SLOT_DOMAIN] = config->domain_context;
	sid_fixed_context[SID_SLOT_FILE] = config->file_context;
	sid_fixed_context[SID_SLOT_ZYGOTE] = SID_ZYGOTE_CONTEXT;
	sid_fixed_context[SID_SLOT_INIT] = SID_INIT_CONTEXT;

	sid_fn_secctx_to_secid = (void *)sid_resolve("selinux_secctx_to_secid");
	sid_fn_secid_to_secctx = (void *)sid_resolve("selinux_secid_to_secctx");
	sid_fn_release_secctx = (void *)sid_resolve("selinux_release_secctx");
	sid_fn_read_nofault = (void *)sid_resolve("copy_from_kernel_nofault");
	sid_fn_write_nofault = (void *)sid_resolve("copy_to_kernel_nofault");
	address = sid_resolve("selinux_state");
	if (!sid_fn_secctx_to_secid || !sid_fn_secid_to_secctx ||
	    !sid_fn_release_secctx || !sid_fn_read_nofault ||
	    !sid_fn_write_nofault || !address) {
		sid_reset();
		return -ENOSYS;
	}
	sid_state_address = address;

	address = sid_resolve("selinux_blob_sizes");
	if (!address) {
		sid_reset();
		return -ENOSYS;
	}
	if (!sid_read_kernel((const void *)(address +
					     offsetof(struct lsm_blob_sizes,
						      lbs_cred)),
			     &blob[0], sizeof(blob[0])) ||
	    !sid_read_kernel((const void *)(address +
					     offsetof(struct lsm_blob_sizes,
						      lbs_inode)),
			     &blob[1], sizeof(blob[1]))) {
		sid_reset();
		return -EFAULT;
	}
	sid_blob_cred = blob[0];
	sid_blob_inode = blob[1];

	error = sid_cache_resync();
	if (error) {
		sid_reset();
		return error;
	}
	return 0;
}

void sid_exit(void)
{
	mutex_lock(&sid_lock);
	sid_reset();
	mutex_unlock(&sid_lock);
}

int sid_cache_resync(void)
{
	u32 value;
	int error;
	int i;

	if (!sid_cfg.resolve) {
		return -ENODEV;
	}

	mutex_lock(&sid_lock);
	memset(sid_cache, 0, sizeof(sid_cache));
	sid_cache_next = 0;
	for (i = 0; i < SID_FIXED_SLOTS; i++) {
		WRITE_ONCE(sid_fixed_sid[i], 0);
		if (!sid_fixed_context[i]) {
			continue;
		}
		error = sid_lookup_policy(sid_fixed_context[i], &value);
		if (error) {
			continue;
		}
		WRITE_ONCE(sid_fixed_sid[i], value);
	}
	mutex_unlock(&sid_lock);
	return 0;
}

int sid_of(const char *context, u32 *sid)
{
	size_t length;
	u32 value;
	int error;
	int i;

	if (!context || !sid) {
		return -EINVAL;
	}
	if (!sid_cfg.resolve) {
		return -ENODEV;
	}

	mutex_lock(&sid_lock);
	for (i = 0; i < SID_FIXED_SLOTS; i++) {
		if (!sid_fixed_context[i]) {
			continue;
		}
		if (strcmp(sid_fixed_context[i], context)) {
			continue;
		}
		value = READ_ONCE(sid_fixed_sid[i]);
		if (value) {
			*sid = value;
			mutex_unlock(&sid_lock);
			return 0;
		}
		error = sid_lookup_policy(context, &value);
		if (!error) {
			WRITE_ONCE(sid_fixed_sid[i], value);
			*sid = value;
		}
		mutex_unlock(&sid_lock);
		return error;
	}

	for (i = 0; i < SID_CACHE_SLOTS; i++) {
		if (!sid_cache[i].sid) {
			continue;
		}
		if (strcmp(sid_cache[i].context, context)) {
			continue;
		}
		*sid = sid_cache[i].sid;
		mutex_unlock(&sid_lock);
		return 0;
	}

	error = sid_lookup_policy(context, &value);
	if (error) {
		mutex_unlock(&sid_lock);
		return error;
	}
	*sid = value;

	length = strlen(context);
	if (length < SID_CONTEXT_MAX) {
		i = sid_cache_next;
		sid_cache_next = (sid_cache_next + 1) % SID_CACHE_SLOTS;
		memcpy(sid_cache[i].context, context, length + 1);
		sid_cache[i].sid = value;
	}
	mutex_unlock(&sid_lock);
	return 0;
}

int sid_to_context(u32 sid, char *buffer, size_t size)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
	char *context = NULL;
	u32 length = 0;
#else
	struct lsm_context lsm_ctx = { 0 };
	char *context;
	u32 length;
#endif
	int error;

	if (!buffer || !size) {
		return -EINVAL;
	}
	if (!sid_cfg.resolve) {
		return -ENODEV;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
	error = sid_call_secid_to_secctx(sid, &context, &length);
	if (error) {
		return error;
	}
#else
	error = sid_call_secid_to_secctx(sid, &lsm_ctx);
	if (error < 0) {
		return error;
	}
	context = lsm_ctx.context;
	length = lsm_ctx.len;
#endif

	if (!context) {
		return -ENOENT;
	}
	if ((size_t)length + 1 > size) {
		error = -ENAMETOOLONG;
	} else {
		memcpy(buffer, context, length);
		buffer[length] = '\0';
		error = 0;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
	sid_call_release_secctx(context, length);
#else
	sid_call_release_secctx(&lsm_ctx);
#endif
	return error;
}

u32 sid_cred_sid(const struct cred *cred)
{
	char *base = sid_cred_security(cred);
	u32 sid = 0;

	if (!base) {
		return 0;
	}
	if (!sid_read_kernel(base + offsetof(struct sid_cred_security, sid), &sid,
			     sizeof(sid))) {
		return 0;
	}
	return sid;
}

u32 sid_current_sid(void)
{
	return sid_cred_sid(current_cred());
}

bool sid_cred_is_sid(const struct cred *cred, u32 sid)
{
	u32 value;

	if (!sid) {
		return false;
	}
	value = sid_cred_sid(cred);
	return value && value == sid;
}

bool sid_current_is_sid(u32 sid)
{
	return sid_cred_is_sid(current_cred(), sid);
}

bool sid_cred_is(const struct cred *cred, const char *context)
{
	u32 sid;

	if (sid_of(context, &sid)) {
		return false;
	}
	return sid_cred_is_sid(cred, sid);
}

bool sid_current_is(const char *context)
{
	return sid_cred_is(current_cred(), context);
}

int sid_cred_set_sid(struct cred *cred, u32 sid, bool clear_exec)
{
	u32 zero = 0;
	char *base;

	if (!cred || !sid) {
		return -EINVAL;
	}
	if (!sid_cfg.resolve) {
		return -ENODEV;
	}
	base = sid_cred_security(cred);
	if (!base) {
		return -ENODATA;
	}

	if (!sid_write_kernel(base + offsetof(struct sid_cred_security, sid), &sid,
			      sizeof(sid)) ||
	    !sid_write_kernel(
		    base + offsetof(struct sid_cred_security, create_sid), &zero,
		    sizeof(zero)) ||
	    !sid_write_kernel(
		    base + offsetof(struct sid_cred_security, keycreate_sid),
		    &zero, sizeof(zero)) ||
	    !sid_write_kernel(
		    base + offsetof(struct sid_cred_security, sockcreate_sid),
		    &zero, sizeof(zero))) {
		return -EFAULT;
	}
	if (clear_exec) {
		if (!sid_write_kernel(
			    base + offsetof(struct sid_cred_security, exec_sid),
			    &zero, sizeof(zero))) {
			return -EFAULT;
		}
	}
	return 0;
}

int sid_cred_set_domain(struct cred *cred, const char *context, bool clear_exec)
{
	u32 sid;
	int error;

	error = sid_of(context, &sid);
	if (error) {
		return error;
	}
	return sid_cred_set_sid(cred, sid, clear_exec);
}

static bool sid_fixed_matches(const struct cred *cred, unsigned int slot)
{
	u32 sid = READ_ONCE(sid_fixed_sid[slot]);

	if (!sid) {
		return false;
	}
	return sid_cred_is_sid(cred, sid);
}

bool sid_is_own_domain(const struct cred *cred)
{
	return sid_fixed_matches(cred, SID_SLOT_DOMAIN);
}

bool sid_is_zygote(const struct cred *cred)
{
	return sid_fixed_matches(cred, SID_SLOT_ZYGOTE);
}

bool sid_is_init(const struct cred *cred)
{
	return sid_fixed_matches(cred, SID_SLOT_INIT);
}

bool sid_is_appuid(uid_t uid)
{
	uid_t appid = uid % SID_PER_USER_RANGE;

	return appid >= SID_FIRST_APPLICATION_UID &&
	       appid <= SID_LAST_APPLICATION_UID;
}

bool sid_is_isolated(uid_t uid)
{
	uid_t appid = uid % SID_PER_USER_RANGE;

	return appid >= SID_FIRST_ISOLATED_UID && appid <= SID_LAST_ISOLATED_UID;
}

u32 sid_inode_sid(const struct inode *inode)
{
	char *base = sid_inode_security(inode);
	u32 sid = 0;

	if (!base) {
		return 0;
	}
	if (!sid_read_kernel(base + offsetof(struct sid_inode_security, sid),
			     &sid, sizeof(sid))) {
		return 0;
	}
	return sid;
}

int sid_inode_set_sid(struct inode *inode, u32 sid)
{
	char *base;

	if (!inode || !sid) {
		return -EINVAL;
	}
	if (!sid_cfg.resolve) {
		return -ENODEV;
	}
	base = sid_inode_security(inode);
	if (!base) {
		return -ENODATA;
	}
	if (!sid_write_kernel(base + offsetof(struct sid_inode_security, sid),
			      &sid, sizeof(sid))) {
		return -EFAULT;
	}
	return 0;
}

int sid_inode_set_domain(struct inode *inode, const char *context)
{
	u32 sid;
	int error;

	error = sid_of(context, &sid);
	if (error) {
		return error;
	}
	return sid_inode_set_sid(inode, sid);
}

int sid_inode_set_file(struct inode *inode)
{
	u32 sid = READ_ONCE(sid_fixed_sid[SID_SLOT_FILE]);

	if (!sid) {
		return -ENOENT;
	}
	return sid_inode_set_sid(inode, sid);
}

bool sid_enforcing_get(void)
{
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
	u8 value = 0;

	if (!sid_state_address) {
		return false;
	}
	if (!sid_read_kernel((const void *)(sid_state_address +
					     SID_STATE_OFF_ENFORCING),
			     &value, sizeof(value))) {
		return false;
	}
	return value != 0;
#else
	return true;
#endif
}

void sid_enforcing_set(bool enforce)
{
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
	u8 value = enforce ? 1 : 0;

	if (!sid_state_address) {
		return;
	}
	sid_write_kernel((void *)(sid_state_address + SID_STATE_OFF_ENFORCING),
			 &value, sizeof(value));
#else
	(void)enforce;
#endif
}

bool sid_disabled_get(void)
{
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
	u8 value = 0;

	if (!sid_state_address) {
		return false;
	}
	if (!sid_read_kernel((const void *)(sid_state_address +
					     SID_STATE_OFF_DISABLED),
			     &value, sizeof(value))) {
		return false;
	}
	return value != 0;
#else
	return false;
#endif
}

void sid_disabled_set(bool disabled)
{
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
	u8 value = disabled ? 1 : 0;

	if (!sid_state_address) {
		return;
	}
	sid_write_kernel((void *)(sid_state_address + SID_STATE_OFF_DISABLED),
			 &value, sizeof(value));
#else
	(void)disabled;
#endif
}

void *sid_state(void)
{
	return (void *)sid_state_address;
}
