// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#include "core.h"
#include "type_info.h"
#include "hk_lsm.h"
#include "hk_ptr.h"
#include "sepolicy.h"
#include "selinuxhide.h"

#define SLH_SCAN_SLOTS 32

/* BTF kind is a uapi ABI constant, kept local to avoid the bpf_prog
 * visibility warning of linux/btf.h on 5.10 and the enum redefinition
 * in the type_info btf.h
 */
#define SLH_BTF_KIND_STRUCT 4

/* flask.h and av_permissions.h values, part of the compiled policy ABI and
 * identical on every kernel version
 */
#define SLH_SECCLASS_PROCESS 2
#define SLH_PROCESS_SETCURRENT 0x01000000U

static struct slh_cfg slh_cfg;
static struct ti_ctx *slh_btf;
static bool slh_ti_owner;
static bool slh_ready;
static bool slh_on;

static void *slh_alt;
static bool slh_alt_owned;

static unsigned long slh_state_addr;
static unsigned long slh_write_op_addr;
static unsigned long slh_addr_write_context;
static unsigned long slh_addr_write_access;
static unsigned long slh_status_ops_addr;
static unsigned long slh_addr_open_status;

static void *slh_fn_avc_has_perm;
static void *slh_fn_cred_getsecid;
static void *slh_fn_context_to_sid;
static void *slh_fn_str_to_sid;
static void *slh_fn_sid_to_context;
static void *slh_fn_compute_av;

static bool slh_direct;

static long slh_off_policy;
static long slh_off_policy_mutex;

/* Fallback for kernels where sepolicy cannot answer for the alternate policy:
 * the global pointer carries it for the whole call sequence, which concurrent
 * readers on other CPUs observe. Only reached when slh_direct is false.
 */
static unsigned long slh_read_ptr(void *base, long off)
{
	void *v;

	memcpy(&v, (char *)base + off, sizeof(v));
	return (unsigned long)v;
}

static void slh_policy_set(unsigned long pol)
{
	void __rcu **slot = (void __rcu **)((char *)slh_state_addr +
					    slh_off_policy);

	rcu_assign_pointer(*slot, (void *)pol);
}

static void slh_swap_in(unsigned long *old)
{
	struct mutex *lock =
		(struct mutex *)((char *)slh_state_addr + slh_off_policy_mutex);

	mutex_lock(lock);
	*old = slh_read_ptr((void *)slh_state_addr, slh_off_policy);
	slh_policy_set((unsigned long)slh_alt);
}

static void slh_swap_out(unsigned long old)
{
	struct mutex *lock =
		(struct mutex *)((char *)slh_state_addr + slh_off_policy_mutex);

	slh_policy_set(old);
	mutex_unlock(lock);
}

static void **slh_slot_context;
static void **slh_slot_access;
static void **slh_slot_status;
static struct page *slh_status_page;

static ssize_t (*slh_orig_write_context)(struct file *file, char *buf,
					 size_t size);
static ssize_t (*slh_orig_write_access)(struct file *file, char *buf,
					size_t size);
static int (*slh_orig_status_open)(struct inode *inode, struct file *filp);

static struct hk_lsm_hook slh_hook;
static struct hk_lsm_layout slh_lsm_layout;

static bool slh_hidden(void)
{
	if (!slh_cfg.should_hide)
		return false;
	return slh_cfg.should_hide(current_uid().val, slh_cfg.priv);
}

static bool slh_swap_ready(void)
{
	return slh_fn_context_to_sid && slh_fn_str_to_sid &&
	       slh_fn_sid_to_context && slh_fn_compute_av;
}

static bool slh_answer_ready(void)
{
	return slh_alt != NULL && (slh_direct || slh_swap_ready());
}

/* hidden readers skip the avc check, should_hide decides who gets an answer */
static ssize_t __nocfi slh_write_context(struct file *file, char *buf,
					 size_t size)
{
	char *canon = NULL;
	u32 sid = 0;
	u32 len = 0;
	int ret;

	if (!slh_hidden() || !slh_answer_ready()) {
		if (slh_orig_write_context)
			return slh_orig_write_context(file, buf, size);
		return -EINVAL;
	}

	if (slh_direct) {
		ret = sepolicy_policy_to_sid(slh_alt, buf, size, &sid);
		if (!ret)
			ret = sepolicy_policy_sid_to_context(slh_alt, sid,
							     &canon, &len);
	} else {
		unsigned long old;

		slh_swap_in(&old);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
		ret = ((int (*)(const char *, u32, u32 *, gfp_t))
			       slh_fn_context_to_sid)(buf, size, &sid,
						      GFP_KERNEL);
		if (!ret)
			ret = ((int (*)(u32, char **, u32 *))
				       slh_fn_sid_to_context)(sid, &canon,
							      &len);
#else
		ret = ((int (*)(void *, const char *, u32, u32 *, gfp_t))
			       slh_fn_context_to_sid)((void *)slh_state_addr,
						      buf, size, &sid,
						      GFP_KERNEL);
		if (!ret)
			ret = ((int (*)(void *, u32, char **, u32 *))
				       slh_fn_sid_to_context)(
				(void *)slh_state_addr, sid, &canon, &len);
#endif
		slh_swap_out(old);
	}

	if (ret)
		return ret;
	if (len > PAGE_SIZE) {
		kfree(canon);
		return -ERANGE;
	}

	memcpy(buf, canon, len);
	kfree(canon);
	return len;
}

static ssize_t __nocfi slh_write_access(struct file *file, char *buf,
					size_t size)
{
	struct sepolicy_av_decision avd;
	char *scon = NULL;
	char *tcon = NULL;
	u32 ssid = 0;
	u32 tsid = 0;
	u16 tclass = 0;
	ssize_t ret;

	if (!slh_hidden() || !slh_answer_ready()) {
		if (slh_orig_write_access)
			return slh_orig_write_access(file, buf, size);
		return -EINVAL;
	}

	scon = kzalloc(size + 1, GFP_KERNEL);
	tcon = kzalloc(size + 1, GFP_KERNEL);
	if (!scon || !tcon) {
		ret = -ENOMEM;
		goto out;
	}

	ret = -EINVAL;
	if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
		goto out;

	memset(&avd, 0, sizeof(avd));
	if (slh_direct) {
		ret = sepolicy_policy_to_sid(slh_alt, scon, 0, &ssid);
		if (!ret)
			ret = sepolicy_policy_to_sid(slh_alt, tcon, 0, &tsid);
		if (!ret)
			ret = sepolicy_policy_av(slh_alt, ssid, tsid, tclass,
						 &avd);
	} else {
		unsigned long old;

		slh_swap_in(&old);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
		ret = ((int (*)(const char *, u32 *, gfp_t))
			       slh_fn_str_to_sid)(scon, &ssid, GFP_KERNEL);
		if (!ret)
			ret = ((int (*)(const char *, u32 *, gfp_t))
				       slh_fn_str_to_sid)(tcon, &tsid,
							  GFP_KERNEL);
		if (!ret)
			((void (*)(u32, u32, u16,
				   struct sepolicy_av_decision *))
				 slh_fn_compute_av)(ssid, tsid, tclass, &avd);
#else
		ret = ((int (*)(void *, const char *, u32 *, gfp_t))
			       slh_fn_str_to_sid)((void *)slh_state_addr, scon,
						  &ssid, GFP_KERNEL);
		if (!ret)
			ret = ((int (*)(void *, const char *, u32 *, gfp_t))
				       slh_fn_str_to_sid)(
				(void *)slh_state_addr, tcon, &tsid,
				GFP_KERNEL);
		if (!ret)
			((void (*)(void *, u32, u32, u16,
				   struct sepolicy_av_decision *))
				 slh_fn_compute_av)((void *)slh_state_addr,
						    ssid, tsid, tclass, &avd);
#endif
		slh_swap_out(old);
	}

	if (ret)
		goto out;

	ret = scnprintf(buf, PAGE_SIZE, "%x %x %x %x %u %x", avd.allowed,
			0xffffffff, avd.auditallow, avd.auditdeny, avd.seqno,
			avd.flags);
out:
	kfree(tcon);
	kfree(scon);
	return ret;
}

static int __nocfi slh_open_status(struct inode *inode, struct file *filp)
{
	if (!slh_hidden() || !slh_cfg.fill_status) {
		if (slh_orig_status_open)
			return slh_orig_status_open(inode, filp);
		return -EINVAL;
	}

	if (!slh_status_page) {
		slh_status_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!slh_status_page)
			return -ENOMEM;
		slh_cfg.fill_status(page_address(slh_status_page),
				    slh_cfg.priv);
	}

	filp->private_data = slh_status_page;
	return 0;
}

static int __nocfi slh_call_original(const char *name, void *value, size_t size)
{
	if (slh_hook.original)
		return ((int (*)(const char *, void *, size_t))
				slh_hook.original)(name, value, size);
	return -EACCES;
}

static int __nocfi slh_check_setcurrent(void)
{
	u32 mysid = 0;
	int ret;

	if (!slh_fn_cred_getsecid || !slh_fn_avc_has_perm)
		return 0;

	((void (*)(const struct cred *, u32 *))slh_fn_cred_getsecid)(
		current_cred(), &mysid);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	ret = ((int (*)(u32, u32, u16, u32, void *))slh_fn_avc_has_perm)(
		mysid, mysid, SLH_SECCLASS_PROCESS, SLH_PROCESS_SETCURRENT, NULL);
#else
	ret = ((int (*)(void *, u32, u32, u16, u32, void *))
		       slh_fn_avc_has_perm)((void *)slh_state_addr, mysid, mysid,
					    SLH_SECCLASS_PROCESS,
					    SLH_PROCESS_SETCURRENT, NULL);
#endif
	return ret;
}

/* the request is checked against the alternate policy, the migration stays
 * with the original hook so the domain really changes
 */
static int __nocfi slh_setprocattr(const char *name, void *value, size_t size)
{
	char *str = value;
	u32 sid = 0;
	int ret;

	if (!slh_hidden() || !name || strcmp(name, "current"))
		return slh_call_original(name, value, size);

	ret = slh_check_setcurrent();
	if (ret)
		return ret;

	if (size && str[0] && str[0] != '\n' && slh_alt &&
	    sepolicy_query_ready()) {
		if (str[size - 1] == '\n') {
			str[size - 1] = 0;
			size--;
		}
		ret = sepolicy_policy_to_sid(slh_alt, str, size, &sid);
		if (ret)
			return ret;
	}

	return slh_call_original(name, value, size);
}

static void **slh_find_slot(unsigned long array, unsigned long target)
{
	int i;

	if (!array || !target)
		return NULL;

	for (i = 0; i < SLH_SCAN_SLOTS; i++) {
		unsigned long v;
		void *p = (void *)(array + i * sizeof(void *));

		if (safe_read(&v, p, sizeof(v)))
			return NULL;
		if (v == target)
			return (void **)p;
	}
	return NULL;
}

static int slh_layout_load(void)
{
	u32 id;
	u32 bit_off, bit_sz;

	slh_off_policy = -1;
	slh_off_policy_mutex = -1;

	if (ti_type_by_name(slh_btf, "selinux_state",
			    BIT(SLH_BTF_KIND_STRUCT), &id))
		return -ENODATA;
	if (ti_member_off(slh_btf, id, "policy", &bit_off, &bit_sz))
		return -ENODATA;
	slh_off_policy = bit_off / 8;
	if (ti_member_off(slh_btf, id, "policy_mutex", &bit_off, &bit_sz))
		return -ENODATA;
	slh_off_policy_mutex = bit_off / 8;
	return 0;
}

static int slh_type_by_name(const char *name, u32 *id)
{
	return ti_type_by_name(slh_btf, name, BIT(SLH_BTF_KIND_STRUCT), id);
}

static int slh_member_off(u32 id, const char *member, u32 *bit_off,
			  u32 *bit_sz)
{
	return ti_member_off(slh_btf, id, member, bit_off, bit_sz);
}

static u32 slh_type_size(u32 id)
{
	return ti_type_size(slh_btf, id);
}

static unsigned long __nocfi slh_resolve(const char *name)
{
	return slh_cfg.resolve(name);
}

static void slh_alt_setup(unsigned long (*resolve)(const char *name))
{
	/* init is idempotent, the consumer may own sepolicy already */
	if (!sepolicy_live_policy())
		sepolicy_init(resolve);

	slh_alt = slh_cfg.alt_policy;
	if (!slh_alt) {
		slh_alt = sepolicy_backup_policy();
		if (slh_alt)
			slh_alt_owned = true;
	}

	slh_direct = slh_alt != NULL && sepolicy_query_ready();
}

int __nocfi selinuxhide_init(const struct slh_cfg *cfg)
{
	struct ti_resolver res;
	int ret;

	if (!cfg || !cfg->resolve || !cfg->should_hide)
		return -EINVAL;

	slh_cfg = *cfg;
	res.name_to_addr = cfg->resolve;
	if (!ti_ready()) {
		ret = ti_init(&res);
		if (ret)
			return ret;
		slh_ti_owner = true;
	}
	slh_btf = ti_base();
	if (!slh_btf)
		return -ENODATA;

	ret = slh_layout_load();
	if (ret) {
		pr_info("[selinuxhide] layout unavailable: %d\n", ret);
		return ret;
	}

	slh_state_addr = cfg->resolve("selinux_state");
	slh_write_op_addr = cfg->resolve("write_op");
	slh_addr_write_context = cfg->resolve("sel_write_context");
	slh_addr_write_access = cfg->resolve("sel_write_access");
	slh_status_ops_addr = cfg->resolve("sel_handle_status_ops");
	slh_addr_open_status = cfg->resolve("sel_open_handle_status");

	slh_fn_avc_has_perm = (void *)cfg->resolve("avc_has_perm");
	slh_fn_cred_getsecid = (void *)cfg->resolve("security_cred_getsecid");
	slh_fn_context_to_sid = (void *)cfg->resolve("security_context_to_sid");
	slh_fn_str_to_sid = (void *)cfg->resolve("security_context_str_to_sid");
	slh_fn_sid_to_context = (void *)cfg->resolve("security_sid_to_context");
	slh_fn_compute_av = (void *)cfg->resolve("security_compute_av_user");

	if (!slh_state_addr || !slh_status_ops_addr || !slh_addr_open_status)
		return -ENODATA;

	slh_alt_setup(cfg->resolve);
	if (!slh_alt)
		pr_info("[selinuxhide] alternate policy unavailable\n");
	else if (!slh_answer_ready())
		pr_info("[selinuxhide] context/access answers unavailable\n");
	else if (!slh_direct)
		pr_info("[selinuxhide] answers through the policy swap\n");
	if (!slh_write_op_addr || !slh_addr_write_context ||
	    !slh_addr_write_access)
		pr_info("[selinuxhide] write slots unavailable\n");

	slh_lsm_layout.resolve = slh_resolve;
	slh_lsm_layout.type_by_name = slh_type_by_name;
	slh_lsm_layout.member_off = slh_member_off;
	slh_lsm_layout.type_size = slh_type_size;
	ret = hk_lsm_init(&slh_lsm_layout);
	if (ret)
		return ret;
	slh_hook = (struct hk_lsm_hook)HK_LSM_HOOK_INIT(
		setprocattr, "selinux_setprocattr", slh_setprocattr, 0);

	slh_ready = true;
	return 0;
}

void selinuxhide_exit(void)
{
	selinuxhide_stop();
	hk_lsm_exit();
	if (slh_status_page) {
		__free_page(slh_status_page);
		slh_status_page = NULL;
	}
	if (slh_alt_owned)
		sepolicy_free_backup_policy(slh_alt);
	slh_alt = NULL;
	slh_alt_owned = false;
	if (slh_ti_owner)
		ti_exit();
	slh_btf = NULL;
	slh_ti_owner = false;
	slh_ready = false;
	memset(&slh_cfg, 0, sizeof(slh_cfg));
}

int selinuxhide_start(void)
{
	if (!slh_ready)
		return -ENODATA;
	if (slh_on)
		return 0;

	if (slh_answer_ready()) {
		slh_slot_context = slh_find_slot(slh_write_op_addr,
						 slh_addr_write_context);
		if (slh_slot_context)
			hk_ptr_hook(slh_slot_context, (void *)slh_write_context,
				    (void **)&slh_orig_write_context);
		slh_slot_access = slh_find_slot(slh_write_op_addr,
						slh_addr_write_access);
		if (slh_slot_access)
			hk_ptr_hook(slh_slot_access, (void *)slh_write_access,
				    (void **)&slh_orig_write_access);
	}

	slh_slot_status = slh_find_slot(slh_status_ops_addr,
					slh_addr_open_status);
	if (slh_slot_status)
		hk_ptr_hook(slh_slot_status, (void *)slh_open_status,
			    (void **)&slh_orig_status_open);

	if (hk_lsm_hook(&slh_hook))
		pr_info("[selinuxhide] setprocattr hook failed\n");

	slh_on = true;
	return 0;
}

void selinuxhide_stop(void)
{
	if (!slh_on)
		return;

	if (slh_slot_status)
		hk_ptr_unhook(slh_slot_status);
	if (slh_slot_access)
		hk_ptr_unhook(slh_slot_access);
	if (slh_slot_context)
		hk_ptr_unhook(slh_slot_context);
	hk_lsm_unhook(&slh_hook);

	slh_slot_status = NULL;
	slh_slot_access = NULL;
	slh_slot_context = NULL;
	slh_on = false;
}
