// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/ptrace.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/unistd.h>

#include "sc.h"
#include "execshim.h"

/* filp_open lives in a VFS namespace on GKI, 6.13 and later want a literal */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

#define EXS_PATH_MAX 256
#define EXS_KEY_MAX 32
#define EXS_ENV_MAX 128
#define EXS_ENV_ADD_MAX 32
#define EXS_STACK_ALIGN 8
#define EXS_NR_COUNT 4

/* arm64 syscall arguments are regs[0..5], regs[8] keeps the original nr */
#define EXS_PARM1(r) ((r)->regs[0])
#define EXS_PARM2(r) ((r)->regs[1])
#define EXS_PARM3(r) ((r)->regs[2])
#define EXS_PARM4(r) ((r)->regs[3])
#define EXS_PARM5(r) ((r)->regs[4])

#ifndef CONFIG_ARM64
#define EXS_UNSUPPORTED 1
#else
#ifndef CONFIG_KERNSC_TP
#define EXS_UNSUPPORTED 1
#endif
#endif

static struct exs_cfg exs_cfg;
static bool exs_ready;

int exs_init(const struct exs_cfg *cfg)
{
	if (!cfg)
		return -EINVAL;
	if (!cfg->map_path && !cfg->env_add && !cfg->path_filter)
		return -EINVAL;
	if (exs_ready)
		return -EALREADY;

	exs_cfg = *cfg;
	exs_ready = true;
	return 0;
}

void exs_exit(void)
{
	exs_stop();
	memset(&exs_cfg, 0, sizeof(exs_cfg));
	exs_ready = false;
}

#ifdef EXS_UNSUPPORTED

int exs_start(void)
{
	return -ENOTSUPP;
}

void exs_stop(void)
{
}

#else

struct exs_stack {
	unsigned long addr;
};

static bool exs_on;

/*
 * stage bytes below the user stack pointer, sp itself is not moved and the
 * copies only live for this syscall
 * the cursor starts 16 byte aligned, every item is 8 byte aligned
 * a failed write means the stack area was not mapped, the caller then
 * falls back to the original syscall
 */
static void exs_stack_init(struct exs_stack *st)
{
	st->addr = ALIGN_DOWN(untagged_addr(current_user_stack_pointer()), 16);
}

static void __user *exs_stack_put(struct exs_stack *st, const void *src,
				  size_t len)
{
	st->addr = ALIGN_DOWN(st->addr - len, EXS_STACK_ALIGN);
	if (copy_to_user((void __user *)st->addr, src, len))
		return NULL;
	return (void __user *)st->addr;
}

/*
 * read a user path into a kernel buffer, unreadable or too long returns a
 * negative value
 * strncpy_from_user returns the length without the trailing NUL and returns
 * the count when the string does not fit
 * the nofault twin is not exported on GKI, referencing it directly makes
 * modpost report an undefined symbol
 */
static int exs_read_path(unsigned long path_user, char *buf)
{
	long ret;

	memset(buf, 0, EXS_PATH_MAX);
	ret = strncpy_from_user(buf,
				(const char __user *)untagged_addr(path_user),
				EXS_PATH_MAX);
	if (ret <= 0 || ret >= EXS_PATH_MAX)
		return -EINVAL;
	return 0;
}

static const char *exs_map_path(const char *path)
{
	const char *to;

	if (!exs_cfg.map_path)
		return NULL;
	to = exs_cfg.map_path(path, exs_cfg.priv);
	if (!to || !to[0])
		return NULL;
	return to;
}

/*
 * one decision per call, path_filter is the only decision maker once set,
 * without it map_path alone decides the rewrite and env_add stays
 * unconditional
 * a rewrite flag that comes back without a usable target is dropped, so the
 * flag word alone says what the rest of the call does
 */
static u32 exs_decide(const char *path, struct exs_plan *plan)
{
	u32 flags;

	memset(plan, 0, sizeof(*plan));

	if (!exs_cfg.path_filter) {
		plan->to = exs_map_path(path);
		return plan->to ? EXS_ACT_REWRITE : EXS_ACT_NONE;
	}

	flags = exs_cfg.path_filter(path, plan, exs_cfg.priv);
	if (!(flags & EXS_ACT_REWRITE))
		return flags;
	if (plan->to && plan->to[0])
		return flags;
	return flags & ~EXS_ACT_REWRITE;
}

static const char *exs_plan_to(u32 flags, const struct exs_plan *plan)
{
	if (!(flags & EXS_ACT_REWRITE))
		return NULL;
	return plan->to;
}

/* no path_filter means the legacy behaviour, env_add on every execve */
static bool exs_want_env(u32 flags)
{
	if (!exs_cfg.path_filter)
		return true;
	return flags & EXS_ACT_ENV;
}

static const char *const *exs_plan_env(u32 flags,
				       const struct exs_plan *plan)
{
	if ((flags & EXS_ACT_ENV) && plan->env)
		return plan->env;
	return exs_cfg.env_add;
}

/* close the temp fd we installed, via the close syscall as KSU does */
static void exs_close_fd(int fd)
{
	struct pt_regs fake = {0};

	fake.regs[0] = (unsigned long)fd;
	sc_tp_orig(__NR_close, &fake);
}

static int exs_env_key(const char *item, size_t *key_len)
{
	const char *eq;

	eq = strchr(item, '=');
	if (!eq || eq == item)
		return -EINVAL;
	if ((size_t)(eq - item) >= EXS_KEY_MAX)
		return -E2BIG;
	*key_len = eq - item;
	return 0;
}

static int exs_env_read(const unsigned long __user *ep, unsigned long *arr,
			int max, int *count)
{
	int n;

	*count = 0;
	if (!ep)
		return 0;

	for (n = 0; n < max; n++) {
		unsigned long p;

		if (copy_from_user_nofault(&p, &ep[n], sizeof(p)))
			return -EFAULT;
		if (!p)
			break;
		arr[n] = p;
	}
	if (n == max)
		return -E2BIG;

	*count = n;
	return 0;
}

static bool exs_env_has_key(const unsigned long *arr, int count,
			    const char *item, size_t key_len)
{
	char buf[EXS_KEY_MAX];
	long ret;
	int i;

	for (i = 0; i < count; i++) {
		ret = strncpy_from_user(
			buf,
			(const char __user *)untagged_addr((unsigned long)arr[i]),
			sizeof(buf));
		if (ret <= 0)
			continue;
		if (strncmp(buf, item, key_len))
			continue;
		if (buf[key_len] == '=')
			return true;
	}
	return false;
}

/*
 * original items first, injected items after, a key already present in the
 * original envp keeps its value and is not appended again
 * changed stays false when envp needs no rewrite
 */
static int exs_env_build(unsigned long envp_user, struct exs_stack *st,
			 const char *const *add, unsigned long *new_envp,
			 bool *changed)
{
	const unsigned long __user *ep =
		(const unsigned long __user *)untagged_addr(envp_user);
	unsigned long *arr;
	size_t total;
	int count = 0;
	int added = 0;
	int ret;
	int i;
	int j;

	*changed = false;

	arr = kmalloc_array(EXS_ENV_MAX + EXS_ENV_ADD_MAX + 1, sizeof(*arr),
			    GFP_KERNEL);
	if (!arr)
		return -ENOMEM;

	ret = exs_env_read(ep, arr, EXS_ENV_MAX, &count);
	if (ret)
		goto out;

	for (i = 0; add[i] && added < EXS_ENV_ADD_MAX; i++) {
		bool dup = false;
		size_t key_len;
		unsigned long addr;

		if (exs_env_key(add[i], &key_len))
			continue;
		if (exs_env_has_key(arr, count, add[i], key_len))
			continue;
		for (j = 0; j < i; j++) {
			size_t other_len;

			if (exs_env_key(add[j], &other_len))
				continue;
			if (other_len != key_len)
				continue;
			if (!strncmp(add[j], add[i], key_len)) {
				dup = true;
				break;
			}
		}
		if (dup)
			continue;

		addr = (unsigned long)exs_stack_put(st, add[i],
						    strlen(add[i]) + 1);
		if (!addr) {
			ret = -EFAULT;
			goto out;
		}
		arr[count + added] = addr;
		added++;
	}

	if (!added) {
		ret = 0;
		goto out;
	}

	arr[count + added] = 0;
	total = (count + added + 1) * sizeof(*arr);
	st->addr = ALIGN_DOWN(st->addr - total, EXS_STACK_ALIGN);
	if (copy_to_user((void __user *)st->addr, arr, total)) {
		ret = -EFAULT;
		goto out;
	}

	*new_envp = st->addr;
	*changed = true;
	ret = 0;
out:
	kfree(arr);
	return ret;
}

/*
 * turn execve into execveat: open the target for an fd and pass an empty
 * filename with AT_EMPTY_PATH
 * execve(file,argv,envp) becomes execveat(fd,file,argv,envp,flags)
 * the five argument registers go into a local array first and are written
 * back one by one when the converted call fails
 */
static long exs_exec_fd(int nr, struct pt_regs *r, const char *to,
			unsigned long argv_user, unsigned long envp_user,
			struct exs_stack *st)
{
	unsigned long orig[5];
	unsigned long empty;
	struct file *file;
	long ret;
	int fd;
	int i;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return sc_tp_orig(nr, r);

	file = filp_open(to, O_PATH, 0);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		return sc_tp_orig(nr, r);
	}
	fd_install(fd, file);

	empty = (unsigned long)exs_stack_put(st, "", sizeof(""));
	if (!empty) {
		exs_close_fd(fd);
		return sc_tp_orig(nr, r);
	}

	for (i = 0; i < 5; i++)
		orig[i] = r->regs[i];
	EXS_PARM5(r) = AT_EMPTY_PATH;
	EXS_PARM4(r) = envp_user;
	EXS_PARM3(r) = argv_user;
	EXS_PARM2(r) = empty;
	EXS_PARM1(r) = (unsigned long)fd;

	ret = sc_tp_orig(__NR_execveat, r);
	if (ret < 0) {
		exs_close_fd(fd);
		for (i = 0; i < 5; i++)
			r->regs[i] = orig[i];
	}
	return ret;
}

/*
 * the escalation follows a successful staging, a consumer that has a
 * precondition tests it in path_filter and asks for nothing instead
 */
static void exs_plan_escalate(const char *path, u32 flags)
{
	if (!(flags & EXS_ACT_ESCALATE) || !exs_cfg.path_escalate)
		return;
	exs_cfg.path_escalate(path, exs_cfg.priv);
}

static long exs_exec_common(int nr, struct pt_regs *r, unsigned long path_user,
			    unsigned long argv_user, unsigned long *envp_p)
{
	struct exs_plan plan = {0};
	struct exs_stack st;
	const char *const *add;
	unsigned long envp_user;
	unsigned long new_envp = 0;
	char path[EXS_PATH_MAX];
	const char *to;
	bool changed = false;
	u32 flags;
	int ret;

	ret = exs_read_path(path_user, path);
	flags = ret ? EXS_ACT_NONE : exs_decide(path, &plan);

	to = exs_plan_to(flags, &plan);
	add = exs_plan_env(flags, &plan);

	envp_user = *envp_p;
	exs_stack_init(&st);

	if (exs_want_env(flags) && add) {
		ret = exs_env_build(envp_user, &st, add, &new_envp, &changed);
		if (ret)
			return sc_tp_orig(nr, r);
		if (changed) {
			envp_user = new_envp;
			*envp_p = new_envp;
		}
	}

	exs_plan_escalate(path, flags);

	if (!to)
		return sc_tp_orig(nr, r);

	return exs_exec_fd(nr, r, to, argv_user, envp_user, &st);
}

static long exs_execve(int nr, struct pt_regs *r)
{
	return exs_exec_common(nr, r, EXS_PARM1(r), EXS_PARM2(r),
			       (unsigned long *)&EXS_PARM3(r));
}

static long exs_execveat(int nr, struct pt_regs *r)
{
	/* like the reference, only the path form, AT_FDCWD with flags 0 */
	if ((int)EXS_PARM1(r) != AT_FDCWD || (int)EXS_PARM5(r) != 0)
		return sc_tp_orig(nr, r);

	return exs_exec_common(nr, r, EXS_PARM2(r), EXS_PARM3(r),
			       (unsigned long *)&EXS_PARM4(r));
}

/* faccessat and newfstatat only rewrite the path pointer held in regs[1] */
static long exs_path_rewrite(int nr, struct pt_regs *r)
{
	const char __user **fn_user = (const char __user **)&EXS_PARM2(r);
	const char __user *orig;
	struct exs_plan plan;
	struct exs_stack st;
	char path[EXS_PATH_MAX];
	const char *to;
	char __user *newp;
	long ret;
	u32 flags;

	if (exs_read_path((unsigned long)*fn_user, path))
		return sc_tp_orig(nr, r);

	flags = exs_decide(path, &plan);
	to = exs_plan_to(flags, &plan);
	if (!to)
		return sc_tp_orig(nr, r);

	exs_stack_init(&st);
	newp = exs_stack_put(&st, to, strlen(to) + 1);
	if (!newp)
		return sc_tp_orig(nr, r);

	orig = *fn_user;
	*fn_user = newp;
	ret = sc_tp_orig(nr, r);
	*fn_user = orig;
	return ret;
}

static long exs_hook(int nr, const struct pt_regs *regs)
{
	struct pt_regs *r;

	if (!exs_on)
		return sc_tp_orig(nr, regs);

	if (exs_cfg.allow_uid &&
	    !exs_cfg.allow_uid(__kuid_val(current_uid()), exs_cfg.priv))
		return sc_tp_orig(nr, regs);

	/*
	 * the const in the hook prototype comes from KernCall, what is really
	 * passed in is the live pt_regs of the current task taken by the
	 * tracepoint, so it may be rewritten for this syscall
	 */
	r = (struct pt_regs *)regs;

	if (nr == __NR_execve)
		return exs_execve(nr, r);
	if (nr == __NR_execveat)
		return exs_execveat(nr, r);
	if (nr == __NR_faccessat || nr == __NR_newfstatat)
		return exs_path_rewrite(nr, r);
	return sc_tp_orig(nr, regs);
}

static const int exs_hook_nrs[EXS_NR_COUNT] = {
	__NR_execve,
	__NR_execveat,
	__NR_faccessat,
	__NR_newfstatat,
};

int exs_start(void)
{
	int ret;
	int i;
	int j;

	if (!exs_ready)
		return -EINVAL;
	if (exs_on)
		return 0;
	if (sc_tp_slot() < 0)
		return -ENODATA;

	for (i = 0; i < EXS_NR_COUNT; i++) {
		ret = sc_tp_register(exs_hook_nrs[i], exs_hook);
		if (!ret)
			continue;
		pr_warn("[execshim] hook %d failed: %d\n", exs_hook_nrs[i],
			ret);
		for (j = 0; j < i; j++)
			sc_tp_unregister(exs_hook_nrs[j]);
		return ret;
	}

	exs_on = true;
	return 0;
}

void exs_stop(void)
{
	int i;

	if (!exs_on)
		return;

	for (i = 0; i < EXS_NR_COUNT; i++)
		sc_tp_unregister(exs_hook_nrs[i]);
	exs_on = false;
}

#endif
