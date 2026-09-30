// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/user.h>
#include <linux/rcupdate.h>
#include <linux/capability.h>
#include <linux/uidgid.h>
#include <linux/mutex.h>
#include <linux/version.h>

#include "hk.h"
#include "credroot.h"

/*
 * Every symbol below is resolved through the consumer resolver, prepare_creds
 * and abort_creds are exported only to the GKI VFS namespace in some releases
 * and alloc_uid and set_cred_ucounts are not exported at all.
 */
struct cr_syms {
	struct cred *(*prepare_creds)(void);
	void (*abort_creds)(struct cred *new);
	struct user_struct *(*alloc_uid)(kuid_t uid);
	struct group_info *(*groups_alloc)(int gidsetsize);
	void (*groups_sort)(struct group_info *group_info);
	void (*set_groups)(struct cred *new, struct group_info *group_info);
	void (*groups_free)(struct group_info *group_info);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	int (*set_cred_ucounts)(struct cred *new);
#endif
};

static struct cr_syms cr_sym;

/*
 * Two callers that swap the cred of one task at the same time both read the
 * same old pointer and both drop the reference of that single task, a double
 * free follows. The swap and the drop are serialized, the preparation of a new
 * cred stays outside the lock.
 */
static DEFINE_MUTEX(cr_swap_lock);

static __nocfi struct cred *cr_call_prepare(void)
{
	return cr_sym.prepare_creds();
}

static __nocfi void cr_call_abort(struct cred *new)
{
	cr_sym.abort_creds(new);
}

static __nocfi struct user_struct *cr_call_alloc_uid(kuid_t uid)
{
	return cr_sym.alloc_uid(uid);
}

static __nocfi struct group_info *cr_call_groups_alloc(int nr)
{
	return cr_sym.groups_alloc(nr);
}

static __nocfi void cr_call_groups_sort(struct group_info *gi)
{
	cr_sym.groups_sort(gi);
}

static __nocfi void cr_call_set_groups(struct cred *new,
				       struct group_info *gi)
{
	cr_sym.set_groups(new, gi);
}

static __nocfi void cr_call_groups_free(struct group_info *gi)
{
	cr_sym.groups_free(gi);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
static __nocfi int cr_call_set_ucounts(struct cred *new)
{
	return cr_sym.set_cred_ucounts(new);
}
#endif

static void cr_reset(void)
{
	memset(&cr_sym, 0, sizeof(cr_sym));
}

int credroot_init(void)
{
	cr_sym.prepare_creds = (void *)hk_resolve("prepare_creds");
	cr_sym.abort_creds = (void *)hk_resolve("abort_creds");
	cr_sym.alloc_uid = (void *)hk_resolve("alloc_uid");
	cr_sym.groups_alloc = (void *)hk_resolve("groups_alloc");
	cr_sym.groups_sort = (void *)hk_resolve("groups_sort");
	cr_sym.set_groups = (void *)hk_resolve("set_groups");
	cr_sym.groups_free = (void *)hk_resolve("groups_free");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	cr_sym.set_cred_ucounts = (void *)hk_resolve("set_cred_ucounts");
#endif

	if (!cr_sym.prepare_creds || !cr_sym.abort_creds || !cr_sym.alloc_uid ||
	    !cr_sym.groups_alloc || !cr_sym.groups_sort || !cr_sym.set_groups ||
	    !cr_sym.groups_free)
		goto missing;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	if (!cr_sym.set_cred_ucounts)
		goto missing;
#endif
	return 0;

missing:
	cr_reset();
	return -ENODATA;
}

void credroot_exit(void)
{
	cr_reset();
}

/*
 * Supplementary groups are rebuilt through the kernel helpers so the
 * __randomize_layout group_info of 6.7 and later keeps its private layout, the
 * root gid as the only member matches a setgroups(1, { 0 }) from userspace.
 * set_groups takes its own reference, so the caller drops the allocation.
 */
static int credroot_root_groups(struct cred *c)
{
	struct group_info *gi;

	gi = cr_call_groups_alloc(1);
	if (!gi)
		return -ENOMEM;
	gi->gid[0] = GLOBAL_ROOT_GID;
	cr_call_groups_sort(gi);
	cr_call_set_groups(c, gi);
	cr_call_groups_free(gi);
	return 0;
}

/*
 * The ids are written first and the accounting runs in the same step, because
 * RLIMIT_NPROC is charged to the user_struct and the ucounts of the cred and
 * not to the numeric uid. A cred that changes uid while it keeps the old
 * accounting pins the old charge, and the su process that follows would
 * inherit an exhausted budget. kernel/sys.c set_user does the same in this
 * order. Both only touch the still private cred, so abort_creds undoes a
 * failure without a leak.
 */
static int credroot_new_root_creds(struct cred *c)
{
	struct user_struct *user;

	c->uid = c->suid = c->euid = c->fsuid = GLOBAL_ROOT_UID;
	c->gid = c->sgid = c->egid = c->fsgid = GLOBAL_ROOT_GID;
	c->securebits = 0;
	c->cap_inheritable = CAP_FULL_SET;
	c->cap_permitted = CAP_FULL_SET;
	c->cap_effective = CAP_FULL_SET;
	c->cap_bset = CAP_FULL_SET;
	c->cap_ambient = CAP_FULL_SET;

	user = cr_call_alloc_uid(c->uid);
	if (!user)
		return -ENOMEM;
	free_uid(c->user);
	c->user = user;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	if (cr_call_set_ucounts(c))
		return -EAGAIN;
#endif
	return credroot_root_groups(c);
}

int credroot_mark_root(pid_t pid)
{
	struct pid *pid_struct;
	struct task_struct *task;
	struct cred *new_cred;
	struct cred *old_cred;
	int ret;

	if (!cr_sym.prepare_creds)
		return -ENODATA;
	if (!pid)
		return -EINVAL;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return -ESRCH;
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!task)
		return -ESRCH;

	new_cred = cr_call_prepare();
	if (!new_cred) {
		put_task_struct(task);
		return -ENOMEM;
	}

	ret = credroot_new_root_creds(new_cred);
	if (ret)
		goto abort;

	/*
	 * Both pointers of the task are published, the file and capability
	 * checks read cred and getuid and the proc status entry read real_cred,
	 * a task that only moves one of them reports a uid that contradicts what
	 * it is allowed to do. The publish stops at this task on purpose, the
	 * other threads of the group and the keyrings stay untouched, which is
	 * the hidden single process root this library exists for.
	 */
	mutex_lock(&cr_swap_lock);
	old_cred = (struct cred *)task->cred;
	rcu_assign_pointer(task->real_cred, new_cred);
	rcu_assign_pointer(task->cred, new_cred);

	/*
	 * The new cred replaces the reference of the task, so the old one is
	 * dropped by hand, abort_creds would free a cred that a task is still
	 * running on. The drop goes through put_cred, the memory is released from
	 * an RCU callback once readers that already picked up the old pointer are
	 * gone. The cred of 5.10 and later also lives in the private cred_jar
	 * cache, so an immediate free would be a cache mismatch.
	 */
	put_cred(old_cred);
	mutex_unlock(&cr_swap_lock);

	put_task_struct(task);
	return 0;

abort:
	cr_call_abort(new_cred);
	put_task_struct(task);
	return ret;
}

int credroot_mark_current(void)
{
	return credroot_mark_root(task_pid_nr(current));
}
