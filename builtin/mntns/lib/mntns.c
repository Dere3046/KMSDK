// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/proc_fs.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <uapi/linux/mount.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/rcupdate.h>
#include <linux/dcache.h>
#include <linux/syscalls.h>

#include "hk.h"
#include "mntns.h"

static long (*mn_setns)(const struct pt_regs *regs);
static struct proc_ns_operations *mn_mntns_ops;
static long (*mn_ns_get_path)(struct path *path,
			      struct task_struct *task,
			      const struct proc_ns_operations *ops);
static long (*mn_ksys_unshare)(unsigned long flags);
static int (*mn_path_mount)(const char *dev_name, struct path *path,
			    const char *type, unsigned long flags,
			    void *data);
static struct file *(*mn_dentry_open)(const struct path *path, int flags,
				      const struct cred *cred);
static void (*mn_path_get)(struct path *path);
static void (*mn_set_fs_pwd)(struct fs_struct *fs, const struct path *pwd);
static int (*mn_filp_close)(struct file *file, fl_owner_t owner);

static __nocfi long mn_call_setns(int fd, int flags)
{
	struct pt_regs fake = {0};

	fake.regs[0] = fd;
	fake.regs[1] = flags;
	return mn_setns(&fake);
}

static __nocfi long mn_call_ns_get_path(struct path *path,
					struct task_struct *task,
					const struct proc_ns_operations *ops)
{
	return mn_ns_get_path(path, task, ops);
}

static __nocfi long mn_call_unshare(unsigned long flags)
{
	return mn_ksys_unshare(flags);
}

static __nocfi int mn_call_path_mount(const char *dev_name, struct path *path,
				      const char *type, unsigned long flags,
				      void *data)
{
	return mn_path_mount(dev_name, path, type, flags, data);
}

static __nocfi struct file *mn_call_dentry_open(const struct path *path,
						int flags,
						const struct cred *cred)
{
	return mn_dentry_open(path, flags, cred);
}

static __nocfi void mn_call_path_get(struct path *path)
{
	mn_path_get(path);
}

static __nocfi void mn_call_set_fs_pwd(struct fs_struct *fs,
				       const struct path *pwd)
{
	mn_set_fs_pwd(fs, pwd);
}

static __nocfi int mn_call_filp_close(struct file *file)
{
	return mn_filp_close(file, NULL);
}

int mntns_init(void)
{
	unsigned long addr;

	addr = hk_resolve("__arm64_sys_setns");
	if (!addr) {
		pr_info("[mntns] no __arm64_sys_setns\n");
		return -ENODATA;
	}
	mn_setns = (long (*)(const struct pt_regs *))addr;

	addr = hk_resolve("mntns_operations");
	if (!addr) {
		pr_info("[mntns] no mntns_operations\n");
		return -ENODATA;
	}
	mn_mntns_ops = (struct proc_ns_operations *)addr;

	addr = hk_resolve("ns_get_path");
	if (!addr) {
		pr_info("[mntns] no ns_get_path\n");
		return -ENODATA;
	}
	mn_ns_get_path = (long (*)(struct path *, struct task_struct *,
				   const struct proc_ns_operations *))addr;

	addr = hk_resolve("ksys_unshare");
	if (!addr) {
		pr_info("[mntns] no ksys_unshare\n");
		return -ENODATA;
	}
	mn_ksys_unshare = (long (*)(unsigned long))addr;

	addr = hk_resolve("path_mount");
	if (!addr) {
		pr_info("[mntns] no path_mount\n");
		return -ENODATA;
	}
	mn_path_mount = (int (*)(const char *, struct path *, const char *,
				 unsigned long, void *))addr;

	addr = hk_resolve("dentry_open");
	if (!addr) {
		pr_info("[mntns] no dentry_open\n");
		return -ENODATA;
	}
	mn_dentry_open = (struct file *(*)(const struct path *, int,
					   const struct cred *))addr;

	addr = hk_resolve("path_get");
	if (!addr) {
		pr_info("[mntns] no path_get\n");
		return -ENODATA;
	}
	mn_path_get = (void (*)(struct path *))addr;

	addr = hk_resolve("set_fs_pwd");
	if (!addr) {
		pr_info("[mntns] no set_fs_pwd\n");
		return -ENODATA;
	}
	mn_set_fs_pwd = (void (*)(struct fs_struct *, const struct path *))addr;

	addr = hk_resolve("filp_close");
	if (!addr) {
		pr_info("[mntns] no filp_close\n");
		return -ENODATA;
	}
	mn_filp_close = (int (*)(struct file *, fl_owner_t))addr;
	return 0;
}

void mntns_exit(void)
{
	mn_setns = NULL;
	mn_mntns_ops = NULL;
	mn_ns_get_path = NULL;
	mn_ksys_unshare = NULL;
	mn_path_mount = NULL;
}

static struct task_struct *mn_find_init(void)
{
	struct pid *pid_struct;
	struct task_struct *task;

	rcu_read_lock();
	pid_struct = find_pid_ns(1, &init_pid_ns);
	if (!pid_struct) {
		rcu_read_unlock();
		return NULL;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	rcu_read_unlock();
	return task;
}

int mntns_enter_init(void)
{
	struct task_struct *task;
	struct path ns_path;
	struct file *ns_file;
	struct path saved_pwd;
	char *buf;
	char *pwd;
	int fd;
	long ret;
	int err;

	if (!mn_mntns_ops || !mn_ns_get_path || !mn_setns)
		return -ENODATA;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	if (!current->fs)
		goto no_pwd;
	saved_pwd = current->fs->pwd;
	mn_call_path_get(&saved_pwd);
	pwd = d_path(&saved_pwd, buf, PATH_MAX);
	path_put(&saved_pwd);
no_pwd:
	if (IS_ERR(pwd))
		pwd = NULL;

	task = mn_find_init();
	if (!task) {
		kfree(buf);
		return -ESRCH;
	}
	ret = mn_call_ns_get_path(&ns_path, task, mn_mntns_ops);
	put_task_struct(task);
	if (ret) {
		kfree(buf);
		return ret;
	}
	ns_file = mn_call_dentry_open(&ns_path, O_RDONLY, current_cred());
	path_put(&ns_path);
	if (IS_ERR(ns_file)) {
		kfree(buf);
		return PTR_ERR(ns_file);
	}
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		fput(ns_file);
		kfree(buf);
		return fd;
	}
	fd_install(fd, ns_file);
	ret = mn_call_setns(fd, CLONE_NEWNS);
	{
		struct fd f = fdget(fd);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
		if (fd_file(f))
			mn_call_filp_close(fd_file(f));
#else
		if (f.file)
			mn_call_filp_close(f.file);
#endif
		fdput(f);
	}

	if (!ret && pwd) {
		struct path new_pwd;

		err = kern_path(pwd, 0, &new_pwd);
		if (!err) {
			mn_call_set_fs_pwd(current->fs, &new_pwd);
			path_put(&new_pwd);
		}
	}
	kfree(buf);
	return ret;
}

int mntns_enter_individual(void)
{
	struct path root_path;
	int ret;

	if (!mn_ksys_unshare || !mn_path_mount)
		return -ENODATA;

	ret = mn_call_unshare(CLONE_NEWNS);
	if (ret)
		return ret;

	if (!current->fs)
		return -EINVAL;
	root_path = current->fs->root;
	mn_call_path_get(&root_path);
	ret = mn_call_path_mount(NULL, &root_path, NULL, MS_PRIVATE | MS_REC,
				 NULL);
	path_put(&root_path);
	return ret;
}
