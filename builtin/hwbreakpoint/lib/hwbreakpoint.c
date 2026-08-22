// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/hw_breakpoint.h>
#include <asm/ptrace.h>

#include "hk.h"
#include "hk_kretprobe.h"
#include "hwbreakpoint.h"

#define HWB_REGSET_GET 0x4204
#define NT_ARM_HW_BREAK 0x402
#define NT_ARM_HW_WATCH 0x403

static struct perf_event *(*hwb_register_bp)(struct perf_event_attr *attr,
					     void (*cb)(struct perf_event *,
							struct perf_sample_data *,
							struct pt_regs *),
					     void *ctx, struct task_struct *tsk);
static void (*hwb_unregister_bp)(struct perf_event *bp);
static int (*hwb_modify_bp)(struct perf_event *bp,
			    struct perf_event_attr *attr);

static __nocfi struct perf_event *hwb_reg(struct perf_event_attr *attr,
					    void (*cb)(struct perf_event *,
						       struct perf_sample_data *,
						       struct pt_regs *),
					    void *ctx, struct task_struct *tsk)
{
	return hwb_register_bp(attr, cb, ctx, tsk);
}

static __nocfi void hwb_unreg(struct perf_event *bp)
{
	hwb_unregister_bp(bp);
}

static __nocfi int hwb_mod(struct perf_event *bp,
			   struct perf_event_attr *attr)
{
	return hwb_modify_bp(bp, attr);
}

static LIST_HEAD(hwb_list);
static DEFINE_SPINLOCK(hwb_lock);
static bool hwb_anti_on;

struct hwb_ptrace_ctx {
	struct iovec iov;
};

static struct hk_kretprobe hwb_krp;

static struct hwbp *hwb_find(struct perf_event *ev)
{
	struct hwbp *bp;
	unsigned long flags;

	spin_lock_irqsave(&hwb_lock, flags);
	list_for_each_entry(bp, &hwb_list, list) {
		if (bp->ev == ev) {
			spin_unlock_irqrestore(&hwb_lock, flags);
			return bp;
		}
	}
	spin_unlock_irqrestore(&hwb_lock, flags);
	return NULL;
}

static void hwb_handler(struct perf_event *ev, struct perf_sample_data *data,
			struct pt_regs *regs)
{
	struct hwbp *bp;

	bp = hwb_find(ev);
	if (!bp)
		return;

	if (bp->hook_pc) {
		regs->pc = bp->hook_pc;
		return;
	}

	if (ev->attr.disabled == 0) {
		struct perf_event_attr attr = ev->attr;

		attr.disabled = 1;
		if (hwb_modify_bp)
			hwb_mod(ev, &attr);
	}
}

int hwbp_init(void)
{
	unsigned long addr;

	addr = hk_resolve("register_user_hw_breakpoint");
	if (!addr)
		return -ENODATA;
	hwb_register_bp = (void *)addr;

	addr = hk_resolve("unregister_hw_breakpoint");
	if (!addr)
		return -ENODATA;
	hwb_unregister_bp = (void *)addr;

	addr = hk_resolve("modify_user_hw_breakpoint");
	if (!addr)
		return -ENODATA;
	hwb_modify_bp = (int (*)(struct perf_event *,
				 struct perf_event_attr *))addr;
	return 0;
}

void hwbp_exit(void)
{
	struct hwbp *bp, *tmp;
	unsigned long flags;

	hwbp_anti_stop();
	spin_lock_irqsave(&hwb_lock, flags);
	list_for_each_entry_safe(bp, tmp, &hwb_list, list) {
		list_del(&bp->list);
		spin_unlock_irqrestore(&hwb_lock, flags);
		if (hwb_unregister_bp)
			hwb_unreg(bp->ev);
		kfree(bp);
		spin_lock_irqsave(&hwb_lock, flags);
	}
	spin_unlock_irqrestore(&hwb_lock, flags);
	hwb_register_bp = NULL;
	hwb_unregister_bp = NULL;
	hwb_modify_bp = NULL;
}

int hwbp_add(pid_t pid, unsigned long addr, int type, int len,
	     struct hwbp **out)
{
	struct perf_event_attr attr;
	struct pid *pid_struct;
	struct task_struct *task;
	struct perf_event *ev;
	struct hwbp *bp;
	unsigned long flags;
	int ret;

	if (!out || !hwb_register_bp)
		return -EINVAL;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return -ESRCH;
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!task)
		return -ESRCH;

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_BREAKPOINT;
	attr.size = sizeof(attr);
	attr.bp_addr = addr;
	attr.bp_len = len;
	attr.bp_type = type;
	attr.disabled = 0;

	ev = hwb_reg(&attr, hwb_handler, NULL, task);
	put_task_struct(task);
	if (IS_ERR(ev)) {
		ret = PTR_ERR(ev);
		if (ret == 0)
			ret = -EINVAL;
		return ret;
	}

	bp = kzalloc(sizeof(*bp), GFP_KERNEL);
	if (!bp) {
		hwb_unreg(ev);
		return -ENOMEM;
	}
	bp->ev = ev;
	bp->addr = addr;

	spin_lock_irqsave(&hwb_lock, flags);
	list_add_tail(&bp->list, &hwb_list);
	spin_unlock_irqrestore(&hwb_lock, flags);

	*out = bp;
	return 0;
}

int hwbp_del(struct hwbp *bp)
{
	unsigned long flags;

	if (!bp)
		return -EINVAL;

	spin_lock_irqsave(&hwb_lock, flags);
	list_del(&bp->list);
	spin_unlock_irqrestore(&hwb_lock, flags);
	hwb_unreg(bp->ev);
	kfree(bp);
	return 0;
}

int hwbp_pause(struct hwbp *bp)
{
	struct perf_event_attr attr;

	if (!bp || !hwb_modify_bp)
		return -EINVAL;
	attr = bp->ev->attr;
	attr.disabled = 1;
	return hwb_mod(bp->ev, &attr);
}

int hwbp_resume(struct hwbp *bp)
{
	struct perf_event_attr attr;

	if (!bp || !hwb_modify_bp)
		return -EINVAL;
	attr = bp->ev->attr;
	attr.disabled = 0;
	return hwb_mod(bp->ev, &attr);
}

int hwbp_set_pc(struct hwbp *bp, unsigned long target)
{
	if (!bp)
		return -EINVAL;
	bp->hook_pc = target;
	return 0;
}

static int hwb_ptrace_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hwb_ptrace_ctx *ctx = (struct hwb_ptrace_ctx *)ri->data;
	long request = regs->regs[1];
	unsigned long regset = regs->regs[2];
	unsigned long iov_ptr = regs->regs[3];

	memset(ctx, 0, sizeof(*ctx));
	if (request != HWB_REGSET_GET ||
	    (regset != NT_ARM_HW_BREAK && regset != NT_ARM_HW_WATCH))
		return 0;
	if (!iov_ptr)
		return 0;
	if (copy_from_user(&ctx->iov, (struct iovec __user *)iov_ptr,
			   sizeof(ctx->iov)))
		return 0;
	return 0;
}

static int hwb_ptrace_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hwb_ptrace_ctx *ctx = (struct hwb_ptrace_ctx *)ri->data;
	struct user_hwdebug_state state;
	struct hwbp *bp;
	unsigned long flags;
	size_t sz;
	int i;

	if (!ctx->iov.iov_base || !ctx->iov.iov_len)
		return 0;

	sz = min_t(size_t, ctx->iov.iov_len, sizeof(state));
	if (!access_ok((void __user *)ctx->iov.iov_base, sz))
		return 0;
	if (copy_from_user(&state, (void __user *)ctx->iov.iov_base, sz))
		return 0;

	spin_lock_irqsave(&hwb_lock, flags);
	for (i = 0; i < 16; i++) {
		if (!state.dbg_regs[i].addr)
			continue;
		list_for_each_entry(bp, &hwb_list, list) {
			if (bp->addr == state.dbg_regs[i].addr) {
				state.dbg_regs[i].addr = 0;
				state.dbg_regs[i].ctrl = 0;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&hwb_lock, flags);

	if (copy_to_user((void __user *)ctx->iov.iov_base, &state, sz))
		return -EFAULT;
	return 0;
}

int hwbp_anti_start(void)
{
	if (hwb_anti_on)
		return -EINVAL;
	if (hk_kretprobe_install_ex(&hwb_krp, "arch_ptrace",
				    hwb_ptrace_entry, hwb_ptrace_ret,
				    sizeof(struct hwb_ptrace_ctx)))
		return -EIO;
	hwb_anti_on = true;
	return 0;
}

void hwbp_anti_stop(void)
{
	if (!hwb_anti_on)
		return;
	hk_kretprobe_remove(&hwb_krp);
	hwb_anti_on = false;
}
