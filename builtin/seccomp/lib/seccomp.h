// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef SECCOMP_H
#define SECCOMP_H

#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/types.h>

/*
 * Seccomp control and the seccomp filter cache of one task.
 *
 * Scope of every call below: the addressed task alone. seccomp state is per
 * task inside a thread group, so a thread that shares the group keeps its own
 * filter and only the syscall work of the addressed task is dropped. The
 * disable path is what makes a task usable after a privilege change, a filter
 * of the caller survives the change and would keep denying the syscalls of a
 * su style handover.
 *
 * Prerequisites: seccomp_init ran and succeeded, and the caller supplies the
 * task resolver that KallRecon and type_info already drive.
 */

struct seccomp_cfg {
	unsigned long (*resolve)(const char *name);
};

/*
 * Resolve the symbols and the layout this library needs. The seccomp filter
 * release routine is not exported, so it is resolved through the consumer
 * callback like every other symbol here. The task and seccomp members the
 * library writes are public types and the compiler resolves them, but the
 * filter cache is not: struct seccomp_filter and struct action_cache live
 * inside kernel/seccomp.c and reach a module as an opaque forward declaration
 * only, so their offsets are read from the BTF of the running kernel or the
 * call is refused. No offset is ever guessed. The release routine changed
 * shape across 6.6 to 6.11 and the shape is probed on the running image, no
 * version macro takes part in that decision.
 * Returns 0, -EINVAL for a NULL cfg or a NULL resolve, -ENODATA when there is
 * no BTF base or when it does not carry the filter cache layout, -ENOSYS when
 * seccomp_filter_release or copy_from_kernel_nofault cannot be resolved. A
 * type_info base another library already brought up is adopted instead of
 * initializing a second one, and seccomp_exit tears down only a base this
 * library created itself.
 */
int seccomp_init(const struct seccomp_cfg *cfg);
void seccomp_exit(void);

/*
 * Drop the seccomp filter of the current task, the filter reference is
 * released through the kernel routine and TIF_SECCOMP, the mode, the filter
 * count and the filter pointer are cleared under the siglock of the task. The
 * syscall path of the task is free of the filter afterwards, which is what a
 * privilege handover needs because a filter installed by the caller survives
 * the credential change and would keep denying the syscalls of the new
 * identity.
 * Returns 0, -ENODATA before seccomp_init, -ENOMEM when the temporary task
 * copy cannot be allocated, -EINVAL when the task has no sighand to lock, and
 * 0 for a task that already runs without a filter.
 */
int seccomp_disable_current(void);

/*
 * Drop the seccomp filter of tsk and leave the syscall work cleared, the
 * counterpart of seccomp_disable_current for a task that is not the caller.
 * The name stays clear of the void seccomp_filter_release of the kernel so the
 * two can never be confused at a call site. tsk must be stopped or otherwise
 * prevented from running its own seccomp changes, and its sighand has to stay
 * valid across the call.
 * Returns 0, -EINVAL for a NULL tsk or a task without a sighand, -ENODATA
 * before seccomp_init, -ENOMEM when the temporary task copy cannot be
 * allocated, and 0 for a task that already runs without a filter.
 */
int sc_filter_release(struct task_struct *tsk);

/*
 * The filter of tsk as it stands right now, NULL when the task has none or
 * before seccomp_init. The pointer is the object the cache calls below write
 * to, it stays owned by the task.
 */
void *seccomp_filter_of(struct task_struct *tsk);

/*
 * Mark a syscall as allowed or denied in the filter cache of the running
 * kernel, which spares the BPF program a walk through every attached filter.
 * filter comes from seccomp_filter_of. Returns 0, -EINVAL for a NULL filter
 * or a negative syscall number, and clears or sets the bit otherwise.
 */
int seccomp_cache_allow(void *filter, int nr);
int seccomp_cache_clear(void *filter, int nr);

#endif
