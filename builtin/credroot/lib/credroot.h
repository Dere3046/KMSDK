// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef CREDROOT_H
#define CREDROOT_H

#include <linux/types.h>

/*
 * Credential replacement for one task.
 *
 * Scope of a mark call, deliberate and part of the design:
 *   only the cred and the real_cred of the addressed task change, the other
 *   threads of the same thread group keep their own pointers and their cred
 *   objects, because the library writes the task pointers directly instead of
 *   going through commit_creds. commit_creds walks the whole thread group,
 *   updates the keyrings and runs the LSM fixups, which is what a caller that
 *   wants a hidden, single process root must avoid. getuid, geteuid and the
 *   /proc status entry read real_cred, so both pointers move together or the
 *   task would report the old uid while acting as root.
 *   The following fields are covered: uid, gid and their suid, sgid, euid,
 *   egid, fsuid, fsgid, the securebits and every capability set, the
 *   supplementary groups, the user_struct that carries the RLIMIT_NPROC
 *   charge and the ucounts of 5.14 and later. The LSM blob, the keyrings and
 *   the user namespace are inherited from the caller cred.
 *
 * Prerequisites for every call below: hk_init with the consumer resolver ran
 * and credroot_init succeeded. Calls sleep, so they need a sleepable context,
 * and they must not run against a task that is changing its own credential at
 * the same time.
 */

/*
 * Resolve the kernel symbols the library drives, it must run after hk_init.
 * The hooks reached here are built into the image, so the resolver has to be
 * a __nocfi wrapper. Returns 0, -ENODATA when prepare_creds, abort_creds,
 * alloc_uid, groups_alloc, groups_sort, set_groups or, on 5.14 and later,
 * set_cred_ucounts cannot be resolved.
 */
int credroot_init(void);
void credroot_exit(void);

/*
 * Give the task a root credential. Returns 0, -EINVAL for pid 0, -ENODATA
 * before credroot_init, -ESRCH when the pid has no task in the initial pid
 * namespace, -ENOMEM when prepare_creds or alloc_uid fails, -EAGAIN when the
 * ucounts refresh of 5.14 and later fails. A failure leaves the task
 * untouched and frees the partial credential through abort_creds.
 */
int credroot_mark_root(pid_t pid);

/* credroot_mark_root for the calling task, see its return codes */
int credroot_mark_current(void);

#endif
