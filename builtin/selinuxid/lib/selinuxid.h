// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef SELINUXID_H
#define SELINUXID_H

#include <linux/types.h>

struct cred;
struct inode;

/*
 * resolve is the consumer symbol resolver, it must be a __nocfi wrapper such
 * as kr_name_to_addr, the SELinux hooks reached here are static in the image
 * and their KCFI preamble does not match a module call site.
 *
 * domain_context is the context of the consumer own domain, file_context the
 * context its private inodes carry, both optional and both must stay valid
 * until sid_exit.
 */
struct sid_config {
	unsigned long (*resolve)(const char *name);
	const char *domain_context;
	const char *file_context;
};

/*
 * Resolve the kernel symbols the library uses and fill the SID cache, it runs
 * before every other call and from a sleepable context. Returns 0, -EINVAL for
 * a NULL config or a NULL resolve, -EALREADY on a second call, -ENOSYS when
 * selinux_state, selinux_blob_sizes, selinux_secctx_to_secid,
 * selinux_secid_to_secctx, selinux_release_secctx, copy_from_kernel_nofault or
 * copy_to_kernel_nofault cannot be resolved, -EFAULT when selinux_blob_sizes
 * cannot be read. A context the live policy does not know yet keeps its cache
 * slot empty and the matching predicate answers false until sid_cache_resync
 * runs.
 */
int sid_init(const struct sid_config *config);
void sid_exit(void);

/*
 * Drop the cached SIDs and resolve the configured contexts again. Call it
 * after the first policy load and after every policy reload, a SID cached
 * against an older policy selects the wrong domain. Sleepable, returns 0 or
 * -ENODEV before sid_init. A context that stays unresolvable leaves its slot
 * empty and is reported per call by sid_of.
 */
int sid_cache_resync(void);

/*
 * Context to SID. Served from the cache, a miss goes to the policy with
 * GFP_KERNEL, so it is sleepable. Returns 0, -EINVAL for a NULL argument,
 * -ENODEV before sid_init, -ENOENT when the policy maps the context to SID
 * zero, otherwise the policy error, an unknown context surfaces as -EINVAL.
 */
int sid_of(const char *context, u32 *sid);

/*
 * SID to context, buffer receives the context and its terminating NUL, size
 * counts both. Sleepable. Returns 0, -EINVAL for a NULL buffer or a zero size,
 * -ENODEV before sid_init, -ENAMETOOLONG when the context does not fit,
 * -ENOENT for a SID without a context.
 */
int sid_to_context(u32 sid, char *buffer, size_t size);

/*
 * SID of a cred, read from the LSM cred blob of that cred. Returns 0 when cred
 * is NULL or the blob cannot be read, sid_init must have run.
 */
u32 sid_cred_sid(const struct cred *cred);

/*
 * SID of the running process, sid_cred_sid of current_cred.
 */
u32 sid_current_sid(void);

/*
 * Compare a SID against a cred or the running process, the pure u32 form for
 * hot paths, no sleep, no string work and no policy lookup. SID zero never
 * matches.
 */
bool sid_cred_is_sid(const struct cred *cred, u32 sid);
bool sid_current_is_sid(u32 sid);

/*
 * Compare a context against a cred or the running process. The SID comes from
 * sid_of, so both sleep, sid_init must have run.
 */
bool sid_cred_is(const struct cred *cred, const char *context);
bool sid_current_is(const char *context);

/*
 * Write the SID of cred->security and clear create_sid, keycreate_sid and
 * sockcreate_sid, exec_sid as well when clear_exec is set. Takes a cred from
 * prepare_creds, commit_creds publishes it. Returns 0, -EINVAL for a NULL cred
 * or a zero SID, -ENODEV before sid_init, -ENODATA when the cred carries no
 * LSM blob, -EFAULT when the blob cannot be written.
 */
int sid_cred_set_sid(struct cred *cred, u32 sid, bool clear_exec);

/*
 * sid_cred_set_sid with the SID resolved from context, the sid_of error is
 * returned as is. Sleepable.
 */
int sid_cred_set_domain(struct cred *cred, const char *context,
			bool clear_exec);

/*
 * Domain predicates, each one a u32 compare against the matching cache slot.
 * No sleep and safe from atomic context, false while the slot is empty.
 */
bool sid_is_own_domain(const struct cred *cred);
bool sid_is_zygote(const struct cred *cred);
bool sid_is_init(const struct cred *cred);

/*
 * Android uid classification, appid is uid modulo the per user range.
 */
bool sid_is_appuid(uid_t uid);
bool sid_is_isolated(uid_t uid);

/*
 * SID of an inode LSM blob, 0 when inode is NULL or the blob cannot be read.
 */
u32 sid_inode_sid(const struct inode *inode);

/*
 * Relabel an inode, sid_inode_set_domain resolves the context first and
 * sid_inode_set_file writes the file_context of sid_init, the label the
 * reference file wrapper puts on its private inode. The inode must already
 * carry an LSM blob, an anon inode gets one from the inode allocator, while a
 * labelled inode that is still pending can be relabelled again by the kernel
 * from its xattr. Returns 0, -EINVAL for a NULL inode or a zero SID, -ENODEV
 * before sid_init, -ENODATA when the inode carries no blob, -EFAULT when the
 * blob cannot be written.
 */
int sid_inode_set_sid(struct inode *inode, u32 sid);
int sid_inode_set_domain(struct inode *inode, const char *context);
int sid_inode_set_file(struct inode *inode);

/*
 * selinux_state.enforcing, the value setenforce reports. With
 * CONFIG_SECURITY_SELINUX_DEVELOP off the kernel treats the policy as always
 * enforcing, the getter then answers true and the setter does nothing. A read
 * that fails answers false.
 */
bool sid_enforcing_get(void);
void sid_enforcing_set(bool enforce);

/*
 * selinux_state.disabled, present and writable only while
 * CONFIG_SECURITY_SELINUX_DISABLE exists, which the kernel dropped in 6.5.
 * Writing the byte alone does not run the kernel teardown, the consumer needs
 * it as a diagnostic and selinux_disable owns the real work. Without the field
 * the getter answers false and the setter does nothing.
 */
bool sid_disabled_get(void);
void sid_disabled_set(bool disabled);

/*
 * Address of selinux_state, for consumers that read the tail of the struct
 * themselves. NULL before sid_init.
 */
void *sid_state(void);

#endif
