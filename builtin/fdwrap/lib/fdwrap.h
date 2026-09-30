// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef FDWRAP_H
#define FDWRAP_H

#include <linux/types.h>

struct cred;
struct file;

/*
 * dentry name of the private wrapper inode
 * the manager unload protocol matches this exact string, keep the default
 * unless the manager scan is changed as well
 */
#define FDW_NAME_DEFAULT "[ksu_fdwrapper]"

/*
 * resolve is the consumer symbol resolver, a __nocfi wrapper such as
 * kr_name_to_addr, fdwrap reaches every kernel symbol through it because GKI
 * trims exports and image functions carry KCFI preambles a module call site
 * cannot match
 *
 * name default dentry name, NULL takes FDW_NAME_DEFAULT
 * context default SELinux context of the wrapper inode
 * sid the same as a ready SID and it wins over context
 * cred credential used to create the private inode and to reopen the original
 *   file, NULL runs with the caller credential, it must stay valid while a
 *   wrapper exists
 * mode default wrapper inode mode, 0 copies the original inode mode
 * unlabeled skips the SELinux relabel, the wrapper then keeps the label the
 *   kernel gave the private inode
 *
 * the struct is copied, the three pointers are kept, so name, context and
 * cred must stay valid until fdw_exit
 * no sid, no context and no unlabeled means sid_inode_set_file, the label
 * selinuxid holds for its file context
 * sid_of and the relabel calls sleep, so fdw_init and every install run from
 * a sleepable context
 */
struct fdw_config {
	unsigned long (*resolve)(const char *name);
	const char *name;
	const char *context;
	u32 sid;
	const struct cred *cred;
	umode_t mode;
	bool unlabeled;
};

/*
 * per call overrides, a NULL opts or an empty field falls back to fdw_config
 *
 * flags creation flags of the wrapper file, 0 copies the original f_flags,
 *   the kernel keeps only O_ACCMODE and O_NONBLOCK out of them
 * a reopen of the wrapper through /proc/<pid>/fd takes the flags and the
 * credential of the opener, only mode and label stick to the inode
 */
struct fdw_opts {
	const char *name;
	const char *context;
	u32 sid;
	umode_t mode;
	int flags;
};

/*
 * resolve the symbols and take the config, sid_init must have run first
 * returns 0 on success, otherwise a negative errno, EINVAL for a NULL config
 * or a NULL resolve, EALREADY when fdw_init ran before without fdw_exit,
 * ENOSYS when a symbol the library needs is missing, EFAULT when the legacy
 * anon inode mount cannot be read
 * a failed call leaves nothing behind, fdw_init can run again
 */
int fdw_init(const struct fdw_config *config);

/*
 * drop the config and release the legacy anon inode mount
 * every wrapper fd must be closed first, a wrapper that is still open leaves
 * its ops table in module memory, fdw_live_count reports the count
 * idempotent, safe when fdw_init never ran
 */
void fdw_exit(void);

/*
 * wrap fd into a new fd of the caller fd table
 * the source fd stays open and stays owned by the caller, the returned fd is
 * owned by the caller and close on it runs the wrapper release
 * mmap runs the original callback with the original file in vm_file, a 6.18
 * file that only offers mmap_prepare cannot be served, mmap on its wrapper
 * answers ENODEV
 * returns the new fd on success, otherwise a negative errno, EBADF for a dead
 * fd, ENODEV before fdw_init, EINVAL when the file already is a wrapper,
 * ENOMEM, the creation error of the private inode or the relabel error the
 * live policy reports
 */
int fdw_install(int fd, const struct fdw_opts *opts);

/*
 * fdw_install over a live file, the file is borrowed and stays with the caller
 * returns the new fd on success, otherwise a negative errno, ENODEV before
 * fdw_init, EINVAL for a NULL file or a file that already is a wrapper
 */
int fdw_install_file(struct file *file, const struct fdw_opts *opts);

/*
 * number of live wrapper files, nonzero means a wrapper fd is open somewhere
 * and the module must not be unloaded, the manager unload protocol closes
 * them first
 */
int fdw_live_count(void);

#endif
