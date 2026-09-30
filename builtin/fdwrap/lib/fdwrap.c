// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/version.h>

#include "fdwrap.h"
#include "selinuxid.h"

/*
 * per file bridge state
 * ops lives here so every wrapper forwards into its own original file, the
 * table dies with the release fput runs, d_fsdata of the wrapper dentry keeps
 * the original path for the dname callback and for a reopen
 */
struct fdw_wrapper {
	struct file *orig;
	struct file_operations ops;
};

static struct fdw_config fdw_cfg;
static bool fdw_ready;
static atomic_t fdw_live = ATOMIC_INIT(0);

static struct file *(*fdw_fn_create_file)(const char *name,
					  const struct file_operations *fops,
					  void *priv, int flags,
					  const struct inode *context_inode);
static struct file *(*fdw_fn_dentry_open)(const struct path *path, int flags,
					  const struct cred *cred);
static char *(*fdw_fn_d_path)(const struct path *path, char *buffer,
			      int buflen);
static struct file *(*fdw_fn_fget)(unsigned int fd);
static void (*fdw_fn_fput)(struct file *file);
static void (*fdw_fn_fd_install)(unsigned int fd, struct file *file);
static int (*fdw_fn_get_unused_fd_flags)(unsigned int flags);
static void (*fdw_fn_put_unused_fd)(unsigned int fd);
static void (*fdw_fn_path_get)(const struct path *path);
static void (*fdw_fn_path_put)(const struct path *path);
static void (*fdw_fn_iput)(struct inode *inode);
static struct inode *(*fdw_fn_alloc_anon_inode)(struct super_block *sb);
static int (*fdw_fn_init_security_anon)(struct inode *inode,
					const struct qstr *name,
					const struct inode *context_inode);
static struct file *(*fdw_fn_alloc_file_pseudo)(struct inode *inode,
						struct vfsmount *mnt,
						const char *name, int flags,
						const struct file_operations *fops);
static struct vfsmount *(*fdw_fn_mntget)(struct vfsmount *mnt);
static void (*fdw_fn_mntput)(struct vfsmount *mnt);
static long (*fdw_fn_read_nofault)(void *dst, const void *src, size_t size);
static struct vfsmount *fdw_legacy_mnt;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
static const struct cred *(*fdw_fn_override_creds)(const struct cred *cred);
static void (*fdw_fn_revert_creds)(const struct cred *cred);
#endif

static struct fdw_wrapper *fdw_wrapper_alloc(struct file *orig);
static void fdw_wrapper_put(struct fdw_wrapper *wrapper);
static int fdw_wrapper_release(struct inode *inode, struct file *filp);
static int fdw_wrapper_open(struct inode *inode, struct file *filp);
static int fdw_install_one(struct file *orig, const struct fdw_opts *opts);

static unsigned long __nocfi fdw_resolve(const char *name)
{
	return fdw_cfg.resolve(name);
}

static bool __nocfi fdw_read_kernel(const void *address, void *buffer,
				    size_t size)
{
	if (!fdw_fn_read_nofault) {
		return false;
	}
	return fdw_fn_read_nofault(buffer, address, size) == 0;
}

static struct file *__nocfi
fdw_call_create_file(const char *name, const struct file_operations *fops,
		     void *priv, int flags,
		     const struct inode *context_inode)
{
	return fdw_fn_create_file(name, fops, priv, flags, context_inode);
}

static struct file *__nocfi fdw_call_dentry_open(const struct path *path,
						 int flags,
						 const struct cred *cred)
{
	return fdw_fn_dentry_open(path, flags, cred);
}

static char *__nocfi fdw_call_d_path(const struct path *path, char *buffer,
				     int buflen)
{
	return fdw_fn_d_path(path, buffer, buflen);
}

static struct file *__nocfi fdw_call_fget(unsigned int fd)
{
	return fdw_fn_fget(fd);
}

static void __nocfi fdw_call_fput(struct file *file)
{
	fdw_fn_fput(file);
}

static void __nocfi fdw_call_fd_install(unsigned int fd, struct file *file)
{
	fdw_fn_fd_install(fd, file);
}

static int __nocfi fdw_call_get_unused_fd_flags(unsigned int flags)
{
	return fdw_fn_get_unused_fd_flags(flags);
}

static void __nocfi fdw_call_put_unused_fd(unsigned int fd)
{
	fdw_fn_put_unused_fd(fd);
}

static void __nocfi fdw_call_path_get(const struct path *path)
{
	fdw_fn_path_get(path);
}

static void __nocfi fdw_call_path_put(const struct path *path)
{
	fdw_fn_path_put(path);
}

static void __nocfi fdw_call_iput(struct inode *inode)
{
	fdw_fn_iput(inode);
}

static struct inode *__nocfi fdw_call_alloc_anon_inode(struct super_block *sb)
{
	return fdw_fn_alloc_anon_inode(sb);
}

static int __nocfi
fdw_call_init_security_anon(struct inode *inode, const struct qstr *name,
			    const struct inode *context_inode)
{
	return fdw_fn_init_security_anon(inode, name, context_inode);
}

static struct file *__nocfi
fdw_call_alloc_file_pseudo(struct inode *inode, struct vfsmount *mnt,
			   const char *name, int flags,
			   const struct file_operations *fops)
{
	return fdw_fn_alloc_file_pseudo(inode, mnt, name, flags, fops);
}

static struct vfsmount *__nocfi fdw_call_mntget(struct vfsmount *mnt)
{
	return fdw_fn_mntget(mnt);
}

static void __nocfi fdw_call_mntput(struct vfsmount *mnt)
{
	fdw_fn_mntput(mnt);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
static const struct cred *__nocfi
fdw_call_override_creds(const struct cred *cred)
{
	return fdw_fn_override_creds(cred);
}

static void __nocfi fdw_call_revert_creds(const struct cred *cred)
{
	fdw_fn_revert_creds(cred);
}
#endif

/*
 * 6.18 made override_creds a static inline that only swaps the pointer, older
 * kernels export a function that also moves the cred reference
 */
static const struct cred *fdw_cred_override(void)
{
	if (!fdw_cfg.cred) {
		return NULL;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	return fdw_call_override_creds(fdw_cfg.cred);
#else
	return override_creds(fdw_cfg.cred);
#endif
}

static void fdw_cred_revert(const struct cred *old)
{
	if (!old) {
		return;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	fdw_call_revert_creds(old);
#else
	revert_creds(old);
#endif
}

static const struct cred *fdw_cred(void)
{
	if (fdw_cfg.cred) {
		return fdw_cfg.cred;
	}
	return current_cred();
}

/*
 * the bridge shows the path of the original file, screen and other tools break
 * on a tty whose /proc path is an anon inode name
 */
static char *fdw_dentry_dname(struct dentry *dentry, char *buffer, int buflen)
{
	struct path *saved = dentry->d_fsdata;

	return fdw_call_d_path(saved, buffer, buflen);
}

static void fdw_dentry_release(struct dentry *dentry)
{
	struct path *saved = dentry->d_fsdata;

	fdw_call_path_put(saved);
	kfree(saved);
}

static const struct dentry_operations fdw_dentry_ops = {
	.d_dname = fdw_dentry_dname,
	.d_release = fdw_dentry_release,
};

static struct file *fdw_wrapper_orig(struct file *filp)
{
	struct fdw_wrapper *wrapper = filp->private_data;

	return wrapper->orig;
}

static loff_t fdw_wrapper_llseek(struct file *filp, loff_t offset, int whence)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->llseek(orig, offset, whence);
}

static ssize_t fdw_wrapper_read(struct file *filp, char __user *buffer,
				size_t count, loff_t *offset)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->read(orig, buffer, count, offset);
}

static ssize_t fdw_wrapper_write(struct file *filp, const char __user *buffer,
				 size_t count, loff_t *offset)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->write(orig, buffer, count, offset);
}

static ssize_t fdw_wrapper_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *orig = fdw_wrapper_orig(iocb->ki_filp);

	iocb->ki_filp = orig;
	return orig->f_op->read_iter(iocb, iter);
}

static ssize_t fdw_wrapper_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *orig = fdw_wrapper_orig(iocb->ki_filp);

	iocb->ki_filp = orig;
	return orig->f_op->write_iter(iocb, iter);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static int fdw_wrapper_iopoll(struct kiocb *iocb, struct io_comp_batch *batch,
			      unsigned int flags)
{
	struct file *orig = fdw_wrapper_orig(iocb->ki_filp);

	iocb->ki_filp = orig;
	return orig->f_op->iopoll(iocb, batch, flags);
}
#else
static int fdw_wrapper_iopoll(struct kiocb *iocb, bool spin)
{
	struct file *orig = fdw_wrapper_orig(iocb->ki_filp);

	iocb->ki_filp = orig;
	return orig->f_op->iopoll(iocb, spin);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
static int fdw_wrapper_iterate(struct file *filp, struct dir_context *ctx)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->iterate(orig, ctx);
}
#endif

static int fdw_wrapper_iterate_shared(struct file *filp,
				      struct dir_context *ctx)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->iterate_shared(orig, ctx);
}

static __poll_t fdw_wrapper_poll(struct file *filp,
				 struct poll_table_struct *pts)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->poll(orig, pts);
}

static long fdw_wrapper_unlocked_ioctl(struct file *filp, unsigned int cmd,
				       unsigned long arg)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->unlocked_ioctl(orig, cmd, arg);
}

static long fdw_wrapper_compat_ioctl(struct file *filp, unsigned int cmd,
				     unsigned long arg)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->compat_ioctl(orig, cmd, arg);
}

/*
 * stacked call, a driver hangs its state off the file it is given, so the vma
 * file moves to the original for the call and the vma reference moves with it
 * every caller from 5.10 to 6.18 releases the vma file on failure and keeps
 * it on success, so a failure puts the wrapper back and drops the new
 * reference while a success drops the wrapper one
 */
static int fdw_wrapper_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct file *orig = fdw_wrapper_orig(filp);
	int ret;

	vma->vm_file = get_file(orig);
	ret = orig->f_op->mmap(orig, vma);
	if (ret) {
		vma->vm_file = filp;
		fdw_call_fput(orig);
	} else {
		fdw_call_fput(filp);
	}
	return ret;
}

static int fdw_wrapper_flush(struct file *filp, fl_owner_t id)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->flush(orig, id);
}

static int fdw_wrapper_fsync(struct file *filp, loff_t start, loff_t end,
			     int datasync)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->fsync(orig, start, end, datasync);
}

static int fdw_wrapper_fasync(int arg, struct file *filp, int mode)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->fasync(arg, orig, mode);
}

static int fdw_wrapper_lock(struct file *filp, int cmd, struct file_lock *fl)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->lock(orig, cmd, fl);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
static ssize_t fdw_wrapper_sendpage(struct file *filp, struct page *page,
				    int offset, size_t count, loff_t *pos,
				    int more)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->sendpage(orig, page, offset, count, pos, more);
}
#endif

static unsigned long fdw_wrapper_get_unmapped_area(struct file *filp,
						   unsigned long addr,
						   unsigned long len,
						   unsigned long pgoff,
						   unsigned long flags)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->get_unmapped_area(orig, addr, len, pgoff, flags);
}

static int fdw_wrapper_flock(struct file *filp, int cmd, struct file_lock *fl)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->flock(orig, cmd, fl);
}

static ssize_t fdw_wrapper_splice_write(struct pipe_inode_info *pipe,
					struct file *filp, loff_t *pos,
					size_t len, unsigned int flags)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->splice_write(pipe, orig, pos, len, flags);
}

static ssize_t fdw_wrapper_splice_read(struct file *filp, loff_t *pos,
				       struct pipe_inode_info *pipe,
				       size_t len, unsigned int flags)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->splice_read(orig, pos, pipe, len, flags);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static void fdw_wrapper_splice_eof(struct file *filp)
{
	struct file *orig = fdw_wrapper_orig(filp);

	orig->f_op->splice_eof(orig);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static int fdw_wrapper_setlease(struct file *filp, int arg,
				struct file_lease **lease, void **priv)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->setlease(orig, arg, lease, priv);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int fdw_wrapper_setlease(struct file *filp, int arg,
				struct file_lock **lock, void **priv)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->setlease(orig, arg, lock, priv);
}
#else
static int fdw_wrapper_setlease(struct file *filp, long arg,
				struct file_lock **lock, void **priv)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->setlease(orig, arg, lock, priv);
}
#endif

static long fdw_wrapper_fallocate(struct file *filp, int mode, loff_t offset,
				  loff_t len)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->fallocate(orig, mode, offset, len);
}

static void fdw_wrapper_show_fdinfo(struct seq_file *m, struct file *filp)
{
	struct file *orig = fdw_wrapper_orig(filp);

	orig->f_op->show_fdinfo(m, orig);
}

static ssize_t fdw_wrapper_copy_file_range(struct file *file_in, loff_t pos_in,
					   struct file *file_out,
					   loff_t pos_out, size_t len,
					   unsigned int flags)
{
	struct file *orig = fdw_wrapper_orig(file_out);

	return orig->f_op->copy_file_range(file_in, pos_in, orig, pos_out, len,
					   flags);
}

/*
 * REMAP_FILE_DEDUP runs the check on file_out, everything else on file_in
 */
static loff_t fdw_wrapper_remap_file_range(struct file *file_in, loff_t pos_in,
					   struct file *file_out,
					   loff_t pos_out, loff_t len,
					   unsigned int remap_flags)
{
	struct file *orig;
	struct file *other;

	if (remap_flags & REMAP_FILE_DEDUP) {
		orig = fdw_wrapper_orig(file_out);
		other = file_in;
	} else {
		orig = fdw_wrapper_orig(file_in);
		other = file_out;
	}
	return orig->f_op->remap_file_range(orig, pos_in, other, pos_out, len,
					    remap_flags);
}

static int fdw_wrapper_fadvise(struct file *filp, loff_t offset, loff_t len,
			       int advice)
{
	struct file *orig = fdw_wrapper_orig(filp);

	return orig->f_op->fadvise(orig, offset, len, advice);
}

/*
 * the core fops_put runs after this release and would read the owner out of a
 * table that is already gone, so the reference moves here and the file pointer
 * is cleared to make the core put a no op
 * the owner is read first and put last, the table is freed in between
 */
static int fdw_wrapper_release(struct inode *inode, struct file *filp)
{
	struct fdw_wrapper *wrapper = filp->private_data;
	struct module *owner = filp->f_op->owner;

	filp->f_op = NULL;
	filp->private_data = NULL;
	atomic_dec(&fdw_live);
	fdw_wrapper_put(wrapper);
	module_put(owner);
	return 0;
}

static const struct file_operations fdw_inode_ops = {
	.owner = THIS_MODULE,
	.open = fdw_wrapper_open,
};

/*
 * a reopen through /proc/<pid>/fd lands on the private inode, the vfs builds a
 * fresh file on it and this open rebuilds the bridge for that file
 * the flags and the credential are the ones of the opener
 */
static int fdw_wrapper_open(struct inode *inode, struct file *filp)
{
	struct path *saved = filp->f_path.dentry->d_fsdata;
	struct fdw_wrapper *wrapper;
	const struct file_operations *fops;
	struct file *orig;

	if (!saved) {
		return -ENODEV;
	}
	orig = fdw_call_dentry_open(saved, filp->f_flags, fdw_cred());
	if (IS_ERR(orig)) {
		return PTR_ERR(orig);
	}
	wrapper = fdw_wrapper_alloc(orig);
	if (IS_ERR(wrapper)) {
		fdw_call_fput(orig);
		return PTR_ERR(wrapper);
	}
	fops = fops_get(&wrapper->ops);
	if (!fops) {
		fdw_call_fput(orig);
		fdw_wrapper_put(wrapper);
		return -ENOENT;
	}
	filp->private_data = wrapper;
	replace_fops(filp, fops);
	atomic_inc(&fdw_live);
	return 0;
}

static void fdw_wrapper_ops_build(struct fdw_wrapper *wrapper)
{
	const struct file_operations *src = wrapper->orig->f_op;

	wrapper->ops.owner = THIS_MODULE;
	wrapper->ops.llseek = src->llseek ? fdw_wrapper_llseek : NULL;
	wrapper->ops.read = src->read ? fdw_wrapper_read : NULL;
	wrapper->ops.write = src->write ? fdw_wrapper_write : NULL;
	wrapper->ops.read_iter = src->read_iter ? fdw_wrapper_read_iter : NULL;
	wrapper->ops.write_iter = src->write_iter ? fdw_wrapper_write_iter : NULL;
	wrapper->ops.iopoll = src->iopoll ? fdw_wrapper_iopoll : NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	wrapper->ops.iterate = src->iterate ? fdw_wrapper_iterate : NULL;
#endif
	wrapper->ops.iterate_shared =
		src->iterate_shared ? fdw_wrapper_iterate_shared : NULL;
	wrapper->ops.poll = src->poll ? fdw_wrapper_poll : NULL;
	wrapper->ops.unlocked_ioctl =
		src->unlocked_ioctl ? fdw_wrapper_unlocked_ioctl : NULL;
	wrapper->ops.compat_ioctl =
		src->compat_ioctl ? fdw_wrapper_compat_ioctl : NULL;
	wrapper->ops.mmap = src->mmap ? fdw_wrapper_mmap : NULL;
	/*
	 * mmap_prepare stays NULL, struct vm_area_desc keeps file const so the
	 * callback cannot be handed the original file and would read the
	 * private inode mapping, a 6.18 file that only offers it answers
	 * ENODEV on mmap
	 */
	wrapper->ops.flush = src->flush ? fdw_wrapper_flush : NULL;
	wrapper->ops.release = fdw_wrapper_release;
	wrapper->ops.fsync = src->fsync ? fdw_wrapper_fsync : NULL;
	wrapper->ops.fasync = src->fasync ? fdw_wrapper_fasync : NULL;
	wrapper->ops.lock = src->lock ? fdw_wrapper_lock : NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	wrapper->ops.sendpage = src->sendpage ? fdw_wrapper_sendpage : NULL;
#endif
	wrapper->ops.get_unmapped_area =
		src->get_unmapped_area ? fdw_wrapper_get_unmapped_area : NULL;
	/* check_flags reads no file, the pointer is shared as it is */
	wrapper->ops.check_flags = src->check_flags;
	wrapper->ops.flock = src->flock ? fdw_wrapper_flock : NULL;
	wrapper->ops.splice_write =
		src->splice_write ? fdw_wrapper_splice_write : NULL;
	wrapper->ops.splice_read =
		src->splice_read ? fdw_wrapper_splice_read : NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	wrapper->ops.splice_eof =
		src->splice_eof ? fdw_wrapper_splice_eof : NULL;
#endif
	wrapper->ops.setlease = src->setlease ? fdw_wrapper_setlease : NULL;
	wrapper->ops.fallocate = src->fallocate ? fdw_wrapper_fallocate : NULL;
	wrapper->ops.show_fdinfo =
		src->show_fdinfo ? fdw_wrapper_show_fdinfo : NULL;
	wrapper->ops.copy_file_range =
		src->copy_file_range ? fdw_wrapper_copy_file_range : NULL;
	wrapper->ops.remap_file_range =
		src->remap_file_range ? fdw_wrapper_remap_file_range : NULL;
	wrapper->ops.fadvise = src->fadvise ? fdw_wrapper_fadvise : NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	wrapper->ops.fop_flags = src->fop_flags;
#else
	wrapper->ops.mmap_supported_flags = src->mmap_supported_flags;
#endif
	/*
	 * uring_cmd and uring_cmd_iopoll stay NULL, both carry the file inside
	 * struct io_uring_cmd and the wrapper cannot put the original there
	 */
}

static struct fdw_wrapper *fdw_wrapper_alloc(struct file *orig)
{
	struct fdw_wrapper *wrapper;

	wrapper = kcalloc(1, sizeof(*wrapper), GFP_KERNEL);
	if (!wrapper) {
		return ERR_PTR(-ENOMEM);
	}
	get_file(orig);
	wrapper->orig = orig;
	fdw_wrapper_ops_build(wrapper);
	return wrapper;
}

static void fdw_wrapper_put(struct fdw_wrapper *wrapper)
{
	if (!wrapper) {
		return;
	}
	fdw_call_fput(wrapper->orig);
	kfree(wrapper);
}

static struct file *fdw_create_legacy(const char *name,
				      const struct file_operations *fops,
				      void *priv, int flags,
				      const struct inode *context_inode)
{
	const struct qstr qname = QSTR_INIT(name, strlen(name));
	struct inode *inode;
	struct file *file;
	int error;

	if (fops->owner && !try_module_get(fops->owner)) {
		return ERR_PTR(-ENOENT);
	}
	inode = fdw_call_alloc_anon_inode(fdw_legacy_mnt->mnt_sb);
	if (IS_ERR(inode)) {
		file = ERR_CAST(inode);
		goto out_owner;
	}
	inode->i_flags &= ~S_PRIVATE;
	error = fdw_call_init_security_anon(inode, &qname, context_inode);
	if (error) {
		fdw_call_iput(inode);
		file = ERR_PTR(error);
		goto out_owner;
	}
	file = fdw_call_alloc_file_pseudo(inode, fdw_legacy_mnt, name,
					  flags & (O_ACCMODE | O_NONBLOCK),
					  fops);
	if (IS_ERR(file)) {
		fdw_call_iput(inode);
		goto out_owner;
	}
	file->f_mapping = inode->i_mapping;
	file->private_data = priv;
	return file;
out_owner:
	if (fops->owner) {
		module_put(fops->owner);
	}
	return file;
}

/*
 * two anon inode providers, anon_inode_create_getfile from 6.8 on and
 * anon_inode_getfile_secure between 5.16 and 6.7 share one prototype, older
 * kernels have neither and get the construction the kernel uses there
 */
static struct file *fdw_create_file(const char *name,
				    const struct file_operations *fops,
				    void *priv, int flags,
				    const struct inode *context_inode)
{
	if (fdw_fn_create_file) {
		return fdw_call_create_file(name, fops, priv, flags,
					    context_inode);
	}
	return fdw_create_legacy(name, fops, priv, flags, context_inode);
}

static int fdw_inode_label(struct inode *inode, const struct fdw_opts *opts)
{
	const char *context = NULL;
	u32 sid = 0;
	int error;

	if (opts) {
		sid = opts->sid;
		context = opts->context;
	}
	if (!sid && !context && !fdw_cfg.unlabeled) {
		sid = fdw_cfg.sid;
		context = fdw_cfg.context;
	}
	if (sid) {
		error = sid_inode_set_sid(inode, sid);
	} else if (context) {
		error = sid_inode_set_domain(inode, context);
	} else if (fdw_cfg.unlabeled) {
		error = 0;
	} else {
		error = sid_inode_set_file(inode);
	}
	/* no lsm blob means no selinux, there is no label to write */
	if (error == -ENODATA) {
		return 0;
	}
	return error;
}

static umode_t fdw_inode_mode(struct file *orig, const struct fdw_opts *opts)
{
	if (opts && opts->mode) {
		return opts->mode;
	}
	if (fdw_cfg.mode) {
		return fdw_cfg.mode;
	}
	return file_inode(orig)->i_mode;
}

/*
 * the file is not published yet, so inode and dentry are edited in place
 * libc stdio reads the mode out of fstat to pick its buffer type
 */
static int fdw_wrapper_apply(struct file *wrapper_file, struct file *orig,
			     const struct fdw_opts *opts)
{
	struct inode *inode = file_inode(wrapper_file);

	inode->i_mode = fdw_inode_mode(orig, opts);
	inode->i_fop = &fdw_inode_ops;
	return fdw_inode_label(inode, opts);
}

static struct file *fdw_wrapper_file_new(struct fdw_wrapper *wrapper,
					 const struct fdw_opts *opts, int flags)
{
	const char *name = opts && opts->name ? opts->name : fdw_cfg.name;
	const struct cred *old_cred;
	struct file *file;

	old_cred = fdw_cred_override();
	file = fdw_create_file(name, &wrapper->ops, wrapper, flags, NULL);
	fdw_cred_revert(old_cred);
	if (IS_ERR(file)) {
		return file;
	}
	atomic_inc(&fdw_live);
	return file;
}

static int fdw_install_one(struct file *orig, const struct fdw_opts *opts)
{
	struct fdw_wrapper *wrapper;
	struct file *wrapper_file;
	struct path *saved;
	int out_fd;
	int flags;
	int ret;

	/* the dentry of a wrapper already carries the bridge state */
	if (orig->f_path.dentry->d_op == &fdw_dentry_ops) {
		return -EINVAL;
	}
	flags = opts && opts->flags ? opts->flags : orig->f_flags;

	out_fd = fdw_call_get_unused_fd_flags(O_CLOEXEC);
	if (out_fd < 0) {
		return out_fd;
	}
	wrapper = fdw_wrapper_alloc(orig);
	if (IS_ERR(wrapper)) {
		ret = PTR_ERR(wrapper);
		goto out_fd;
	}
	wrapper_file = fdw_wrapper_file_new(wrapper, opts, flags);
	if (IS_ERR(wrapper_file)) {
		ret = PTR_ERR(wrapper_file);
		goto out_wrapper;
	}
	ret = fdw_wrapper_apply(wrapper_file, orig, opts);
	if (ret) {
		goto out_file;
	}
	saved = kmalloc(sizeof(*saved), GFP_KERNEL);
	if (!saved) {
		ret = -ENOMEM;
		goto out_file;
	}
	*saved = orig->f_path;
	fdw_call_path_get(saved);
	wrapper_file->f_path.dentry->d_fsdata = saved;
	wrapper_file->f_path.dentry->d_op = &fdw_dentry_ops;

	fdw_call_fd_install(out_fd, wrapper_file);
	return out_fd;

out_file:
	/* the release of this file frees the wrapper */
	fdw_call_fput(wrapper_file);
	goto out_fd;
out_wrapper:
	fdw_wrapper_put(wrapper);
out_fd:
	fdw_call_put_unused_fd(out_fd);
	return ret;
}

int fdw_install(int fd, const struct fdw_opts *opts)
{
	struct file *orig;
	int ret;

	if (!fdw_ready) {
		return -ENODEV;
	}
	orig = fdw_call_fget(fd);
	if (!orig) {
		return -EBADF;
	}
	ret = fdw_install_one(orig, opts);
	fdw_call_fput(orig);
	return ret;
}

int fdw_install_file(struct file *file, const struct fdw_opts *opts)
{
	if (!fdw_ready) {
		return -ENODEV;
	}
	if (!file) {
		return -EINVAL;
	}
	return fdw_install_one(file, opts);
}

static int fdw_legacy_init(void)
{
	unsigned long address;
	struct vfsmount *mnt = NULL;

	fdw_fn_alloc_anon_inode = (void *)fdw_resolve("alloc_anon_inode");
	fdw_fn_init_security_anon =
		(void *)fdw_resolve("security_inode_init_security_anon");
	fdw_fn_alloc_file_pseudo = (void *)fdw_resolve("alloc_file_pseudo");
	fdw_fn_iput = (void *)fdw_resolve("iput");
	fdw_fn_mntget = (void *)fdw_resolve("mntget");
	fdw_fn_mntput = (void *)fdw_resolve("mntput");
	fdw_fn_read_nofault = (void *)fdw_resolve("copy_from_kernel_nofault");
	address = fdw_resolve("anon_inode_mnt");
	if (!fdw_fn_alloc_anon_inode || !fdw_fn_init_security_anon ||
	    !fdw_fn_alloc_file_pseudo || !fdw_fn_iput || !fdw_fn_mntget ||
	    !fdw_fn_mntput || !fdw_fn_read_nofault || !address) {
		return -ENOSYS;
	}
	/*
	 * the mount pointer is a static symbol, it is read through
	 * copy_from_kernel_nofault and a reference is taken so that fdw_exit
	 * owns everything the library hands out
	 */
	if (!fdw_read_kernel((const void *)address, &mnt, sizeof(mnt)) ||
	    !mnt) {
		return -EFAULT;
	}
	fdw_legacy_mnt = fdw_call_mntget(mnt);
	return 0;
}

static void fdw_reset(void)
{
	if (fdw_legacy_mnt) {
		fdw_call_mntput(fdw_legacy_mnt);
	}
	memset(&fdw_cfg, 0, sizeof(fdw_cfg));
	fdw_ready = false;
	fdw_legacy_mnt = NULL;
	fdw_fn_create_file = NULL;
	fdw_fn_dentry_open = NULL;
	fdw_fn_d_path = NULL;
	fdw_fn_fget = NULL;
	fdw_fn_fput = NULL;
	fdw_fn_fd_install = NULL;
	fdw_fn_get_unused_fd_flags = NULL;
	fdw_fn_put_unused_fd = NULL;
	fdw_fn_path_get = NULL;
	fdw_fn_path_put = NULL;
	fdw_fn_iput = NULL;
	fdw_fn_alloc_anon_inode = NULL;
	fdw_fn_init_security_anon = NULL;
	fdw_fn_alloc_file_pseudo = NULL;
	fdw_fn_mntget = NULL;
	fdw_fn_mntput = NULL;
	fdw_fn_read_nofault = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	fdw_fn_override_creds = NULL;
	fdw_fn_revert_creds = NULL;
#endif
}

int fdw_init(const struct fdw_config *config)
{
	int error;

	if (!config || !config->resolve) {
		return -EINVAL;
	}
	if (fdw_cfg.resolve) {
		return -EALREADY;
	}
	fdw_cfg = *config;
	if (!fdw_cfg.name) {
		fdw_cfg.name = FDW_NAME_DEFAULT;
	}

	fdw_fn_create_file = (void *)fdw_resolve("anon_inode_create_getfile");
	if (!fdw_fn_create_file) {
		fdw_fn_create_file =
			(void *)fdw_resolve("anon_inode_getfile_secure");
	}
	fdw_fn_dentry_open = (void *)fdw_resolve("dentry_open");
	fdw_fn_d_path = (void *)fdw_resolve("d_path");
	fdw_fn_fget = (void *)fdw_resolve("fget");
	fdw_fn_fput = (void *)fdw_resolve("fput");
	fdw_fn_fd_install = (void *)fdw_resolve("fd_install");
	fdw_fn_get_unused_fd_flags =
		(void *)fdw_resolve("get_unused_fd_flags");
	fdw_fn_put_unused_fd = (void *)fdw_resolve("put_unused_fd");
	fdw_fn_path_get = (void *)fdw_resolve("path_get");
	fdw_fn_path_put = (void *)fdw_resolve("path_put");
	if (!fdw_fn_dentry_open || !fdw_fn_d_path || !fdw_fn_fget ||
	    !fdw_fn_fput || !fdw_fn_fd_install ||
	    !fdw_fn_get_unused_fd_flags || !fdw_fn_put_unused_fd ||
	    !fdw_fn_path_get || !fdw_fn_path_put) {
		fdw_reset();
		return -ENOSYS;
	}

	if (!fdw_fn_create_file) {
		error = fdw_legacy_init();
		if (error) {
			fdw_reset();
			return error;
		}
	}

	if (fdw_cfg.cred) {
		/* 6.18 has both as static inlines, nothing to resolve there */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
		fdw_fn_override_creds = (void *)fdw_resolve("override_creds");
		fdw_fn_revert_creds = (void *)fdw_resolve("revert_creds");
		if (!fdw_fn_override_creds || !fdw_fn_revert_creds) {
			fdw_reset();
			return -ENOSYS;
		}
#endif
	}

	fdw_ready = true;
	return 0;
}

void fdw_exit(void)
{
	int live;

	if (!fdw_cfg.resolve) {
		return;
	}
	live = atomic_read(&fdw_live);
	if (live) {
		pr_warn("fdwrap: %d wrapper file still open\n", live);
	}
	fdw_reset();
}

int fdw_live_count(void)
{
	return atomic_read(&fdw_live);
}
