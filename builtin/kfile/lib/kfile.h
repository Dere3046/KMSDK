// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef KFILE_H
#define KFILE_H

#include <linux/types.h>

struct file;

/* hk_init with a resolve wrapper must run before kfile_init */
int kfile_init(void);
void kfile_exit(void);

ssize_t kfile_read(const char *path, void *buf, size_t len);
ssize_t kfile_write(const char *path, const void *buf, size_t len,
		    umode_t mode);
int kfile_exist(const char *path);

struct kfile_handle;

/* nonotify opens with __FMODE_NONOTIFY so no fsnotify event is raised */
struct kfile_handle *kfile_open(const char *path, bool nonotify);
void kfile_close(struct kfile_handle *h);
loff_t kfile_size(struct kfile_handle *h);
ssize_t kfile_pread(struct kfile_handle *h, void *buf, size_t len, loff_t pos);

/* expose the underlying file for iterate_dir style callers, invalid after
 * kfile_close and must not be closed by the caller
 */
struct file *kfile_filp(struct kfile_handle *h);

/*
 * append extra content to a target file, the hook channel and the target
 * policy stay with the consumer
 *
 * mechanism only: the target file object keeps its own file_operations, a
 * copy with read and read_iter replaced is installed on that file object
 * alone, the inode, the page cache and every other file object are untouched
 * the read position decides what is appended, a reader sees the original
 * bytes, then the payload, then end of file, so the byte count matches the
 * size that kfile_rc_stat_size reports
 * targets must be regular files
 *
 * prerequisite: kfile_init ran, kfile_rc_init took the cfg, kfile_rc_start
 * installed the channel, then the channel read hook calls kfile_rc_proxy or
 * kfile_rc_proxy_fd and the channel fstat hook calls kfile_rc_stat_size
 *
 * hook_add installs the consumer hook channel, NULL skips the call
 *   a non zero return is handed back by kfile_rc_start and nothing stays
 *   installed
 * hook_remove removes it, NULL skips the call, kfile_rc_stop calls it last
 *   after every proxy is restored
 * match_file decides if this file object is a target, required
 *   runs in the syscall context of the hooked process on every read of
 *   every file, keep it cheap and free of sleeps, the file is live for the
 *   duration of the call
 * content_get hands the payload over once per proxied file, required
 *   len receives the payload length, a NULL return or a zero length refuses
 *   the proxy
 *   the payload must stay valid until content_put returns for it, or until
 *   kfile_rc_stop returns when content_put is NULL
 *   read it with kfile_open and kfile_pread, those already run with full
 *   credentials
 * content_put releases a payload, NULL skips the call
 * log receives a NUL terminated line naming the library and the value, it
 *   ends with a newline and is valid for the call only, NULL skips the call
 * priv goes back to every callback
 *
 * the payload length is taken once, the fake size and the appended bytes
 * then come from the same number
 */
struct kfile_rc_cfg {
	int (*hook_add)(void *priv);
	void (*hook_remove)(void *priv);
	bool (*match_file)(struct file *file, void *priv);
	const char *(*content_get)(size_t *len, void *priv);
	void (*content_put)(const char *content, size_t len, void *priv);
	void (*log)(const char *message, void *priv);
	void *priv;
};

/* 0 on success, -EINVAL when a required callback is missing, -EALREADY when
 * kfile_rc_init ran before without kfile_rc_exit
 */
int kfile_rc_init(const struct kfile_rc_cfg *cfg);

/* stops first, then drops the cfg, kfile_exit calls it */
void kfile_rc_exit(void);

/* idempotent, a started library returns 0 without calling hook_add again
 * -ENODATA when kfile_rc_init never ran, otherwise the return of hook_add
 */
int kfile_rc_start(void);

/* idempotent, restores every proxy, releases every payload, then calls
 * hook_remove
 * the read side of the channel must be down before this call and no call
 * into the library may be in flight, a proxy serves reads through the file
 * object itself once it is installed
 * -ENODATA when kfile_rc_init never ran, 0 otherwise
 */
int kfile_rc_stop(void);

/* read hook entry, called with the live struct file of the read
 * 1 the proxy was installed by this call
 * 0 not a target, or already proxied
 * negative refused and the file is untouched, -ENOSPC when four files are
 * already proxied
 */
int kfile_rc_proxy(struct file *file);

/* the same over fget of fd, a closed or negative fd gives 0 */
int kfile_rc_proxy_fd(int fd);

/* fstat hook entry, size holds the st_size the caller read out of the user
 * buffer, the payload length is added in place
 * 1 size was changed, 0 the file is not proxied and size is untouched
 */
int kfile_rc_stat_size(struct file *file, loff_t *size);

#endif
