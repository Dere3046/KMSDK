// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/fsnotify_backend.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/version.h>

#include "kfile.h"
#include "pkgwatch.h"

#define PW_PATH_MAX		384
#define PW_PKG_MAX		256
#define PW_LIST_MAX		(1024 * 1024)
#define PW_LIST_NAME		"packages.list"
#define PW_LIST_NAME_LEN	13
#define PW_APK_NAME		"base.apk"
#define PW_APK_NAME_LEN		8
#define PW_WATCH_MASK		(FS_CREATE | FS_MOVE | FS_EVENT_ON_CHILD)

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
#define PW_FILLDIR_RET		int
#define PW_FILLDIR_GO		0
#define PW_FILLDIR_STOP		(-EINVAL)
#else
#define PW_FILLDIR_RET		bool
#define PW_FILLDIR_GO		true
#define PW_FILLDIR_STOP		false
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
typedef struct fsnotify_group *(*pw_alloc_group_t)(const struct fsnotify_ops *,
						   int);
#else
typedef struct fsnotify_group *(*pw_alloc_group_t)(const struct fsnotify_ops *);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
typedef int (*pw_add_mark_t)(struct fsnotify_mark *, void *, unsigned int, int);
#else
typedef int (*pw_add_mark_t)(struct fsnotify_mark *, fsnotify_connp_t *,
			     unsigned int, int, __kernel_fsid_t *);
#endif

typedef void (*pw_put_group_t)(struct fsnotify_group *);
typedef void (*pw_init_mark_t)(struct fsnotify_mark *, struct fsnotify_group *);
typedef void (*pw_destroy_mark_t)(struct fsnotify_mark *,
				  struct fsnotify_group *);
typedef void (*pw_put_mark_t)(struct fsnotify_mark *);
typedef int (*pw_iterate_dir_t)(struct file *, struct dir_context *);

struct pw_uid {
	struct list_head list;
	u32 uid;
	char pkg[PW_PKG_MAX];
};

struct pw_path {
	struct list_head list;
	char dir[PW_PATH_MAX];
	int depth;
};

struct pw_seen {
	struct list_head list;
	u32 hash;
	bool exists;
};

struct pw_walk {
	struct list_head dirs;
	unsigned long magic;
	bool found;
	char apk[PW_PATH_MAX];
};

struct pw_dir_ctx {
	struct dir_context ctx;
	struct pw_walk *walk;
	const char *dir;
	int depth;
};

static struct pkgwatch_cfg pw_cfg;
static char *pw_list_path;
static char *pw_app_dir;
static bool pw_inited;
static LIST_HEAD(pw_uids);
static LIST_HEAD(pw_seen);
static u32 pw_manager_appid;
static bool pw_manager_valid;

static struct fsnotify_group *pw_group;
static struct fsnotify_mark *pw_mark;
static struct inode *pw_watch_inode;
static struct path pw_watch_path;

/*
 * fsnotify symbols are not in the GKI KMI list, so they are resolved at init
 * instead of being linked. Indirect calls across the CFI boundary must sit in
 * __nocfi functions, which is why every call below goes through a wrapper.
 */
static pw_alloc_group_t pw_fsnotify_alloc_group;
static pw_put_group_t pw_fsnotify_put_group;
static pw_init_mark_t pw_fsnotify_init_mark;
static pw_add_mark_t pw_fsnotify_add_mark;
static pw_destroy_mark_t pw_fsnotify_destroy_mark;
static pw_put_mark_t pw_fsnotify_put_mark;
static pw_iterate_dir_t pw_iterate_dir;

static u32 pw_hash(const char *s)
{
	u32 h = 0x811c9dc5;
	int i;

	for (i = 0; s[i]; i++) {
		h ^= (u8)s[i];
		h *= 0x01000193;
	}
	return h;
}

/* a path judged once as not the manager is remembered and not judged again */
static bool pw_seen_hit(const char *path)
{
	struct pw_seen *s;
	u32 hash = pw_hash(path);

	list_for_each_entry(s, &pw_seen, list) {
		if (s->hash == hash) {
			s->exists = true;
			return true;
		}
	}
	return false;
}

static void pw_seen_add(const char *path)
{
	struct pw_seen *s;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return;
	s->hash = pw_hash(path);
	s->exists = true;
	list_add_tail(&s->list, &pw_seen);
}

static void pw_seen_begin(void)
{
	struct pw_seen *s;

	list_for_each_entry(s, &pw_seen, list)
		s->exists = false;
}

static void pw_seen_sweep(void)
{
	struct pw_seen *s, *n;

	list_for_each_entry_safe(s, n, &pw_seen, list) {
		if (!s->exists) {
			list_del(&s->list);
			kfree(s);
		}
	}
}

static void pw_seen_clear(void)
{
	struct pw_seen *s, *n;

	list_for_each_entry_safe(s, n, &pw_seen, list) {
		list_del(&s->list);
		kfree(s);
	}
}

static void pw_uids_free(struct list_head *head)
{
	struct pw_uid *u, *n;

	list_for_each_entry_safe(u, n, head, list) {
		list_del(&u->list);
		kfree(u);
	}
}

static bool pw_uid_have(u32 uid)
{
	struct pw_uid *u;

	list_for_each_entry(u, &pw_uids, list) {
		if (u->uid == uid)
			return true;
	}
	return false;
}

static int pw_uid_lookup(const char *pkg, u32 *uid)
{
	struct pw_uid *u;

	list_for_each_entry(u, &pw_uids, list) {
		if (!strcmp(u->pkg, pkg)) {
			*uid = u->uid;
			return 0;
		}
	}
	return -ENOENT;
}

/*
 * apk path layout is /data/app/<random>/<package name> then a hyphen and a
 * random suffix, so the first hyphen after the second last slash ends the name.
 */
static int pw_pkg_from_path(const char *apk_path, char *out, size_t out_len)
{
	const char *last_slash = NULL;
	const char *second_last_slash = NULL;
	const char *hyphen;
	size_t len, pkg_len;
	int i;

	if (!apk_path || !out || !out_len)
		return -EINVAL;

	len = strlen(apk_path);
	if (!len || len > INT_MAX)
		return -EINVAL;

	for (i = (int)len - 1; i >= 0; i--) {
		if (apk_path[i] != '/')
			continue;
		if (!last_slash) {
			last_slash = &apk_path[i];
			continue;
		}
		second_last_slash = &apk_path[i];
		break;
	}
	if (!last_slash || !second_last_slash)
		return -EINVAL;

	hyphen = strchr(second_last_slash, '-');
	if (!hyphen || hyphen > last_slash)
		return -EINVAL;

	pkg_len = (size_t)(hyphen - second_last_slash - 1);
	if (!pkg_len)
		return -EINVAL;
	if (pkg_len + 1 > out_len)
		return -E2BIG;

	memcpy(out, second_last_slash + 1, pkg_len);
	out[pkg_len] = '\0';
	return 0;
}

static int pw_uid_of_apk(const char *apk_path, u32 *uid)
{
	char pkg[PW_PKG_MAX];
	int ret;

	ret = pw_pkg_from_path(apk_path, pkg, sizeof(pkg));
	if (ret)
		return ret;
	return pw_uid_lookup(pkg, uid);
}

static PW_FILLDIR_RET pw_actor(struct dir_context *ctx, const char *name,
			       int namelen, loff_t off, u64 ino,
			       unsigned int d_type)
{
	struct pw_dir_ctx *dc = container_of(ctx, struct pw_dir_ctx, ctx);
	struct pw_walk *w = dc->walk;
	char path[PW_PATH_MAX];

	if (w->found)
		return PW_FILLDIR_STOP;

	if ((namelen == 1 && name[0] == '.') ||
	    (namelen == 2 && name[0] == '.' && name[1] == '.'))
		return PW_FILLDIR_GO;

	if (namelen <= 0 ||
	    scnprintf(path, PW_PATH_MAX, "%s/%.*s", dc->dir, namelen,
		      name) >= PW_PATH_MAX)
		return PW_FILLDIR_GO;

	if (d_type == DT_DIR) {
		struct pw_path *p;

		if (dc->depth <= 0)
			return PW_FILLDIR_GO;
		if (namelen >= 4 && !strncmp(name, "vmdl", 4))
			return PW_FILLDIR_GO;
		p = kzalloc(sizeof(*p), GFP_KERNEL);
		if (!p)
			return PW_FILLDIR_GO;
		strscpy(p->dir, path, PW_PATH_MAX);
		p->depth = dc->depth - 1;
		list_add_tail(&p->list, &w->dirs);
		return PW_FILLDIR_GO;
	}

	if (namelen != PW_APK_NAME_LEN ||
	    strncmp(name, PW_APK_NAME, PW_APK_NAME_LEN))
		return PW_FILLDIR_GO;
	if (pw_seen_hit(path))
		return PW_FILLDIR_GO;
	if (!pw_cfg.is_manager(path, pw_cfg.priv)) {
		pw_seen_add(path);
		return PW_FILLDIR_GO;
	}

	strscpy(w->apk, path, PW_PATH_MAX);
	pw_seen_clear();
	w->found = true;
	return PW_FILLDIR_STOP;
}

/* only directories on the same filesystem as app_dir pass, this blocks spoofing */
static bool pw_dir_ok(struct kfile_handle *h, struct pw_walk *w)
{
	struct file *fp = kfile_filp(h);
	unsigned long magic;

	if (!fp)
		return false;
	magic = file_inode(fp)->i_sb->s_magic;
	if (!magic)
		return false;
	if (!w->magic) {
		w->magic = magic;
		return true;
	}
	return magic == w->magic;
}

static __nocfi int pw_scan(struct pw_walk *w)
{
	struct pw_path first;

	memset(w, 0, sizeof(*w));
	INIT_LIST_HEAD(&w->dirs);

	if (strlen(pw_app_dir) >= PW_PATH_MAX)
		return -E2BIG;

	pw_seen_begin();
	strscpy(first.dir, pw_app_dir, PW_PATH_MAX);
	first.depth = pw_cfg.max_depth;
	list_add_tail(&first.list, &w->dirs);

	/* the actor appends sub directories to the tail, so take the head here */
	while (!list_empty(&w->dirs)) {
		struct pw_path *p = list_first_entry(&w->dirs, struct pw_path,
						     list);
		struct kfile_handle *h;
		struct pw_dir_ctx dc;

		if (!w->found) {
			h = kfile_open(p->dir, true);
			if (!IS_ERR(h)) {
				if (pw_dir_ok(h, w)) {
					memset(&dc, 0, sizeof(dc));
					dc.ctx.actor = pw_actor;
					dc.walk = w;
					dc.dir = p->dir;
					dc.depth = p->depth;
					pw_iterate_dir(kfile_filp(h), &dc.ctx);
				}
				kfile_close(h);
			}
		}

		list_del(&p->list);
		if (p != &first)
			kfree(p);
	}

	pw_seen_sweep();
	return 0;
}

static int pw_uids_parse(char *buf, struct list_head *out)
{
	char *line;

	while ((line = strsep(&buf, "\n")) != NULL) {
		struct pw_uid *u;
		char *tmp = line;
		char *pkg = strsep(&tmp, " ");
		char *uid = strsep(&tmp, " ");
		u32 v;

		if (!pkg || !*pkg || !uid || !*uid)
			continue;
		if (kstrtou32(uid, 10, &v))
			continue;
		u = kzalloc(sizeof(*u), GFP_KERNEL);
		if (!u)
			return -ENOMEM;
		u->uid = v;
		strscpy(u->pkg, pkg, PW_PKG_MAX);
		list_add_tail(&u->list, out);
	}
	return 0;
}

static int pw_uids_load(struct list_head *out)
{
	struct kfile_handle *h;
	char *buf;
	loff_t size;
	ssize_t n;
	int ret;

	h = kfile_open(pw_list_path, true);
	if (IS_ERR(h))
		return PTR_ERR(h);

	size = kfile_size(h);
	if (size <= 0) {
		ret = -EINVAL;
		goto out;
	}
	if (size > PW_LIST_MAX) {
		ret = -E2BIG;
		goto out;
	}

	buf = kmalloc((size_t)size + 1, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	n = kfile_pread(h, buf, size, 0);
	if (n < 0) {
		ret = (int)n;
		kfree(buf);
		goto out;
	}
	if (n == 0) {
		ret = -EIO;
		kfree(buf);
		goto out;
	}

	buf[n] = '\0';
	ret = pw_uids_parse(buf, out);
	kfree(buf);
out:
	kfile_close(h);
	return ret;
}

int pkgwatch_refresh(void)
{
	LIST_HEAD(loaded);
	struct pw_walk walk;
	u32 uid;
	int ret;

	if (!pw_inited)
		return -ENODATA;

	ret = pw_uids_load(&loaded);
	if (ret) {
		pw_uids_free(&loaded);
		return ret;
	}

	pw_uids_free(&pw_uids);
	list_splice_tail_init(&loaded, &pw_uids);

	if (pw_manager_valid && !pw_uid_have(pw_manager_appid))
		pw_manager_valid = false;

	if (pw_manager_valid)
		return 0;

	ret = pw_scan(&walk);
	if (ret || !walk.found)
		return ret;
	if (pw_uid_of_apk(walk.apk, &uid))
		return 0;

	pw_manager_appid = uid;
	pw_manager_valid = true;
	if (pw_cfg.on_manager)
		pw_cfg.on_manager(uid, walk.apk, pw_cfg.priv);
	return 0;
}

int pkgwatch_uid_of(const char *pkg, uid_t *uid)
{
	u32 v;
	int ret;

	if (!pkg || !uid)
		return -EINVAL;
	if (!pw_inited)
		return -ENODATA;

	ret = pw_uid_lookup(pkg, &v);
	if (ret)
		return ret;
	*uid = v;
	return 0;
}

int pkgwatch_prune(bool (*keep)(uid_t uid, const char *pkg, void *arg),
		   void *arg)
{
	struct pw_uid *u, *n;

	if (!pw_inited)
		return -ENODATA;
	if (!keep)
		return -EINVAL;

	list_for_each_entry_safe(u, n, &pw_uids, list) {
		if (!keep(u->uid, u->pkg, arg)) {
			list_del(&u->list);
			kfree(u);
		}
	}
	return 0;
}

static int pw_handle_inode_event(struct fsnotify_mark *mark, u32 mask,
				 struct inode *inode, struct inode *dir,
				 const struct qstr *file_name, u32 cookie)
{
	if (!file_name)
		return 0;
	if (mask & FS_ISDIR)
		return 0;
	if (file_name->len == PW_LIST_NAME_LEN &&
	    !memcmp(file_name->name, PW_LIST_NAME, PW_LIST_NAME_LEN))
		pkgwatch_refresh();
	return 0;
}

/* fsnotify_final_mark_destroy calls this on the last put, the mark came from
 * kzalloc in pw_watch_dir
 */
static void pw_free_mark(struct fsnotify_mark *mark)
{
	kfree(mark);
}

static const struct fsnotify_ops pw_fsnotify_ops = {
	.handle_inode_event = pw_handle_inode_event,
	.free_mark = pw_free_mark,
};

static __nocfi struct fsnotify_group *pw_group_alloc(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	return pw_fsnotify_alloc_group(&pw_fsnotify_ops, 0);
#else
	return pw_fsnotify_alloc_group(&pw_fsnotify_ops);
#endif
}

static __nocfi void pw_group_put(struct fsnotify_group *group)
{
	pw_fsnotify_put_group(group);
}

static __nocfi void pw_mark_init(struct fsnotify_mark *mark,
				 struct fsnotify_group *group)
{
	pw_fsnotify_init_mark(mark, group);
}

static __nocfi int pw_mark_add(struct fsnotify_mark *mark, struct inode *inode,
			       int flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
	return pw_fsnotify_add_mark(mark, inode, FSNOTIFY_OBJ_TYPE_INODE, flags);
#else
	return pw_fsnotify_add_mark(mark, &inode->i_fsnotify_marks,
				    FSNOTIFY_OBJ_TYPE_INODE, flags, NULL);
#endif
}

static __nocfi void pw_mark_destroy(struct fsnotify_mark *mark,
				    struct fsnotify_group *group)
{
	pw_fsnotify_destroy_mark(mark, group);
}

static __nocfi void pw_mark_put(struct fsnotify_mark *mark)
{
	pw_fsnotify_put_mark(mark);
}

static unsigned long pw_resolve(const char *name)
{
	unsigned long addr;

	addr = pw_cfg.resolve(name);
	if (!addr)
		pr_info("[pkgwatch] cannot resolve %s\n", name);
	return addr;
}

static int pw_resolve_symbols(void)
{
	unsigned long addr;

	addr = pw_resolve("fsnotify_alloc_group");
	pw_fsnotify_alloc_group = (pw_alloc_group_t)addr;
	addr = pw_resolve("fsnotify_put_group");
	pw_fsnotify_put_group = (pw_put_group_t)addr;
	addr = pw_resolve("fsnotify_init_mark");
	pw_fsnotify_init_mark = (pw_init_mark_t)addr;
	addr = pw_resolve("fsnotify_add_mark");
	pw_fsnotify_add_mark = (pw_add_mark_t)addr;
	addr = pw_resolve("fsnotify_destroy_mark");
	pw_fsnotify_destroy_mark = (pw_destroy_mark_t)addr;
	addr = pw_resolve("fsnotify_put_mark");
	pw_fsnotify_put_mark = (pw_put_mark_t)addr;
	/* not exported on 5.10 GKI, resolve it like the fsnotify set */
	addr = pw_resolve("iterate_dir");
	pw_iterate_dir = (pw_iterate_dir_t)addr;

	if (!pw_fsnotify_alloc_group || !pw_fsnotify_put_group ||
	    !pw_fsnotify_init_mark || !pw_fsnotify_add_mark ||
	    !pw_fsnotify_destroy_mark || !pw_fsnotify_put_mark ||
	    !pw_iterate_dir) {
		pr_info("[pkgwatch] fsnotify symbols incomplete\n");
		return -ENODATA;
	}
	return 0;
}

static int pw_watch_dir(void)
{
	char dir[PW_PATH_MAX];
	const char *slash;
	size_t len;
	int ret;

	slash = strrchr(pw_list_path, '/');
	if (!slash || slash == pw_list_path)
		return -EINVAL;

	len = (size_t)(slash - pw_list_path);
	if (len >= PW_PATH_MAX)
		return -E2BIG;
	memcpy(dir, pw_list_path, len);
	dir[len] = '\0';

	ret = kern_path(dir, LOOKUP_FOLLOW, &pw_watch_path);
	if (ret)
		return ret;

	pw_watch_inode = d_inode(pw_watch_path.dentry);
	ihold(pw_watch_inode);

	pw_mark = kzalloc(sizeof(*pw_mark), GFP_KERNEL);
	if (!pw_mark) {
		ret = -ENOMEM;
		goto err;
	}
	pw_mark_init(pw_mark, pw_group);
	pw_mark->mask = PW_WATCH_MASK;

	ret = pw_mark_add(pw_mark, pw_watch_inode, 0);
	if (ret) {
		pw_mark_put(pw_mark);
		pw_mark = NULL;
		goto err;
	}
	return 0;

err:
	iput(pw_watch_inode);
	pw_watch_inode = NULL;
	path_put(&pw_watch_path);
	memset(&pw_watch_path, 0, sizeof(pw_watch_path));
	return ret;
}

int pkgwatch_watch_start(void)
{
	int ret;

	if (!pw_inited)
		return -ENODATA;
	if (pw_group)
		return 0;

	pw_group = pw_group_alloc();
	if (IS_ERR(pw_group)) {
		ret = PTR_ERR(pw_group);
		pw_group = NULL;
		return ret;
	}

	ret = pw_watch_dir();
	if (ret) {
		pw_group_put(pw_group);
		pw_group = NULL;
		return ret;
	}
	return 0;
}

void pkgwatch_watch_stop(void)
{
	if (pw_mark) {
		pw_mark_destroy(pw_mark, pw_group);
		pw_mark_put(pw_mark);
		pw_mark = NULL;
	}
	if (pw_watch_inode) {
		iput(pw_watch_inode);
		pw_watch_inode = NULL;
	}
	if (pw_watch_path.dentry) {
		path_put(&pw_watch_path);
		memset(&pw_watch_path, 0, sizeof(pw_watch_path));
	}
	if (pw_group) {
		pw_group_put(pw_group);
		pw_group = NULL;
	}
}

int pkgwatch_init(const struct pkgwatch_cfg *cfg)
{
	int ret;

	if (!cfg || !cfg->resolve || !cfg->packages_list || !cfg->app_dir ||
	    !cfg->is_manager)
		return -EINVAL;
	if (cfg->max_depth < 0)
		return -EINVAL;
	if (pw_inited)
		return -EALREADY;

	pw_list_path = kstrdup(cfg->packages_list, GFP_KERNEL);
	if (!pw_list_path)
		return -ENOMEM;

	pw_app_dir = kstrdup(cfg->app_dir, GFP_KERNEL);
	if (!pw_app_dir) {
		kfree(pw_list_path);
		pw_list_path = NULL;
		return -ENOMEM;
	}

	pw_cfg = *cfg;
	pw_cfg.packages_list = pw_list_path;
	pw_cfg.app_dir = pw_app_dir;

	ret = pw_resolve_symbols();
	if (ret) {
		kfree(pw_list_path);
		pw_list_path = NULL;
		kfree(pw_app_dir);
		pw_app_dir = NULL;
		memset(&pw_cfg, 0, sizeof(pw_cfg));
		return ret;
	}

	pw_manager_appid = 0;
	pw_manager_valid = false;
	pw_inited = true;
	return 0;
}

void pkgwatch_exit(void)
{
	pkgwatch_watch_stop();

	pw_uids_free(&pw_uids);
	pw_seen_clear();

	kfree(pw_list_path);
	pw_list_path = NULL;
	kfree(pw_app_dir);
	pw_app_dir = NULL;

	pw_fsnotify_alloc_group = NULL;
	pw_fsnotify_put_group = NULL;
	pw_fsnotify_init_mark = NULL;
	pw_fsnotify_add_mark = NULL;
	pw_fsnotify_destroy_mark = NULL;
	pw_fsnotify_put_mark = NULL;

	pw_manager_appid = 0;
	pw_manager_valid = false;
	pw_inited = false;
	memset(&pw_cfg, 0, sizeof(pw_cfg));
}
