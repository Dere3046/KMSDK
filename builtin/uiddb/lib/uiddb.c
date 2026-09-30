// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/err.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "kfile.h"
#include "uiddb.h"

#define UIDDB_HASH_BITS 8
#define UIDDB_FILE_HDR_LEN (2 * sizeof(u32))
#define UIDDB_REC_HDR_LEN sizeof(u32)

struct uiddb_node {
	struct hlist_node list;
	struct rcu_head rcu;
	struct kref ref;
	uid_t uid;
	u8 rec[];
};

static DEFINE_HASHTABLE(uiddb_hash, UIDDB_HASH_BITS);
static DEFINE_MUTEX(uiddb_lock);
static const char *uiddb_path;
static int (*uiddb_validate)(const void *rec, u32 version);
static void (*uiddb_migrate)(void *rec, u32 from_version);
static u32 uiddb_magic;
static u32 uiddb_version;
static u32 uiddb_record_size;
static u16 uiddb_num;
static bool uiddb_ready;

static void uiddb_node_free(struct kref *ref)
{
	struct uiddb_node *node = container_of(ref, struct uiddb_node, ref);

	kfree_rcu(node, rcu);
}

static void uiddb_node_put(struct uiddb_node *node)
{
	kref_put(&node->ref, uiddb_node_free);
}

static struct uiddb_node *uiddb_alloc(uid_t uid, const void *rec)
{
	struct uiddb_node *node;

	node = kzalloc(struct_size(node, rec, (size_t)uiddb_record_size),
		       GFP_KERNEL);
	if (!node) {
		return NULL;
	}

	kref_init(&node->ref);
	node->uid = uid;
	if (rec) {
		memcpy(node->rec, rec, uiddb_record_size);
	}

	return node;
}

/* the mutex is held */
static struct uiddb_node *uiddb_find(uid_t uid)
{
	struct uiddb_node *node;

	hash_for_each_possible (uiddb_hash, node, list, uid) {
		if (node->uid == uid) {
			return node;
		}
	}

	return NULL;
}

/* rcu read lock is held */
static struct uiddb_node *uiddb_find_rcu(uid_t uid)
{
	struct uiddb_node *node;

	hash_for_each_possible_rcu (uiddb_hash, node, list, uid) {
		if (node->uid == uid) {
			return node;
		}
	}

	return NULL;
}

/* the mutex is held */
static int uiddb_insert_locked(uid_t uid, const void *rec)
{
	struct uiddb_node *node;
	struct uiddb_node *old;
	int ret = 0;

	node = uiddb_alloc(uid, rec);
	if (!node) {
		return -ENOMEM;
	}

	old = uiddb_find(uid);
	if (old) {
		hlist_replace_rcu(&old->list, &node->list);
		uiddb_node_put(old);
	} else if (uiddb_num == U16_MAX) {
		ret = -ENOSPC;
	} else {
		hash_add_rcu(uiddb_hash, &node->list, uid);
		uiddb_num++;
	}

	if (ret) {
		uiddb_node_put(node);
	}

	return ret;
}

int uiddb_init(const struct uiddb_cfg *cfg)
{
	if (!cfg || !cfg->path || !cfg->record_size) {
		return -EINVAL;
	}

	mutex_lock(&uiddb_lock);
	if (uiddb_ready) {
		mutex_unlock(&uiddb_lock);
		return -EBUSY;
	}

	hash_init(uiddb_hash);
	uiddb_magic = cfg->magic;
	uiddb_version = cfg->version;
	uiddb_record_size = cfg->record_size;
	uiddb_path = cfg->path;
	uiddb_validate = cfg->validate;
	uiddb_migrate = cfg->migrate;
	uiddb_num = 0;
	WRITE_ONCE(uiddb_ready, true);
	mutex_unlock(&uiddb_lock);

	return 0;
}

void uiddb_exit(void)
{
	struct uiddb_node *node;
	struct hlist_node *tmp;
	int bucket;

	mutex_lock(&uiddb_lock);
	if (!uiddb_ready) {
		mutex_unlock(&uiddb_lock);
		return;
	}

	WRITE_ONCE(uiddb_ready, false);

	hash_for_each_safe (uiddb_hash, bucket, tmp, node, list) {
		hlist_del_rcu(&node->list);
		uiddb_node_put(node);
	}
	uiddb_num = 0;

	uiddb_path = NULL;
	uiddb_validate = NULL;
	uiddb_migrate = NULL;
	uiddb_record_size = 0;
	mutex_unlock(&uiddb_lock);
}

void *uiddb_get(uid_t uid)
{
	struct uiddb_node *node;

	if (!READ_ONCE(uiddb_ready)) {
		return NULL;
	}

	rcu_read_lock();
retry:
	node = uiddb_find_rcu(uid);
	if (node && !kref_get_unless_zero(&node->ref)) {
		goto retry;
	}
	rcu_read_unlock();

	return node ? node->rec : NULL;
}

void uiddb_put(void *rec)
{
	struct uiddb_node *node;

	if (!rec) {
		return;
	}

	node = container_of(rec, struct uiddb_node, rec);
	uiddb_node_put(node);
}

int uiddb_set(uid_t uid, const void *rec)
{
	int ret;

	if (!READ_ONCE(uiddb_ready)) {
		return -ENODATA;
	}
	if (!rec) {
		return -EINVAL;
	}
	if (uiddb_validate && uiddb_validate(rec, uiddb_version)) {
		return -EINVAL;
	}

	mutex_lock(&uiddb_lock);
	ret = uiddb_insert_locked(uid, rec);
	mutex_unlock(&uiddb_lock);

	return ret;
}

int uiddb_del(uid_t uid)
{
	struct uiddb_node *node;
	int ret = -ENOENT;

	if (!READ_ONCE(uiddb_ready)) {
		return -ENODATA;
	}

	mutex_lock(&uiddb_lock);
	node = uiddb_find(uid);
	if (node) {
		hlist_del_rcu(&node->list);
		uiddb_num--;
		uiddb_node_put(node);
		ret = 0;
	}
	mutex_unlock(&uiddb_lock);

	return ret;
}

int uiddb_count(void)
{
	if (!READ_ONCE(uiddb_ready)) {
		return 0;
	}

	return (int)READ_ONCE(uiddb_num);
}

int uiddb_save(void)
{
	struct uiddb_node *node;
	u32 file_hdr[2];
	u32 file_uid;
	u8 *buf;
	u8 *pos;
	size_t rec_len;
	size_t total;
	ssize_t ret;
	int bucket;

	if (!READ_ONCE(uiddb_ready)) {
		return -ENODATA;
	}

	rec_len = (size_t)UIDDB_REC_HDR_LEN + (size_t)uiddb_record_size;

	mutex_lock(&uiddb_lock);
	if (check_mul_overflow((size_t)uiddb_num, rec_len, &total) ||
	    check_add_overflow(total, (size_t)UIDDB_FILE_HDR_LEN, &total)) {
		mutex_unlock(&uiddb_lock);
		return -E2BIG;
	}

	buf = kvmalloc(total, GFP_KERNEL);
	if (!buf) {
		mutex_unlock(&uiddb_lock);
		return -ENOMEM;
	}

	file_hdr[0] = uiddb_magic;
	file_hdr[1] = uiddb_version;
	pos = buf;
	memcpy(pos, file_hdr, sizeof(file_hdr));
	pos += sizeof(file_hdr);

	hash_for_each (uiddb_hash, bucket, node, list) {
		file_uid = (u32)node->uid;
		memcpy(pos, &file_uid, sizeof(file_uid));
		pos += sizeof(file_uid);
		memcpy(pos, node->rec, uiddb_record_size);
		pos += uiddb_record_size;
	}
	mutex_unlock(&uiddb_lock);

	ret = kfile_write(uiddb_path, buf, total, 0644);
	kvfree(buf);

	if (ret < 0) {
		return (int)ret;
	}
	if ((size_t)ret != total) {
		return -EIO;
	}

	return 0;
}

int uiddb_load(void)
{
	struct kfile_handle *h;
	u32 file_hdr[2];
	u32 uid;
	u8 *scratch;
	u8 *buf;
	u8 *pos;
	loff_t size;
	ssize_t got;
	size_t cap_max;
	size_t rec_len;
	size_t payload;
	int ret = 0;

	if (!READ_ONCE(uiddb_ready)) {
		return -ENODATA;
	}

	rec_len = (size_t)UIDDB_REC_HDR_LEN + (size_t)uiddb_record_size;
	if (check_mul_overflow((size_t)U16_MAX + 1U, rec_len, &cap_max) ||
	    check_add_overflow(cap_max, (size_t)UIDDB_FILE_HDR_LEN, &cap_max)) {
		return -E2BIG;
	}

	h = kfile_open(uiddb_path, false);
	if (IS_ERR(h)) {
		ret = (int)PTR_ERR(h);
		/* a missing file counts as an empty store */
		if (ret == -ENOENT) {
			ret = 0;
		}
		return ret;
	}
	if (!h) {
		return -ENODATA;
	}

	size = kfile_size(h);
	if (size < 0) {
		ret = (int)size;
		kfile_close(h);
		return ret;
	}
	if ((u64)size < (u64)UIDDB_FILE_HDR_LEN) {
		kfile_close(h);
		return -EINVAL;
	}
	if ((u64)size > (u64)cap_max) {
		kfile_close(h);
		return -E2BIG;
	}

	buf = kvmalloc((size_t)size, GFP_KERNEL);
	if (!buf) {
		kfile_close(h);
		return -ENOMEM;
	}

	got = kfile_pread(h, buf, (size_t)size, 0);
	kfile_close(h);
	if (got < 0) {
		kvfree(buf);
		return (int)got;
	}
	if ((size_t)got != (size_t)size) {
		kvfree(buf);
		return -EIO;
	}

	memcpy(file_hdr, buf, sizeof(file_hdr));
	if (file_hdr[0] != uiddb_magic || file_hdr[1] > uiddb_version) {
		kvfree(buf);
		return -EINVAL;
	}

	/* records are copied through an aligned buffer, the file layout is not */
	scratch = kvmalloc((size_t)uiddb_record_size, GFP_KERNEL);
	if (!scratch) {
		kvfree(buf);
		return -ENOMEM;
	}

	payload = (size_t)size - (size_t)UIDDB_FILE_HDR_LEN;
	pos = buf + UIDDB_FILE_HDR_LEN;

	while (payload >= rec_len) {
		memcpy(&uid, pos, sizeof(uid));
		memcpy(scratch, pos + UIDDB_REC_HDR_LEN, uiddb_record_size);

		if (file_hdr[1] < uiddb_version && uiddb_migrate) {
			uiddb_migrate(scratch, file_hdr[1]);
		}
		if (uiddb_validate && uiddb_validate(scratch, uiddb_version)) {
			pos += rec_len;
			payload -= rec_len;
			continue;
		}

		mutex_lock(&uiddb_lock);
		ret = uiddb_insert_locked(uid, scratch);
		mutex_unlock(&uiddb_lock);
		if (ret) {
			break;
		}

		pos += rec_len;
		payload -= rec_len;
	}

	kvfree(scratch);
	kvfree(buf);

	return ret;
}

int uiddb_prune(bool (*keep)(uid_t uid, const void *rec, void *arg), void *arg)
{
	struct uiddb_node *node;
	struct hlist_node *tmp;
	int pruned = 0;
	int bucket;

	if (!READ_ONCE(uiddb_ready)) {
		return -ENODATA;
	}
	if (!keep) {
		return -EINVAL;
	}

	mutex_lock(&uiddb_lock);
	hash_for_each_safe (uiddb_hash, bucket, tmp, node, list) {
		if (keep(node->uid, node->rec, arg)) {
			continue;
		}
		hlist_del_rcu(&node->list);
		uiddb_num--;
		uiddb_node_put(node);
		pruned++;
	}
	mutex_unlock(&uiddb_lock);

	return pruned;
}

int uiddb_foreach(int (*cb)(uid_t uid, const void *rec, void *arg), void *arg)
{
	struct uiddb_node *node;
	int ret = 0;
	int bucket;

	if (!READ_ONCE(uiddb_ready)) {
		return -ENODATA;
	}
	if (!cb) {
		return -EINVAL;
	}

	rcu_read_lock();
	hash_for_each_rcu (uiddb_hash, bucket, node, list) {
		ret = cb(node->uid, node->rec, arg);
		if (ret) {
			break;
		}
	}
	rcu_read_unlock();

	return ret;
}
