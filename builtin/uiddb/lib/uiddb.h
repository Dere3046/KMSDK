// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef UIDDB_H
#define UIDDB_H

#include <linux/types.h>

struct uiddb_cfg {
	u32 magic;
	u32 version;
	u32 record_size;
	const char *path;
	int (*validate)(const void *rec, u32 version);
	void (*migrate)(void *rec, u32 from_version);
};

/*
 * The store keeps at most 65535 records, uiddb_set returns -ENOSPC beyond it.
 *
 * uiddb_get returns the stored record and holds a reference on it, the caller
 * must release it with uiddb_put. validate returns 0 for an accepted record,
 * any other value rejects it: uiddb_set then returns -EINVAL and uiddb_load
 * skips that record. migrate is called once per record while loading a file
 * whose version is older than uiddb_cfg.version, validate is called after
 * migration with uiddb_cfg.version.
 *
 * The record body is opaque, records are copied in and out of the store.
 *
 * uiddb_save writes the whole table in one buffer, uiddb_load merges the file
 * into the live table. A missing file counts as an empty store, uiddb_load
 * returns 0 for it. Both use uiddb_cfg.path, the string must stay valid for
 * the lifetime of the store. uiddb_init and uiddb_exit must not run while any
 * other uiddb call is in flight.
 *
 * uiddb_foreach runs its callback under RCU, the callback must not sleep.
 * uiddb_prune runs its callback under the store lock and returns the number of
 * removed records, saving the result is up to the caller.
 */
int uiddb_init(const struct uiddb_cfg *cfg);
void uiddb_exit(void);

void *uiddb_get(uid_t uid);
void uiddb_put(void *rec);

int uiddb_set(uid_t uid, const void *rec);
int uiddb_del(uid_t uid);
int uiddb_count(void);

int uiddb_save(void);
int uiddb_load(void);

int uiddb_prune(bool (*keep)(uid_t uid, const void *rec, void *arg), void *arg);
int uiddb_foreach(int (*cb)(uid_t uid, const void *rec, void *arg), void *arg);

#endif
