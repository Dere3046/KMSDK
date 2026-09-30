// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef PKGWATCH_H
#define PKGWATCH_H

#include <linux/types.h>

struct pkgwatch_cfg {
	/* consumer symbol lookup, must be a __nocfi wrapper such as KallRecon */
	unsigned long (*resolve)(const char *name);
	const char *packages_list;
	const char *app_dir;
	int max_depth;
	bool (*is_manager)(const char *apk_path, void *priv);
	void (*on_manager)(uid_t uid, const char *apk_path, void *priv);
	void *priv;
};

int pkgwatch_init(const struct pkgwatch_cfg *cfg);
void pkgwatch_exit(void);

/*
 * Reload packages.list into the internal package to uid table. When the recorded
 * manager is gone, scan app_dir, judge with is_manager, remember the uid and call
 * on_manager. uid values come from the second column of packages.list, consumers
 * that need a user offset add it themselves.
 */
int pkgwatch_refresh(void);

/* failure code is returned as is, the watch exists only after 0 */
int pkgwatch_watch_start(void);
void pkgwatch_watch_stop(void);

/* uid of a package from packages.list, ENOENT negative when it is absent */
int pkgwatch_uid_of(const char *pkg, uid_t *uid);

/* call keep for every entry of the internal table, entries it rejects are dropped */
int pkgwatch_prune(bool (*keep)(uid_t uid, const char *pkg, void *arg),
		   void *arg);

#endif
