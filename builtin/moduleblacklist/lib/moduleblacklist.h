// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef MODULEBLACKLIST_H
#define MODULEBLACKLIST_H

#include <linux/types.h>

struct mbl_cfg {
	unsigned long (*resolve)(const char *name);
	/* names merged into the kernel's own list, comma separated */
	const char *names;
};

int moduleblacklist_init(const struct mbl_cfg *cfg);
int moduleblacklist_start(void);
void moduleblacklist_stop(void);
bool moduleblacklist_contains(const char *name);

#endif
