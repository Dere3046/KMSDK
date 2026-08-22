// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef MNTNS_H
#define MNTNS_H

#include <linux/types.h>

int mntns_init(void);
void mntns_exit(void);

int mntns_enter_init(void);
int mntns_enter_individual(void);

#endif
