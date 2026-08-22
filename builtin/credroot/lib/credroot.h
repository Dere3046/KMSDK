// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef CREDROOT_H
#define CREDROOT_H

#include <linux/types.h>

int credroot_init(void);
void credroot_exit(void);

int credroot_mark_root(pid_t pid);
int credroot_mark_current(void);

#endif
