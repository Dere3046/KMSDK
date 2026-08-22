// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef SECCOMP_H
#define SECCOMP_H

#include <linux/types.h>

int seccomp_init(unsigned long (*resolve)(const char *name));
void seccomp_exit(void);

int seccomp_cache_allow(void *filter, int nr);
int seccomp_cache_clear(void *filter, int nr);

#endif
