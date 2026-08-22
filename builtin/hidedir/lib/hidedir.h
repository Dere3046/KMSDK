// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef HIDEDIR_H
#define HIDEDIR_H

#include <linux/types.h>

int hidedir_init(void);
void hidedir_exit(void);

int hidedir_add(const char *name);
int hidedir_remove(const char *name);
void hidedir_clear(void);
int hidedir_start(void);
void hidedir_stop(void);

#endif
