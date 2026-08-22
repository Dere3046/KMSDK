// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef SEPOLICY_H
#define SEPOLICY_H

#include <linux/types.h>

int sepolicy_init(unsigned long (*resolve)(const char *name));
void sepolicy_exit(void);

int sepolicy_add_allow(const char *s, const char *t, const char *c,
		       const char *d);
int sepolicy_add_type(const char *type_name);

#endif
