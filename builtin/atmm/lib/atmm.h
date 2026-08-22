// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef ATMM_H
#define ATMM_H

#include <linux/types.h>

int atmm_translate(pid_t pid, unsigned long va, unsigned long *pa);

#endif
