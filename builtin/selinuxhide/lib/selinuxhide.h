// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef SELINUXHIDE_H
#define SELINUXHIDE_H

#include "hk_lsm.h"

int selinuxhide_init(const struct hk_lsm_layout *layout);
void selinuxhide_exit(void);
int selinuxhide_start(void);
void selinuxhide_stop(void);

#endif
