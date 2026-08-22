// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef KFILE_H
#define KFILE_H

#include <linux/types.h>

int kfile_init(void);
void kfile_exit(void);

ssize_t kfile_read(const char *path, void *buf, size_t len);
ssize_t kfile_write(const char *path, const void *buf, size_t len,
		    umode_t mode);
int kfile_exist(const char *path);

#endif
