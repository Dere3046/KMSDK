// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef HWBREAKPOINT_H
#define HWBREAKPOINT_H

#include <linux/types.h>

struct hwbp {
	struct perf_event *ev;
	unsigned long addr;
	unsigned long hook_pc;
	struct list_head list;
};

int hwbp_init(void);
void hwbp_exit(void);

int hwbp_add(pid_t pid, unsigned long addr, int type, int len,
	     struct hwbp **out);
int hwbp_del(struct hwbp *bp);
int hwbp_pause(struct hwbp *bp);
int hwbp_resume(struct hwbp *bp);
int hwbp_set_pc(struct hwbp *bp, unsigned long target);

int hwbp_anti_start(void);
void hwbp_anti_stop(void);

#endif
