// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>

#include "kevent.h"
#include "sulog.h"

static bool slog_on;

int slog_init(const struct slog_config *config)
{
	struct kevent_capture_config capture;
	int ret;

	if (!config) {
		return -EINVAL;
	}

	BUILD_BUG_ON(SLOG_EXTRA_MAX > KEVENT_EVENT_TAIL_MAX);

	capture.resolve = config->resolve;
	capture.domain = config->domain;

	ret = kevent_capture_init(&capture);
	if (ret) {
		return ret;
	}

	slog_on = true;

	return 0;
}

void slog_exit(void)
{
	slog_on = false;
	kevent_capture_exit();
}

void slog_enable(bool on)
{
	slog_on = on;
}

bool slog_enabled(void)
{
	return slog_on;
}

int slog_emit(struct task_struct *task, s32 result, const void *extra,
	      u32 extra_len)
{
	if (!slog_on) {
		return -EPERM;
	}
	if (!task) {
		return -EINVAL;
	}
	if (extra_len > SLOG_EXTRA_MAX) {
		return -EMSGSIZE;
	}

	return kevent_emit_event(task, KEVENT_EVENT_SULOG, result, extra,
				 extra_len);
}
