// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef SULOG_H
#define SULOG_H

#include <linux/types.h>

#include "kevent.h"

struct task_struct;

/*
 * Payload assembly for one privilege grant: who asked, with which identity
 * and which command line, as one KEVENT_EVENT_SULOG record on the kevent
 * channel. The channel, its payload limit and its sequence numbering belong
 * to kevent, this library only fills the schema of kevent.h. A consumer sizes
 * the ring for sizeof(struct kevent_event) plus the tail it wants, and the
 * tail never exceeds KEVENT_EVENT_TAIL_MAX bytes.
 */
#define SLOG_EXTRA_MAX 128U

/*
 * resolve is forwarded to kevent_capture_init and must be a __nocfi wrapper
 * such as the KallRecon kr_name_to_addr, domain is the SELinux callback, both
 * carry the contract documented on struct kevent_capture_config. domain stays
 * optional, the library never links a policy source.
 */
struct slog_config {
	unsigned long (*resolve)(const char *name);
	int (*domain)(struct task_struct *task, char *out, u32 size);
};

/*
 * Returns 0, negative EINVAL for a NULL config or a NULL resolve, negative
 * ENODATA for a symbol the resolver does not know. The channel itself does
 * not have to exist yet, kevent_init may follow this call. Emission is on
 * after it returns 0.
 */
int slog_init(const struct slog_config *config);
void slog_exit(void);

/*
 * Runtime switch, on after slog_init. While it is off slog_emit returns
 * negative EPERM before it touches the channel.
 */
void slog_enable(bool on);
bool slog_enabled(void);

/*
 * Assemble and push one record for task with a producer result, 0 for a grant
 * and a negative errno for a refusal by convention. extra is opaque producer
 * data appended after the argv bytes, a NUL terminated operation name for
 * instance, capped at SLOG_EXTRA_MAX, the argv part keeps the budget that is
 * left.
 *
 * Context: no sleep when task shares the mm of the caller, which is the
 * usual case, and the domain callback must then be atomic safe too. A task
 * with another mm is read through access_process_vm, that path sleeps and
 * belongs in process context, in atomic context its argv part is skipped and
 * flagged. The record is copied into the ring before the call returns, the
 * caller may reuse extra right away.
 *
 * Returns 0 when the record is queued, negative EINVAL for a NULL task or a
 * NULL extra with a nonzero length, negative EPERM while emission is off,
 * negative EMSGSIZE for an extra above SLOG_EXTRA_MAX or a record above the
 * ring payload limit, negative EPIPE before kevent_init or after
 * kevent_exit, negative ENOSPC when the queue is full.
 *
 * An emit that fails is not retried and not queued anywhere else, the record
 * is lost from the caller point of view. kevent counts every record it
 * refuses as a drop, so the sequence numbers and kevent_get_stat expose the
 * gap, an audit path that must not lose events reads that counter.
 */
int slog_emit(struct task_struct *task, s32 result, const void *extra,
	      u32 extra_len);

#endif
