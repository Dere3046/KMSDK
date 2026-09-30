// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef KEVENT_H
#define KEVENT_H

#include <linux/types.h>

#define KEVENT_TYPE_ANY 0xffff

struct kevent_hdr {
	u16 type;
	u16 flags;
	u32 len;
	u64 seq;
	u64 ts_ns;
};

struct kevent_stat {
	u64 pushed;
	u64 dropped;
	u64 first_drop_seq;
	u64 last_drop_seq;
};

/*
 * Payload layout of one structured record:
 *
 *   kevent_hdr, kevent_event, argv_len bytes of argv, extra_len bytes
 *
 * kevent itself keeps carrying opaque payloads, only the types of enum
 * kevent_event_type follow this layout. kevent_hdr.len bounds the whole
 * payload, so a consumer that does not know a type skips the record with the
 * length in that header alone and never parses the body.
 *
 * kevent_event.size is the body size its producer wrote and the tail starts
 * at that offset. A consumer must use size and never its own sizeof to reach
 * the tail, because a producer that adds fields appends them at the end of
 * the body and grows size, and a consumer built against the shorter body
 * keeps reading the fields it knows with the rest skipped. Fields never move,
 * change meaning or change width, an event that needs any of that takes a new
 * type. The body holds no pointer and no u64, so a 32 bit consumer reads the
 * same layout.
 *
 * Each argv string is NUL terminated and argv_len counts the NUL that ends
 * the argv part, so those bytes always end on a NUL and a zero argv_len means
 * no argv was captured. The flags below say which case the capture hit.
 * extra_len is producer data with a shape that follows the event type.
 *
 * kevent_hdr.ts_ns is the time the record entered the queue and the only
 * clock in the schema, a producer that captures and pushes in one call, as
 * kevent_emit_event does, has that as its capture time.
 */
#define KEVENT_COMM_LEN 16
#define KEVENT_DOMAIN_LEN 64

enum kevent_event_type {
	KEVENT_EVENT_NONE = 0,
	KEVENT_EVENT_SULOG = 1,
};

/*
 * kevent_event.flags
 *
 * KEVENT_EVF_ARGV_NONE		no argv was captured: no task, no capture
 *				layer, no mm, or a foreign mm while the
 *				call sat in atomic context
 * KEVENT_EVF_ARGV_EMPTY	the argument range of the task is empty
 * KEVENT_EVF_ARGV_INVALID	the range ends below its start, the window
 *				in which exec installs a new range reads
 *				like this
 * KEVENT_EVF_ARGV_FAULT	the user read failed or came back short,
 *				the bytes that did arrive are kept
 * KEVENT_EVF_ARGV_TRUNC	the range is longer than the buffer, one
 *				byte stays for the terminating NUL
 * KEVENT_EVF_ARGV_RACE		the task changed its mm or its range under
 *				the read, the bytes may mix two exec
 *				images
 * KEVENT_EVF_COMPAT		the mm is AArch32, the strings are read the
 *				same way, the bit only says what the
 *				consumer is looking at
 * KEVENT_EVF_DOMAIN_FAIL	the domain callback failed, the field is
 *				empty
 * KEVENT_EVF_DOMAIN_LONG	the domain did not fit, the field is empty
 */
#define KEVENT_EVF_ARGV_NONE 0x0001U
#define KEVENT_EVF_ARGV_EMPTY 0x0002U
#define KEVENT_EVF_ARGV_INVALID 0x0004U
#define KEVENT_EVF_ARGV_FAULT 0x0008U
#define KEVENT_EVF_ARGV_TRUNC 0x0010U
#define KEVENT_EVF_ARGV_RACE 0x0020U
#define KEVENT_EVF_COMPAT 0x0040U
#define KEVENT_EVF_DOMAIN_FAIL 0x0080U
#define KEVENT_EVF_DOMAIN_LONG 0x0100U

#define KEVENT_EVF_ARGV_MASK (KEVENT_EVF_ARGV_NONE | KEVENT_EVF_ARGV_EMPTY | \
			      KEVENT_EVF_ARGV_INVALID | KEVENT_EVF_ARGV_FAULT | \
			      KEVENT_EVF_ARGV_TRUNC | KEVENT_EVF_ARGV_RACE | \
			      KEVENT_EVF_COMPAT)

struct kevent_event {
	u16 type;
	u16 size;
	s32 result;
	u32 pid;
	u32 tgid;
	u32 ppid;
	u32 uid;
	u32 euid;
	u32 gid;
	u32 egid;
	u32 flags;
	u32 argv_len;
	u32 extra_len;
	char comm[KEVENT_COMM_LEN];
	char domain[KEVENT_DOMAIN_LEN];
};

/*
 * read returns one whole record: the header followed by len payload bytes.
 * When count is smaller than that record read returns negative EMSGSIZE and
 * the record stays queued. read returns 0 once the queue is closed and
 * drained. poll waits while the queue is empty and reports EPOLLHUP after
 * kevent_exit. Only one reader is supported: the second kevent_install_fd
 * returns negative EBUSY.
 *
 * Every kevent_push and kevent_drop consumes one sequence number, dropped
 * counts the sequence numbers that never reached the queue, so a reader can
 * size the gap between first_drop_seq and last_drop_seq. Sequence numbers
 * start at 1, the value 0 means no drop happened yet. An oversized payload
 * is rejected with negative EMSGSIZE and counted as dropped as well.
 */
int kevent_init(u32 max_queued, u32 max_payload);
void kevent_exit(void);

int kevent_push(u16 type, u16 flags, const void *payload, u32 len);
void kevent_drop(void);

int kevent_install_fd(const char *name, unsigned int fd_flags);
void kevent_get_stat(struct kevent_stat *out);

#define KEVENT_EVENT_TAIL_MAX 512U

struct task_struct;

/*
 * Capture layer of the payload schema, it fills a kevent_event and the argv
 * part of the tail from one task. resolve is the consumer symbol resolver and
 * must be a __nocfi wrapper such as the KallRecon kr_name_to_addr, it has to
 * know copy_from_user_nofault, access_process_vm, get_task_mm and mmput. A
 * missing symbol fails kevent_capture_init with negative ENODATA, so nothing
 * is linked and no unexported helper is called directly. domain is optional,
 * the library never links a policy source.
 *
 * Context: a target that shares the mm of the caller is read with the nofault
 * user copy, that path takes no lock, allocates nothing and does not sleep. A
 * target with another mm goes through access_process_vm and mmput, both sleep
 * and must not run in interrupt context, under a spinlock or under
 * rcu_read_lock, in that case the argv part is skipped and flagged instead.
 *
 * kevent_capture_init and kevent_capture_exit run at setup and at teardown,
 * no capture may run while they do.
 */
struct kevent_capture_config {
	unsigned long (*resolve)(const char *name);
	int (*domain)(struct task_struct *task, char *out, u32 size);
};

/*
 * Returns 0, negative EINVAL for a NULL config or a NULL resolve, negative
 * ENODATA for a symbol the resolver does not know. A second call replaces the
 * earlier config. Without this call the event builders below still fill the
 * identity fields, they only skip the argv part and flag it.
 */
int kevent_capture_init(const struct kevent_capture_config *config);
void kevent_capture_exit(void);

/*
 * Reset one body to a type and a producer result, size is set to the body
 * size of this build and both tail lengths to zero. result is producer
 * defined, the convention is 0 for an event that went through and a negative
 * errno for one that was refused.
 */
void kevent_event_init(struct kevent_event *ev, u16 type, s32 result);

/*
 * Identity of a task: pid, tgid, ppid, the real uid, euid, gid and egid, comm
 * and the domain from the injected callback. comm is always NUL terminated
 * inside its 16 bytes. A domain the callback cannot produce leaves the field
 * empty and sets KEVENT_EVF_DOMAIN_FAIL, one that does not fit leaves it
 * empty as well and sets KEVENT_EVF_DOMAIN_LONG, so a consumer never reads a
 * cut context as a real one. No sleep, safe in atomic context, a NULL task
 * leaves every field zero.
 */
void kevent_event_identity(struct kevent_event *ev, struct task_struct *task);

/*
 * argv of the argument range of the task mm, written into tail as the NUL
 * separated strings the kernel holds. The range takes at most tail_size
 * bytes, one byte stays for the terminating NUL, a longer range is cut and
 * flagged with KEVENT_EVF_ARGV_TRUNC. argv_len counts the NUL, so it is at
 * least 1 once a range was read and 0 when nothing was captured. The whole
 * argv state is cleared first, the flags of the run replace it.
 *
 * Returns the bytes written to tail, which is ev->argv_len.
 */
u32 kevent_event_argv(struct kevent_event *ev, struct task_struct *task,
		      char *tail, u32 tail_size);

/*
 * Fill a body for task, append extra after the argv bytes and push the whole
 * record on the channel as one payload. extra is opaque producer data and may
 * be NULL, extra_len is capped at KEVENT_EVENT_TAIL_MAX and a larger one is
 * refused with negative EMSGSIZE, the argv budget drops by extra_len. The
 * record is built on the stack, so the tail never exceeds
 * KEVENT_EVENT_TAIL_MAX and no allocation happens on any path.
 *
 * Returns the kevent_push result: 0 when queued, negative EPIPE before
 * kevent_init or after kevent_exit, negative EMSGSIZE when the record is
 * larger than the ring payload limit, negative ENOSPC when the queue is full,
 * negative EINVAL for a NULL extra with a nonzero length. The channel counts
 * the two size cases as drops, a caller that must not lose events reads
 * kevent_get_stat instead of trusting this value alone.
 */
int kevent_emit_event(struct task_struct *task, u16 type, s32 result,
		      const void *extra, u32 extra_len);

#endif
