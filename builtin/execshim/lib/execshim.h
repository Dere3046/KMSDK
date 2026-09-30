// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef EXECSHIM_H
#define EXECSHIM_H

#include <linux/types.h>

/* not handled, the original syscall runs and nothing else happens */
#define EXS_ACT_NONE 0u
/* replace the path with plan->to, dropped when plan->to is NULL or empty */
#define EXS_ACT_REWRITE 0x1u
/* inject an env item list into the envp of this execve or execveat */
#define EXS_ACT_ENV 0x2u
/* run path_escalate for this call, a no op while that callback is NULL */
#define EXS_ACT_ESCALATE 0x4u

/*
 * filled by path_filter, execshim clears it before every call
 *
 * to is the replacement path used when EXS_ACT_REWRITE comes back
 *   owned by the consumer and it must stay valid until the current
 *   syscall ends, never return a stack or temp buffer, a kernel
 *   buffer or a static string is the intended source
 *
 * env is the KEY=VALUE list injected when EXS_ACT_ENV comes back
 *   NULL falls back to cfg->env_add, the same rules apply, every item
 *   must stay valid and be NUL terminated
 */
struct exs_plan {
	const char *to;
	const char *const *env;
};

/*
 * mechanism only: path rewrite, env injection, uid gate, user stack staging
 * every path, every env item and the uid policy come from the consumer
 *
 * map_path returns the replacement path, NULL means keep the original
 *   the input is the original path read into a kernel buffer, NUL
 *   terminated and shorter than 256 bytes
 *   the returned string is owned by the consumer and must stay valid
 *   until the current syscall ends, never return stack or temp buffers
 *   an empty string means no rewrite
 *   execve and path form execveat hand the target over as an fd
 *   faccessat and newfstatat only rewrite the path pointer argument
 *   never called once path_filter is set
 *
 * env_add NULL terminated array of KEY=VALUE items injected into the envp
 *   of execve and execveat
 *   a key already present in the original envp keeps its original value,
 *   no duplicate key is appended
 *   at most 32 items are injected, the rest is ignored, every item must
 *   stay valid and be NUL terminated
 *   NULL means no injection
 *   without path_filter it is injected into every execve and execveat,
 *   with path_filter only when the decision asks for EXS_ACT_ENV
 *
 * allow_uid decides if a call is handled at all, NULL means always handle
 *   the argument is the real uid of the current process
 *   a coarse gate in front of path_filter, both have to pass
 *
 * path_filter per path decision, the second and richer gate, NULL means
 *   every call falls back to map_path plus an unconditional env_add
 *   called with the original path before anything is staged, from the
 *   context of the calling task, so it may sleep the way the rest of the
 *   hook does, a kern_path probe for a support file is fine
 *   never called for the fd form of execveat, that call is passed through
 *   returns a bitwise or of the EXS_ACT_* flags, EXS_ACT_NONE means the
 *   original syscall runs
 *   once set it is the only decision maker, map_path is not called and
 *   env_add is not injected on its own
 *   faccessat and newfstatat apply EXS_ACT_REWRITE only
 *   a consumer with a precondition, a support library that has to exist
 *   for example, tests it here and returns EXS_ACT_NONE to leave the
 *   call alone
 *
 * path_escalate runs the credential or the domain change asked for by
 *   EXS_ACT_ESCALATE, NULL makes the flag a no op
 *   called after the env staging succeeded and before the rewritten
 *   syscall is issued, so a staging failure never escalates and a
 *   consumer that escalates inside path_filter must not ask for the flag
 *   execshim itself never touches cred, the domain side is composed by
 *   the consumer, from its own code or from a library it links
 *
 * priv is passed back to the four callbacks above
 */
struct exs_cfg {
	const char *(*map_path)(const char *path, void *priv);
	const char *const *env_add;
	bool (*allow_uid)(uid_t uid, void *priv);
	u32 (*path_filter)(const char *path, struct exs_plan *plan, void *priv);
	void (*path_escalate)(const char *path, void *priv);
	void *priv;
};

int exs_init(const struct exs_cfg *cfg);
void exs_exit(void);
int exs_start(void);
void exs_stop(void);

#endif
