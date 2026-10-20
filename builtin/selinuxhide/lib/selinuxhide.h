// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef SELINUXHIDE_H
#define SELINUXHIDE_H

#include <linux/types.h>

/*
 * Mechanism only: the three selinuxfs leak points plus setprocattr are
 * driven by consumer policy.
 *   context and access write slots answer from the consumer alternate policy
 *   the status page is filled by the consumer
 *   setprocattr checks the request against the alternate policy and then runs
 *   the original hook, so the domain change is real
 * The alternate policy comes from the consumer, a NULL one makes the library
 * clone the live policy through sepolicy. The clone is freed on
 * selinuxhide_exit, so that call has to come before sepolicy_exit.
 * Answers come from the sepolicy query primitives, the global policy pointer
 * is swapped only when those are unavailable on the running kernel.
 */

struct slh_cfg {
	unsigned long (*resolve)(const char *name);
	bool (*should_hide)(uid_t uid, void *priv);
	void (*fill_status)(void *page, void *priv);
	/*
	 * what a stock boot of this kernel shows on the status page. the consumer
	 * names them because they follow the kernel's behaviour and not a version
	 * number the library would have to guess at
	 */
	u32 stock_sequence;
	u32 stock_policyload;
	void *alt_policy;
	void *priv;
};

int selinuxhide_init(const struct slh_cfg *cfg);
void selinuxhide_exit(void);
int selinuxhide_start(void);

/*
 * the counter surface answers from the policy copy, and it is named at install time
 * so the engine can find it: that is why it carries a prototype here and not a
 * static definition in the source
 */
ssize_t slh_read_sidtab_hash_stats(struct file *file, char __user *buf,
				   size_t count, loff_t *ppos);
void selinuxhide_stop(void);

#endif
