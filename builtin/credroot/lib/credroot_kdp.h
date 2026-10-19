// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef CREDROOT_KDP_H
#define CREDROOT_KDP_H

#include <linux/sched.h>
#include <linux/types.h>

/*
 * the credential path, for a kernel that protects it. a commit through these is
 * the same change a plain call makes, arranged so the protected path is not the
 * one it takes. not verified here: the kernels that need it are not the ones this
 * was built against
 */

/* resolve what the commit needs. 0 when everything was found */
int credroot_kdp_init(void);

/* the replacement entry points, for a consumer that wants them */
int credroot_commit_creds(struct cred *cred);
void credroot_put_cred(const struct cred *cred);

#endif
