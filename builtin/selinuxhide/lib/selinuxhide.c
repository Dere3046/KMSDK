// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/string.h>

#include "hk_lsm.h"
#include "selinuxhide.h"

static bool slh_on;

static int __nocfi slh_setprocattr(const char *name, void *value, size_t size)
{
	/* apps must believe setcon succeeded, domain stays untouched */
	if (current_uid().val >= 10000 && name && !strcmp(name, "current"))
		return 0;
	return -EACCES;
}

static struct hk_lsm_hook slh_hook =
	HK_LSM_HOOK_INIT(setprocattr, "selinux_setprocattr",
			 slh_setprocattr, 0);

int selinuxhide_init(const struct hk_lsm_layout *layout)
{
	if (!layout || !layout->resolve)
		return -EINVAL;
	return hk_lsm_init(layout);
}

void selinuxhide_exit(void)
{
	selinuxhide_stop();
	hk_lsm_exit();
}

int selinuxhide_start(void)
{
	int ret;

	if (slh_on)
		return 0;
	ret = hk_lsm_hook(&slh_hook);
	if (ret)
		return ret;
	slh_on = true;
	return 0;
}

void selinuxhide_stop(void)
{
	if (!slh_on)
		return;
	hk_lsm_unhook(&slh_hook);
	slh_on = false;
}
