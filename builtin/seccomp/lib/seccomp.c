// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

#include "type_info.h"
#include "btf.h"
#include "seccomp.h"

static struct ti_ctx *sc_btf;
static bool sc_layout_ok;
static long sc_off_cache = -1;
static long sc_off_allow_native = -1;

int seccomp_init(unsigned long (*resolve)(const char *name))
{
	struct ti_resolver res = {
		.name_to_addr = resolve,
	};
	u32 id, bit_off, bit_sz;
	int ret;

	if (!ti_ready()) {
		ret = ti_init(&res);
		if (ret)
			return ret;
	}
	sc_btf = ti_base();
	if (!sc_btf)
		return -ENODATA;

	/* runtime layout first, embedded offsets are the fallback */
	if (!ti_type_by_name(sc_btf, "seccomp_filter", BIT(BTF_KIND_STRUCT), &id) &&
	    !ti_member_off(sc_btf, id, "cache", &bit_off, &bit_sz)) {
		sc_off_cache = bit_off / 8;
		if (!ti_type_by_name(sc_btf, "action_cache",
				     BIT(BTF_KIND_STRUCT), &id) &&
		    !ti_member_off(sc_btf, id, "allow_native",
				   &bit_off, &bit_sz))
			sc_off_allow_native = bit_off / 8;
	}
	if (sc_off_cache >= 0 && sc_off_allow_native >= 0)
		sc_layout_ok = true;
	else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
		sc_off_cache = 16;
#else
		sc_off_cache = 12;
#endif
		sc_off_allow_native = 0;
		sc_layout_ok = true;
	}
	return 0;
}

void seccomp_exit(void)
{
	ti_exit();
	sc_btf = NULL;
	sc_layout_ok = false;
}

static unsigned long *sc_bitmap(void *filter)
{
	return (unsigned long *)((char *)filter + sc_off_cache +
				 sc_off_allow_native);
}

int seccomp_cache_allow(void *filter, int nr)
{
	if (!filter || !sc_layout_ok || nr < 0)
		return -EINVAL;
	set_bit(nr, sc_bitmap(filter));
	return 0;
}

int seccomp_cache_clear(void *filter, int nr)
{
	if (!filter || !sc_layout_ok || nr < 0)
		return -EINVAL;
	clear_bit(nr, sc_bitmap(filter));
	return 0;
}
