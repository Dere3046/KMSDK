// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef VENDORCOMPAT_H
#define VENDORCOMPAT_H

#include <linux/types.h>

/*
 * some kernels protect the paths a module usually takes, and the work that needs
 * them then lands nowhere while every call still returns success. this library is
 * one place for what such a kernel needed instead, so a consumer does not carry a
 * version of it per project
 *
 * everything here is opt in and reports what it did. nothing is claimed to be
 * verified: the protections are not ours and the kernels that have them are not
 * the ones this was built against, so a call that cannot be made says so instead of
 * pretending
 */

/*
 * name the vendor entry point that decides whether a task is allowed to do
 * something, and this replaces it with one that always allows. the entry is found
 * in the function table it is published in, which is a pointer and not code, so no
 * text is written. returns 0 when the slot was replaced, -ENODATA when the symbol
 * or its slot cannot be found, which leaves the kernel untouched
 */
int vc_allow_entry(const char *name);

/* put the replaced entries back. safe to call when nothing was replaced */
void vc_exit(void);

/* how many entries this library replaced */
unsigned int vc_active(void);

#endif
