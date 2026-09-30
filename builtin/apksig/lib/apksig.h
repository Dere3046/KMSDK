// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#ifndef APKSIG_H
#define APKSIG_H

#include <linux/types.h>

int apksig_init(void);
void apksig_exit(void);

/*
 * Fingerprint compare only: parse the ZIP structure, take the first certificate
 * of the v2 signing block and compare its length and sha256. No ASN.1 parsing,
 * no RSA or ECDSA verification, no v3 and no signing lineage. Return 0 on a
 * match, a negative errno such as EKEYREJECTED otherwise. The optional second
 * fingerprint is left to the caller, which simply calls this twice.
 */
int apksig_fingerprint_v2(const char *path, u32 expected_size,
			  const char *expected_sha256_hex);

/* package name from a base.apk path, 0 on success, E2BIG negative if too small */
int apksig_pkg_from_path(const char *apk_path, char *out, size_t out_len);

#endif
