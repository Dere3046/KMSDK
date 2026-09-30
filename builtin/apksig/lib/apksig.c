// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * based on https://github.com/tiann/KernelSU
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/limits.h>
#include <linux/version.h>
#include <crypto/hash.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#include <linux/hex.h>
#endif

#include "kfile.h"
#include "apksig.h"

#define APK_EOCD_MAGIC		0x06054b50
#define APK_EOCD_SIZE		0x16
#define APK_EOCD_SCAN_MAX	0xffff
#define APK_ZIP64_LOCATOR	0x07064b50
#define APK_ZIP64_LOCATOR_OFF	0x14
#define APK_CD_MIN		0x20
#define APK_SIG_MAGIC		"APK Sig Block 42"
#define APK_SIG_MAGIC_LEN	0x10
#define APK_SIG_TAIL_SIZE	0x18
#define APK_V2_BLOCK_ID		0x7109871a
#define APK_VERITY_PADDING_ID	0x42726577
#define APK_CERT_MAX		1024
#define APK_HEX_LEN		(SHA256_DIGEST_SIZE * 2)

struct apk_sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct apk_sdesc *apk_sdesc_alloc(struct crypto_shash *alg)
{
	struct apk_sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kzalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);
	sdesc->shash.tfm = alg;
	return sdesc;
}

static int apk_sha256(const u8 *data, unsigned int len, u8 *digest)
{
	struct crypto_shash *alg;
	struct apk_sdesc *sdesc;
	int ret;

	alg = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(alg))
		return PTR_ERR(alg);

	sdesc = apk_sdesc_alloc(alg);
	if (IS_ERR(sdesc)) {
		crypto_free_shash(alg);
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, len, digest);
	kfree(sdesc);
	crypto_free_shash(alg);
	return ret;
}

int apksig_init(void)
{
	struct crypto_shash *alg;

	alg = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(alg))
		return PTR_ERR(alg);
	crypto_free_shash(alg);
	return 0;
}

void apksig_exit(void)
{
}

static bool apk_read(struct kfile_handle *h, void *buf, size_t len, loff_t *pos,
		     loff_t end)
{
	if (*pos < 0 || *pos > end || len > (size_t)(end - *pos))
		return false;
	if (kfile_pread(h, buf, len, *pos) != (ssize_t)len)
		return false;
	*pos += len;
	return true;
}

static bool apk_read_prefixed_end(struct kfile_handle *h, loff_t *pos,
				  loff_t container_end, loff_t *value_end)
{
	u32 len;

	if (!apk_read(h, &len, sizeof(len), pos, container_end))
		return false;
	if (len > INT_MAX || len > (u64)(container_end - *pos))
		return false;
	*value_end = *pos + len;
	return true;
}

static int apk_check_block(struct kfile_handle *h, loff_t *pos, loff_t block_end,
			   u32 expected_size, const char *expected_sha256_hex)
{
	loff_t signers_end, signer_end, signed_data_end, digests_end;
	loff_t certificates_end;
	u8 cert[APK_CERT_MAX];
	u8 digest[SHA256_DIGEST_SIZE];
	char hex[APK_HEX_LEN + 1];
	u32 cert_size;
	int ret;

	/* v2 block: signers sequence, first signer, signed data, digests */
	if (!apk_read_prefixed_end(h, pos, block_end, &signers_end) ||
	    !apk_read_prefixed_end(h, pos, signers_end, &signer_end) ||
	    !apk_read_prefixed_end(h, pos, signer_end, &signed_data_end) ||
	    !apk_read_prefixed_end(h, pos, signed_data_end, &digests_end))
		return -EINVAL;

	*pos = digests_end;
	if (!apk_read_prefixed_end(h, pos, signed_data_end, &certificates_end) ||
	    !apk_read(h, &cert_size, sizeof(cert_size), pos, certificates_end))
		return -EINVAL;
	if (cert_size > APK_CERT_MAX || cert_size > (u64)(certificates_end - *pos))
		return -EINVAL;
	if (cert_size != expected_size)
		return -EKEYREJECTED;
	if (!apk_read(h, cert, cert_size, pos, certificates_end))
		return -EINVAL;

	ret = apk_sha256(cert, cert_size, digest);
	if (ret)
		return ret;

	hex[APK_HEX_LEN] = '\0';
	bin2hex(hex, digest, SHA256_DIGEST_SIZE);
	if (strcmp(hex, expected_sha256_hex))
		return -EKEYREJECTED;
	return 0;
}

int apksig_fingerprint_v2(const char *path, u32 expected_size,
			  const char *expected_sha256_hex)
{
	u8 tail[APK_SIG_MAGIC_LEN];
	loff_t pos, pairs_end, file_size, eocd_offset;
	u32 cd_offset, cd_size, magic;
	u64 block_size, block_size_at_head;
	struct kfile_handle *h;
	int v2_blocks = 0;
	int ret;
	int i;

	if (!path || !expected_sha256_hex)
		return -EINVAL;
	if (strlen(expected_sha256_hex) != APK_HEX_LEN)
		return -EINVAL;

	h = kfile_open(path, true);
	if (IS_ERR(h))
		return PTR_ERR(h);

	file_size = kfile_size(h);
	if (file_size < APK_EOCD_SIZE) {
		ret = -EINVAL;
		goto out;
	}

	/* walk back from the end matching the comment length, capped at 0xffff */
	for (i = 0;; i++) {
		unsigned short comment_size;

		pos = file_size - i - 2;
		if (!apk_read(h, &comment_size, sizeof(comment_size), &pos,
			      file_size)) {
			ret = -EINVAL;
			goto out;
		}
		if (comment_size == i) {
			pos -= APK_EOCD_SIZE;
			if (!apk_read(h, &magic, sizeof(magic), &pos, file_size)) {
				ret = -EINVAL;
				goto out;
			}
			if (magic == APK_EOCD_MAGIC) {
				eocd_offset = pos - sizeof(magic);
				break;
			}
		}
		if (i == APK_EOCD_SCAN_MAX) {
			ret = -EINVAL;
			goto out;
		}
	}

	/* reject ZIP64 up front, its locator sits 20 bytes before the EOCD */
	if (eocd_offset >= APK_ZIP64_LOCATOR_OFF) {
		pos = eocd_offset - APK_ZIP64_LOCATOR_OFF;
		if (!apk_read(h, &magic, sizeof(magic), &pos, file_size)) {
			ret = -EINVAL;
			goto out;
		}
		if (magic == APK_ZIP64_LOCATOR) {
			ret = -EINVAL;
			goto out;
		}
	}

	pos = eocd_offset + 12;
	if (!apk_read(h, &cd_size, sizeof(cd_size), &pos, file_size)) {
		ret = -EINVAL;
		goto out;
	}
	if (!apk_read(h, &cd_offset, sizeof(cd_offset), &pos, file_size)) {
		ret = -EINVAL;
		goto out;
	}
	if ((u64)cd_offset > (u64)eocd_offset ||
	    (u64)cd_size != (u64)eocd_offset - cd_offset) {
		ret = -EINVAL;
		goto out;
	}
	if (cd_offset < APK_CD_MIN) {
		ret = -EINVAL;
		goto out;
	}

	/* signing block tail: 8 byte size plus the 16 byte magic, before the CD */
	pairs_end = (loff_t)cd_offset - APK_SIG_TAIL_SIZE;
	pos = pairs_end;
	if (!apk_read(h, &block_size, sizeof(block_size), &pos, cd_offset)) {
		ret = -EINVAL;
		goto out;
	}
	if (!apk_read(h, tail, sizeof(tail), &pos, cd_offset)) {
		ret = -EINVAL;
		goto out;
	}
	if (memcmp(tail, APK_SIG_MAGIC, sizeof(tail))) {
		ret = -EINVAL;
		goto out;
	}
	if (block_size < APK_SIG_TAIL_SIZE || block_size > INT_MAX - 0x8 ||
	    block_size > (u64)cd_offset - 0x8) {
		ret = -EINVAL;
		goto out;
	}

	pos = (loff_t)cd_offset - (loff_t)block_size - 0x8;
	if (!apk_read(h, &block_size_at_head, sizeof(block_size_at_head), &pos,
		      pairs_end)) {
		ret = -EINVAL;
		goto out;
	}
	if (block_size_at_head != block_size) {
		ret = -EINVAL;
		goto out;
	}

	/* walk length prefixed pairs, only v2 and verity padding ids are legal */
	ret = -EKEYREJECTED;
	while (pos < pairs_end) {
		u64 pair_size;
		loff_t pair_end;
		u32 id;

		if (!apk_read(h, &pair_size, sizeof(pair_size), &pos, pairs_end)) {
			ret = -EINVAL;
			break;
		}
		if (pair_size < sizeof(id) || pair_size > INT_MAX ||
		    pair_size > (u64)(pairs_end - pos)) {
			ret = -EINVAL;
			break;
		}

		pair_end = pos + (loff_t)pair_size;
		if (!apk_read(h, &id, sizeof(id), &pos, pair_end)) {
			ret = -EINVAL;
			break;
		}

		if (id == APK_V2_BLOCK_ID) {
			v2_blocks++;
			ret = apk_check_block(h, &pos, pair_end, expected_size,
					      expected_sha256_hex);
		} else if (id != APK_VERITY_PADDING_ID) {
			ret = -EINVAL;
			break;
		}
		pos = pair_end;
	}

	if (v2_blocks != 1)
		ret = -EKEYREJECTED;

out:
	kfile_close(h);
	return ret;
}

int apksig_pkg_from_path(const char *apk_path, char *out, size_t out_len)
{
	const char *last_slash = NULL;
	const char *second_last_slash = NULL;
	const char *hyphen;
	size_t len, pkg_len;
	int i;

	if (!apk_path || !out || !out_len)
		return -EINVAL;

	len = strlen(apk_path);
	if (!len || len > INT_MAX)
		return -EINVAL;

	for (i = (int)len - 1; i >= 0; i--) {
		if (apk_path[i] != '/')
			continue;
		if (!last_slash) {
			last_slash = &apk_path[i];
			continue;
		}
		second_last_slash = &apk_path[i];
		break;
	}
	if (!last_slash || !second_last_slash)
		return -EINVAL;

	/* package dir is <name> plus a random suffix, so the first hyphen ends it */
	hyphen = strchr(second_last_slash, '-');
	if (!hyphen || hyphen > last_slash)
		return -EINVAL;

	pkg_len = (size_t)(hyphen - second_last_slash - 1);
	if (!pkg_len)
		return -EINVAL;
	if (pkg_len + 1 > out_len)
		return -E2BIG;

	memcpy(out, second_last_slash + 1, pkg_len);
	out[pkg_len] = '\0';
	return 0;
}
