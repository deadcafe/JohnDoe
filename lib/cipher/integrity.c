/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <string.h>

#include "johndoe/cipher/integrity.h"
#include "johndoe/cipher/ikev2_iana.h"

/*****************************************************************************
 *	Integrity
 *****************************************************************************/

static const struct digest_profile const profile[] = {
	{
		.private_id = AUTH_ID_NONE,
		.transform_id = IKEV2_IANA_AUTH_NONE,
		.block_size = 0,
		.output_size = 0,
		.name = "AUTH_NONE",
		.digest = EVP_md_null,
	},
	{
		.private_id = AUTH_ID_HMAC_MD5_96,
		.transform_id = IKEV2_IANA_AUTH_HMAC_MD5_96,
		.block_size = 64,
		.output_size = 16,
		.auth_size = 12,
		.name = "AUTH_HMAC_MD5_96",
		.digest = EVP_md5,
	},
	{
		.private_id = AUTH_ID_HMAC_SHA1_96,
		.transform_id = IKEV2_IANA_AUTH_HMAC_SHA1_96,
		.block_size = 64,
		.output_size = 20,
		.auth_size = 12,
		.name = "AUTH_HMAC_SHA1_96",
		.digest = EVP_sha1,
	},
	{
		.private_id = AUTH_ID_AES_XCBC_96,
		.transform_id = IKEV2_IANA_AUTH_AES_XCBC_96,
		.block_size = AES_BLOCK_SIZE,
		.output_size = AES_BLOCK_SIZE,
		.auth_size = 12,
		.name = "AUTH_AES_XCBC_96",
	},
	{
		.private_id = AUTH_ID_HMAC_MD5_128,
		.transform_id = IKEV2_IANA_AUTH_HMAC_MD5_128,
		.block_size = 64,
		.output_size = 16,
		.auth_size = 16,
		.name = "AUTH_HMAC_MD5_128",
		.digest = EVP_md5,
	},
	{
		.private_id = AUTH_ID_HMAC_SHA1_160,
		.transform_id = IKEV2_IANA_AUTH_HMAC_SHA1_160,
		.block_size = 64,
		.output_size = 20,
		.auth_size = 20,
		.name = "AUTH_HMAC_SHA1_160",
		.digest = EVP_sha1,
	},
	{
		.private_id = AUTH_ID_AES_CMAC_96,
		.transform_id = IKEV2_IANA_AUTH_AES_CMAC_96,
		.block_size = AES_BLOCK_SIZE,
		.output_size = AES_BLOCK_SIZE,
		.auth_size = 12,
		.name = "AUTH_AES_CMAC_96",
	},
	{
		.private_id = AUTH_ID_HMAC_SHA2_256_128,
		.transform_id = IKEV2_IANA_AUTH_HMAC_SHA2_256_128,
		.block_size = 64,
		.output_size = 32,
		.auth_size = 16,
		.name = "AUTH_HMAC_SHA2_256_128",
		.digest = EVP_sha256,
	},
	{
		.private_id = AUTH_ID_HMAC_SHA2_384_192,
		.transform_id = IKEV2_IANA_AUTH_HMAC_SHA2_384_192,
		.block_size = 128,
		.output_size = 48,
		.auth_size = 24,
		.name = "AUTH_HMAC_SHA2_384_192",
		.digest = EVP_sha384,
	},
	{
		.private_id = AUTH_ID_HMAC_SHA2_512_256,
		.transform_id = IKEV2_IANA_AUTH_HMAC_SHA2_512_256,
		.block_size = 128,
		.output_size = 64,
		.auth_size = 32,
		.name = "AUTH_HMAC_SHA2_512_256",
		.digest = EVP_sha512,
	},
};

/*
 *
 */
struct digest_ctx *
auth_create(int transform_id)
{
	return digest_create(transform_id, profile, ARRAY_NUM(profile));
}

struct digest_ctx *
auth_create_byid(int private_id)
{
	return digest_create_byid(private_id, profile, ARRAY_NUM(profile));
}

void
auth_destroy(struct digest_ctx *ctx)
{
	digest_destroy(ctx);
}

ssize_t
auth_oneshot(struct digest_ctx * restrict ctx,
	     const void * restrict key, size_t key_len,
	     const void * restrict data, size_t data_len,
	     void * restrict buf_p, size_t buf_len)
{
	return digest_oneshot(ctx, key, key_len, data, data_len,
			      buf_p, buf_len);
}

int
auth_verify(struct digest_ctx * restrict ctx,
	    const void * restrict key, size_t key_len,
	    const void * restrict data, size_t data_len,
	    void * restrict icv)
{
	unsigned char buf[512];
	ssize_t len;
	int ret = -1;

	len = digest_oneshot(ctx, key, key_len, data, data_len,
			     buf, sizeof(buf));
	if ((size_t)len >= ctx->profile->auth_size)
		ret = memcmp(icv, buf, ctx->profile->auth_size);
	return ret;
}


