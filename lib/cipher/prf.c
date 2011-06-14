/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "johndoe/cipher/ikev2_iana.h"
#include "johndoe/cipher/prf.h"

/*****************************************************************************
 *	Pseudo-random Function
 *****************************************************************************/
static const struct digest_profile const profile[] = {
	{
		.private_id = PRF_ID_NULL,
		.transform_id = IKEV2_IANA_PRF_NULL,
		.block_size = 0,
		.output_size = 0,	/* 1? */
		.name = "PRF_NULL",
		.digest = EVP_md_null,
		.method = &digest_method_hmac,
	},
	{
		.private_id = PRF_ID_HMAC_MD5,
		.transform_id = IKEV2_IANA_PRF_HMAC_MD5,
		.block_size = 64,
		.output_size = 16,
		.name = "PRF_HMAC_MD5",
		.digest = EVP_md5,
		.method = &digest_method_hmac,
	},
	{
		.private_id = PRF_ID_HMAC_SHA1,
		.transform_id = IKEV2_IANA_PRF_HMAC_SHA1,
		.block_size = 64,
		.output_size = 20,
		.name = "PRF_HMAC_SHA1",
		.digest = EVP_sha1,
		.method = &digest_method_hmac,
	},
	{
		.private_id = PRF_ID_AES128_XCBC,
		.transform_id = IKEV2_IANA_PRF_AES128_XCBC,
		.block_size = AES_BLOCK_SIZE,
		.output_size = AES_BLOCK_SIZE,
		.name = "PRF_AES128_XCBC",
		.method = &digest_method_aes_xcbc,
	},
	{
		.private_id = PRF_ID_HMAC_SHA_256,
		.transform_id = IKEV2_IANA_PRF_HMAC_SHA2_256,
		.block_size = 64,
		.output_size = 32,
		.name = "PRF_HMAC_SHA_256",
		.digest = EVP_sha256,
		.method = &digest_method_hmac,
	},
	{
		.private_id = PRF_ID_HMAC_SHA_384,
		.transform_id = IKEV2_IANA_PRF_HMAC_SHA2_384,
		.block_size = 128,
		.output_size = 48,
		.name = "PRF_HMAC_SHA_384",
		.digest = EVP_sha384,
		.method = &digest_method_hmac,
	},
	{
		.private_id = PRF_ID_HMAC_SHA_512,
		.transform_id = IKEV2_IANA_PRF_HMAC_SHA2_512,
		.block_size = 128,
		.output_size = 64,
		.name = "PRF_HMAC_SHA_512",
		.digest = EVP_sha512,
		.method = &digest_method_hmac,
	},
	{
		.private_id = PRF_ID_AES128_CMAC,
		.transform_id = IKEV2_IANA_PRF_AES128_CMAC,
		.block_size = AES_BLOCK_SIZE,
		.output_size = AES_BLOCK_SIZE,
		.name = "PRF_AES128_CMAC",
		.method = &digest_method_aes_cmac,
	},
};

struct digest_ctx *
prf_create(int transform_id)
{
	return digest_create(transform_id, profile, ARRAY_NUM(profile));
}

struct digest_ctx *
prf_create_byid(int private_id)
{
	return digest_create_byid(private_id, profile, ARRAY_NUM(profile));
}

void
prf_destroy(struct digest_ctx *ctx)
{
	digest_destroy(ctx);
}

ssize_t
prf_oneshot(struct digest_ctx * restrict ctx,
	    const void * restrict key, size_t key_len,
	    const void * restrict data, size_t data_len,
	    void * restrict buf_p, size_t buf_len)
{
	return digest_oneshot(ctx, key, key_len, data, data_len,
			      buf_p, buf_len);
}
