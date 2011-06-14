/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#include <sys/types.h>

#include "johndoe/cipher/encrypt.h"
#include "johndoe/cipher/ikev2_iana.h"

#define	ARRAY_NUM(_a)	(sizeof(_a)/sizeof(_a[0]))

/*****************************************************************************
 *	Encryption
 *****************************************************************************/
static const struct encrypt_profile const profile_tbl[] = {
	{
		.private_id = ENCR_ID_NULL,
		.transform_id = IKEV2_IANA_ENCR_NULL,
		.name = "ENCR_NULL",
		.creator = EVP_enc_null,
	},
	{
		.private_id = ENCR_ID_3DES,
		.transform_id = IKEV2_IANA_ENCR_3DES,
		.name = "ENCR_3DES",
		.creator = EVP_des_ede3_cbc,
	},
	{
		.private_id = ENCR_ID_AES_128_CBC,
		.transform_id = IKEV2_IANA_ENCR_AES_CBC,
		.name = "ENCR_AES_128_CBC",
		.keylen = 128,
		.creator = EVP_aes_128_cbc,
	},
	{
		.private_id = ENCR_ID_AES_192_CBC,
		.transform_id = IKEV2_IANA_ENCR_AES_CBC,
		.name = "ENCR_AES_192_CBC",
		.keylen = 192,
		.creator = EVP_aes_192_cbc,
	},
	{
		.private_id = ENCR_ID_AES_256_CBC,
		.transform_id = IKEV2_IANA_ENCR_AES_CBC,
		.name = "ENCR_AES_256_CBC",
		.keylen = 256,
		.creator = EVP_aes_256_cbc,
	},
};

struct encrypt_ctx *
encrypt_create(int transform_id,
	       size_t keylen)
{
	struct encrypt_ctx *ctx = NULL;
	size_t i;

	for (i = 0; i < ARRAY_NUM(profile_tbl); i++) {
		if (profile_tbl[i].transform_id == transform_id &&
		    profile_tbl[i].keylen == keylen) {
			if ((ctx = malloc(sizeof(*ctx))) != NULL) {
				EVP_CIPHER_CTX_init(&ctx->ctx);
				ctx->method = (*profile_tbl[i].creator)();
				ctx->profile = &profile_tbl[i];
			}
			break;
		}
	}
	return ctx;
}

void
encrypt_destroy(struct encrypt_ctx *ctx)
{
	if (ctx) {
		EVP_CIPHER_CTX_cleanup(&ctx->ctx);
		free(ctx);
	}
}

size_t
encrypt_blocksize(const struct encrypt_ctx *ctx)
{
	return (size_t)EVP_CIPHER_block_size(ctx->method);
}

size_t
encrypt_keylen(const struct encrypt_ctx *ctx)
{
	return (size_t)EVP_CIPHER_key_length(ctx->method);
}

size_t
encrypt_ivlen(const struct encrypt_ctx *ctx)
{
	return (size_t)EVP_CIPHER_iv_length(ctx->method);
}

const char *
encrypt_name(const struct encrypt_ctx *ctx)
{
	return ctx->profile->name;
}

static ssize_t
encrypt_oneshot(int is_enc,
		const EVP_CIPHER * restrict method,
		EVP_CIPHER_CTX * restrict ctx,
		const void * restrict key,
		const void * restrict iv,
		const void * restrict in_p, size_t in_len,
		void * restrict buf_p, size_t buf_len)
{
	int pos = 0;
	ssize_t num = 0;
	unsigned char *buf = buf_p;
	ssize_t ret = -1;
	size_t blocklen = (size_t)EVP_CIPHER_block_size(method);
	size_t outlen;

	if (in_len % blocklen)
		outlen = ((in_len / blocklen) + 1) * blocklen;
	else
		outlen = in_len;
	if (outlen > buf_len)
		return -1;

	if (!EVP_CipherInit(ctx, method, key, iv, is_enc))
		goto end;

	if (!EVP_CipherUpdate(ctx, &buf[num], &pos, in_p, in_len))
		goto end;
	num += pos;
	if (!EVP_CipherFinal(ctx, &buf[num], &pos))
		goto end;
	num += pos;
	ret = num;
end:
	EVP_CIPHER_CTX_cleanup(ctx);
	return ret;
}

ssize_t
encrypt_encrypt(struct encrypt_ctx * restrict ctx,
	       const void * restrict key,
	       const void * restrict iv,
	       const void * restrict in_p, size_t in_len,
	       void * restrict out_p, size_t out_len)
{
	return encrypt_oneshot(1, ctx->method, &ctx->ctx, key, iv,
			       in_p, in_len, out_p, out_len);
}

ssize_t
encrypt_decrypt(struct encrypt_ctx * restrict ctx,
		const void * restrict key,
		const void * restrict iv,
		const void * restrict in_p, size_t in_len,
		void * restrict out_p, size_t out_len)
{
	return encrypt_oneshot(0, ctx->method, &ctx->ctx, key, iv,
			       in_p, in_len, out_p, out_len);
}

