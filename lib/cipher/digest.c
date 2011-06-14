/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "johndoe/cipher/digest.h"

static const unsigned char ZERO[AES_BLOCK_SIZE] = { REPEAT16(0) };

/*
 * AES-XCBC-MAC (RFC3664) / AES-XCBC-PRF-128 (RFC4434) / RFC3566
 */
static void
aes_init_ctx(struct digest_ctx *ctx)
{
	memset(ctx->u.aes.e, 0, sizeof(ctx->u.aes.e));
	ctx->u.aes.mlen = 0;
}

static void
aes_cleanup_ctx(struct digest_ctx *ctx)
{
	memset(&ctx->u.aes, 0, sizeof(ctx->u.aes));
}

static ssize_t
aes_xcbc_mac_init(struct digest_ctx * restrict ctx,
		  const void * restrict key,
		  size_t keylen)
{
	const unsigned char c1[AES_BLOCK_SIZE] = { REPEAT16(1) };
	const unsigned char c2[AES_BLOCK_SIZE] = { REPEAT16(2) };
	const unsigned char c3[AES_BLOCK_SIZE] = { REPEAT16(3) };
	unsigned char k_org[AES_BLOCK_SIZE];
	unsigned char k1[AES_BLOCK_SIZE];
	AES_KEY k;

	if (keylen == AES_BLOCK_SIZE)
		memcpy(k_org, key, AES_BLOCK_SIZE);
	else if (keylen < AES_BLOCK_SIZE) {
		memcpy(k_org, key, keylen);
		memset(&k_org[keylen], 0, AES_BLOCK_SIZE - keylen);
	} else {
		ssize_t ret;

		ret = digest_oneshot(ctx, ZERO, sizeof(ZERO),
				     key, keylen, k_org, sizeof(k_org));
		if (ret < 0)
			return ret;
		(*ctx->profile->method->init_ctx)(ctx);
	}

	if (!AES_set_encrypt_key(k_org, sizeof(k_org) * 8, &k))
		return -1;
	AES_encrypt(c1, k1, &k);

	if (!AES_set_encrypt_key(k1, sizeof(k1) * 8, &ctx->u.aes.k1))
		return -1;
	AES_encrypt(c2, ctx->u.aes.k2, &k);
	AES_encrypt(c3, ctx->u.aes.k3, &k);
	return 0;
}

static ssize_t
aes_xcbc_mac_update(struct digest_ctx * restrict ctx,
		    const void * restrict data,
		    size_t len)
{
	const unsigned char *p = data;

	while (len) {
		size_t l;

		if (ctx->u.aes.mlen == AES_BLOCK_SIZE) {
			int i;

			for (i = 0; i < AES_BLOCK_SIZE; i++)
				ctx->u.aes.m[i] ^= ctx->u.aes.e[i];
			AES_encrypt(ctx->u.aes.m, ctx->u.aes.e, &ctx->u.aes.k1);
			ctx->u.aes.mlen = 0;
		}
		l = len;
		if (l > AES_BLOCK_SIZE - ctx->u.aes.mlen)
			l = AES_BLOCK_SIZE - ctx->u.aes.mlen;
		memcpy(&ctx->u.aes.m[ctx->u.aes.mlen], p, l);
		ctx->u.aes.mlen += l;
		len -= l;
		p += l;
	}
	return 0;
}

static ssize_t
aes_xcbc_mac_final(struct digest_ctx * restrict ctx,
		   void * restrict buf)
{
	size_t i;

	if (ctx->u.aes.mlen == AES_BLOCK_SIZE) {
		for (i = 0; i < AES_BLOCK_SIZE; i++)
			ctx->u.aes.m[i] ^= ctx->u.aes.e[i] ^ ctx->u.aes.k2[i];
	} else {
		ctx->u.aes.m[ctx->u.aes.mlen] = 0x80;
		for (i = ctx->u.aes.mlen + 1; i < AES_BLOCK_SIZE; i++)
			ctx->u.aes.m[i] = 0;
		for (i = 0; i < AES_BLOCK_SIZE; i++)
			ctx->u.aes.m[i] ^= ctx->u.aes.e[i] ^ ctx->u.aes.k3[i];
	}
	AES_encrypt(ctx->u.aes.m, buf, &ctx->u.aes.k1);
	return AES_BLOCK_SIZE;
}

const struct digest_method digest_method_aes_xcbc = {
	.init_ctx = aes_init_ctx,
	.cleanup_ctx = aes_cleanup_ctx,
	.init = aes_xcbc_mac_init,
	.update = aes_xcbc_mac_update,
	.final = aes_xcbc_mac_final,
};

/*
 * CMAC RFC4493
 */
static inline void
gf_mult(unsigned char *l,
        unsigned char *k,
        unsigned char r)
{
        int i;
        int carryover;

        carryover = 0;
        for (i = AES_BLOCK_SIZE; --i >= 0;) {
		int value;

                value = l[i] << 1;
                k[i] = value | carryover;
                carryover = value >> 8;
        }
        if (carryover)
                k[AES_BLOCK_SIZE - 1] ^= r;
}

static ssize_t
aes_cmac_init(struct digest_ctx * restrict ctx,
	      const void * restrict key,
	      size_t key_len)
{
	unsigned char K[AES_BLOCK_SIZE];
	unsigned char L[AES_BLOCK_SIZE];
#define	R128	0x87

	if (key_len == AES_BLOCK_SIZE) {
		memcpy(K, key, sizeof(K));
	} else if (key_len < AES_BLOCK_SIZE) {
		memcpy(K, key, key_len);
		memset(&K[key_len], 0, sizeof(K) - key_len);
	} else {
		ssize_t ret;

		ret = digest_oneshot(ctx, ZERO, sizeof(ZERO),
				     key, key_len, K, sizeof(K));
		if (ret < 0)
			return ret;
		(*ctx->profile->method->init_ctx)(ctx);
	}

	if (AES_set_encrypt_key(K, sizeof(K) * 8, &ctx->u.aes.k1))
		return -1;
	AES_encrypt(ZERO, L, &ctx->u.aes.k1);
	gf_mult(L, ctx->u.aes.k2, R128);
	gf_mult(ctx->u.aes.k2, ctx->u.aes.k3, R128);

	memset(K, 0, sizeof(K));
	memset(L, 0, sizeof(L));
	return 0;
}

const struct digest_method digest_method_aes_cmac = {
	.init_ctx = aes_init_ctx,
	.cleanup_ctx = aes_cleanup_ctx,
	.init = aes_cmac_init,
	.update = aes_xcbc_mac_update,
	.final = aes_xcbc_mac_final,
};

/*
 *	HMAC
 */
static void
hmac_init_ctx(struct digest_ctx *ctx)
{
	HMAC_CTX_init(&ctx->u.md);
}

static void
hmac_cleanup_ctx(struct digest_ctx *ctx)
{
	HMAC_CTX_cleanup(&ctx->u.md);
}

static ssize_t
hmac_init(struct digest_ctx * restrict ctx,
	  const void * restrict key,
	  size_t key_len)
{
	HMAC_Init(&ctx->u.md, key, key_len, (*ctx->profile->digest)());
	return 0;
}

static ssize_t
hmac_update(struct digest_ctx * restrict ctx,
	    const void * restrict data,
	    size_t data_len)
{
	HMAC_Update(&ctx->u.md, data, data_len);
	return 0;
}

static ssize_t
hmac_final(struct digest_ctx * restrict ctx,
	   void * restrict buf_p)
{
	unsigned char *buf = buf_p;
	unsigned int len = 0;

	HMAC_Final(&ctx->u.md, buf, &len);
	return (ssize_t)len;
}

const struct digest_method digest_method_hmac = {
	.init_ctx = hmac_init_ctx,
	.cleanup_ctx = hmac_cleanup_ctx,
	.init = hmac_init,
	.update = hmac_update,
	.final = hmac_final,
};

/*
 * Digest API
 */
struct digest_ctx *
digest_create(int transform_id,
	      const struct digest_profile *profile,
	      size_t num)
{
	struct digest_ctx *ctx = NULL;
	size_t i;

	for (i = 0; i < num; i++) {
		if (profile[i].transform_id == transform_id) {
			if ((ctx = malloc(sizeof(*ctx))) != NULL) {
				ctx->profile = &profile[i];
				(*ctx->profile->method->init_ctx)(ctx);
			}
			break;
		}
	}
	return ctx;
}

struct digest_ctx *
digest_create_byid(int private_id,
		   const struct digest_profile *profile,
		   size_t num)
{
	struct digest_ctx *ctx = NULL;
	size_t i;

	for (i = 0; i < num; i++) {
		if (profile[i].private_id == private_id) {
			if ((ctx = malloc(sizeof(*ctx))) != NULL) {
				ctx->profile = &profile[i];
				(*ctx->profile->method->init_ctx)(ctx);
			}
			break;
		}
	}
	return ctx;
}

void
digest_destroy(struct digest_ctx *ctx)
{
	if (ctx) {
		(*ctx->profile->method->cleanup_ctx)(ctx);
		free(ctx);
	}
}

void
digest_dump_profile(const struct digest_ctx * restrict ctx,
		    FILE * restrict fp)
{
	fprintf(fp,
		"%s: block_size:%lu output_size:%lu\n",
		ctx->profile->name,
		ctx->profile->block_size,
		ctx->profile->output_size);
}

ssize_t
digest_oneshot(struct digest_ctx * restrict ctx,
	       const void * restrict key, size_t key_len,
	       const void * restrict data, size_t data_len,
	       void * restrict buf_p, size_t buf_len)
{
	ssize_t len = -EINVAL;

	if (buf_len < ctx->profile->output_size)
		goto end;

	if ((len = (*ctx->profile->method->init)(ctx, key, key_len)) != 0)
		goto end;

	if ((len = (*ctx->profile->method->update)(ctx, data, data_len)) != 0)
		goto end;

	len = (*ctx->profile->method->final)(ctx, buf_p);

end:
	(*ctx->profile->method->cleanup_ctx)(ctx);
	return len;
}
