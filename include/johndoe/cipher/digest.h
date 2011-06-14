/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_JD_DIGEST_H_
#define	_JD_DIGEST_H_

#include <sys/types.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

#define	ARRAY_NUM(_a)	(sizeof(_a)/sizeof(_a[0]))
#define REPEAT4(x_)     x_, x_, x_, x_
#define REPEAT16(x_)    REPEAT4(x_), REPEAT4(x_), REPEAT4(x_), REPEAT4(x_)

struct digest_ctx;

struct digest_method {
	void (*init_ctx)(struct digest_ctx *);
	void (*cleanup_ctx)(struct digest_ctx *);

	ssize_t (*init)(struct digest_ctx * restrict, const void * restrict,
			size_t);
	ssize_t (*update)(struct digest_ctx * restrict, const void * restrict,
			  size_t);
	ssize_t (*final)(struct digest_ctx * restrict, void * restrict);
};

struct digest_profile {
	int private_id;
	int transform_id;

	size_t block_size;
	size_t output_size;
	size_t auth_size;	/* for authentication */

	const char * const name;
	const EVP_MD *(*digest)(void);
	const struct digest_method *method;
};

typedef struct aes_mac_ctx {
        AES_KEY k1;
        unsigned char k2[AES_BLOCK_SIZE];
        unsigned char k3[AES_BLOCK_SIZE];
        unsigned char e[AES_BLOCK_SIZE];
        unsigned char m[AES_BLOCK_SIZE];
        size_t mlen;
} AES_CTX;


struct digest_ctx {
	const struct digest_profile *profile;
	union {
		HMAC_CTX md;
		AES_CTX aes;
	} u;
};


extern const struct digest_method digest_method_aes_xcbc;
extern const struct digest_method digest_method_aes_cmac;
extern const struct digest_method digest_method_hmac;

extern struct digest_ctx *digest_create(int, const struct digest_profile *,
					size_t);
extern struct digest_ctx *digest_create_byid(int, const struct digest_profile *,
					     size_t);
extern void digest_destroy(struct digest_ctx *);
extern void digest_dump_profile(const struct digest_ctx * restrict,
				FILE * restrict);
extern ssize_t digest_oneshot(struct digest_ctx * restrict,
			      const void * restrict, size_t,
			      const void * restrict, size_t,
			      void * restrict, size_t);

#endif	/* !_JD_DIGEST_H_ */
