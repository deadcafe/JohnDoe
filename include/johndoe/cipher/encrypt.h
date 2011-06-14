/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_JD_ENCRYPT_H_
#define	_JD_ENCRYPT_H_

#include <sys/types.h>
#include <openssl/evp.h>

/*****************************************************************************
 *	Encryption
 *****************************************************************************/
struct encrypt_profile {
	int private_id;
	int transform_id;
	size_t keylen;		/* bit */
	const char * const name;
	const EVP_CIPHER *(*creator)(void);
};

struct encrypt_ctx {
	const struct encrypt_profile *profile;
	const EVP_CIPHER *method;
	EVP_CIPHER_CTX ctx;
};

/*
 * private ID
 */
enum {
	ENCR_ID_NULL = 0,
	ENCR_ID_3DES,
	ENCR_ID_AES_128_CBC,
	ENCR_ID_AES_192_CBC,
	ENCR_ID_AES_256_CBC,
};

extern struct encrypt_ctx *encrypt_create(int, size_t);
extern void encrypt_destroy(struct encrypt_ctx *);
extern size_t encrypt_blocksize(const struct encrypt_ctx *);
extern size_t encrypt_keylen(const struct encrypt_ctx *);
extern size_t encrypt_ivlen(const struct encrypt_ctx *);
extern const char * encrypt_name(const struct encrypt_ctx *);
extern ssize_t encrypt_encrypt(struct encrypt_ctx * restrict,
			       const void * restrict,
			       const void * restrict ,
			       const void * restrict, size_t,
			       void * restrict, size_t);
extern ssize_t encrypt_decrypt(struct encrypt_ctx * restrict,
			       const void * restrict,
			       const void * restrict,
			       const void * restrict, size_t,
			       void * restrict, size_t);

#endif	/* !_JD_ENCRYPT_H_ */
