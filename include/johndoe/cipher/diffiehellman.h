/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_JD_DIFFIEHELLMAN_H_
#define	_JD_DIFFIEHELLMAN_H_

#include <sys/types.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

/*****************************************************************************
 *	Diffie-Hellman
 *****************************************************************************/
struct dh_profile {
	int private_id;
	int transform_id;
	const char *name;
	BIGNUM prime;
	BIGNUM generator;
	long exponent;
};

struct dh_ctx {
	const struct dh_profile *profile;
	DH *dh;
	BIGNUM peer_pub;

	size_t key_len;
	unsigned char *key;
	size_t buf_size;
	void *buf;
};

enum {
	DH_ID_NONE = 0,
	DH_ID_MODP_768,
	DH_ID_MODP_1024,
	DH_ID_MODP_1536,
	DH_ID_MODP_2048,
	DH_ID_MODP_3072,
	DH_ID_MODP_4096,
	DH_ID_MODP_6144,
	DH_ID_MODP_8192,
	DH_ID_MODP_1024_PRIME_160,
	DH_ID_MODP_2048_PRIME_224,
	DH_ID_MODP_2048_PRIME_256,
};

extern struct dh_ctx *dh_create(int, int);
extern struct dh_ctx *dh_create_byid(int, int);
extern void dh_destroy(struct dh_ctx *);
extern int dh_generate_key(struct dh_ctx *);
extern int dh_compute_key(struct dh_ctx * restrict, const void * restrict,
			  size_t);
extern void dh_cleanup(struct dh_ctx *);
extern size_t dh_size(const struct dh_ctx *);
extern size_t dh_size_pubkey(const struct dh_ctx *);
extern size_t dh_read_pubkey(const struct dh_ctx * restrict, void * restrict);
extern size_t dh_size_privkey(const struct dh_ctx *);
extern size_t dh_read_privkey(const struct dh_ctx * restrict, void * restrict);
extern size_t dh_size_sharedkey(const struct dh_ctx *);
extern size_t dh_read_sharedkey(const struct dh_ctx * restrict,
				void * restrict);
extern void test_prime1024_160(void (*)(const void *, size_t));

/*
 * don't use
 */
extern const char * dh_init(void);
extern void dh_exit(void);

#endif	/* !_JD_DIFFIEHELLMAN_H_ */
