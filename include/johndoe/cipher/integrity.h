/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_JD_INTEGRITY_H_
#define	_JD_INTEGRITY_H_

#include <johndoe/cipher/digest.h>

/*****************************************************************************
 *	Integrity
 *****************************************************************************/

/*
 *	Private ID of Integrity
 */
enum {
	AUTH_ID_NONE,		/* dummy */
	AUTH_ID_HMAC_MD5_96,
	AUTH_ID_HMAC_SHA1_96,
	AUTH_ID_AES_XCBC_96,
	AUTH_ID_HMAC_MD5_128,
	AUTH_ID_HMAC_SHA1_160,
	AUTH_ID_AES_CMAC_96,
	AUTH_ID_HMAC_SHA2_256_128,
	AUTH_ID_HMAC_SHA2_384_192,
	AUTH_ID_HMAC_SHA2_512_256,
};

extern struct digest_ctx *auth_create(int);
extern struct digest_ctx *auth_create_byid(int);
extern void auth_destroy(struct digest_ctx *);
extern ssize_t auth_oneshot(struct digest_ctx * restrict,
			    const void * restrict, size_t,
			    const void * restrict, size_t,
			    void * restrict, size_t);
extern int auth_verify(struct digest_ctx * restrict,
		       const void * restrict, size_t,
		       const void * restrict, size_t,
		       void * restrict);

#endif	/* !_JD_INTEGRITY_H_ */
