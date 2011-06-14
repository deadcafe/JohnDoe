/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_JD_PRF_H_
#define	_JD_PRF_H_

#include <sys/types.h>
#include <johndoe/cipher/digest.h>

/*****************************************************************************
 *	Pseudo-random Function
 *****************************************************************************/
/*
 *	Private ID of PRF
 */
enum {
	PRF_ID_NULL,		/* dummy */
	PRF_ID_HMAC_MD5,
	PRF_ID_HMAC_SHA1,
	PRF_ID_AES128_XCBC,
	PRF_ID_HMAC_SHA_256,
	PRF_ID_HMAC_SHA_384,
	PRF_ID_HMAC_SHA_512,
	PRF_ID_AES128_CMAC,
};

extern struct digest_ctx *prf_create(int);
extern struct digest_ctx *prf_create_byid(int);
extern void prf_destroy(struct digest_ctx *);
extern ssize_t prf_oneshot(struct digest_ctx * restrict,
			   const void * restrict, size_t,
			   const void * restrict, size_t,
			   void * restrict, size_t);

#endif	/* !_JD_PRF_H_ */
