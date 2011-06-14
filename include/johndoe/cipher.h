/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_JD_CIPHER_H_
#define	_JD_CIPHER_H_

#include <openssl/aes.h>
#include <openssl/evp.h>

#include <johndoe/cipher/encrypt.h>
#include <johndoe/cipher/prf.h>
#include <johndoe/cipher/integrity.h>
#include <johndoe/cipher/diffiehellman.h>

/*****************************************************************************
 *	common
 *****************************************************************************/
extern int cipher_init(void);
extern void cipher_exit(void);

#endif	/* !_JD_CIPHER_H_ */
