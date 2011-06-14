/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_LIBS_LOG_H_
#define	_LIBS_LOG_H_

#ifndef _GNU_SOURCE
# error "not defined _GNU_SOURCE\n"
#endif

#include <sys/types.h>
#include <errno.h>
#include <string.h>

#include "johndoe/log.h"

#define	ARRAY_SIZE(a)	(sizeof(a)/sizeof(a[0]))

#define	ERR_BUFFER_SIZE	128
#define ERRBUFF()	char _errbuff[ERR_BUFFER_SIZE]
#define	STRERR(n)	(wrap_strerr((n), _errbuff, sizeof(_errbuff)))

static inline char *
wrap_strerr(int ecode,
	    char *buff,
	    size_t size)
{
	int backup = errno;
	char *p = strerror_r(ecode, buff, size);

	errno = backup;
	return p;
}

#define LOG(lv_, fmt_, ...)                                             \
do {                                                                    \
        if (jd_log_cb) {						\
		int _backup = errno;					\
                (*jd_log_cb)((lv_), "%s:%d: " fmt_,			\
				  __FUNCTION__, __LINE__, ##__VA_ARGS__); \
		errno = _backup;					\
	}								\
} while (0)

extern void (*jd_log_cb)(int, const char *, ...);

#endif	/* !_LIBS_LOG_H_ */
