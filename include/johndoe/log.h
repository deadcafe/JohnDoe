/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_JD_LOG_H_
#define	_JD_LOG_H_

#include <syslog.h>

/*
 * API
 */
extern void jd_set_logger(void (*logger)(int, const char *, ...));

#endif	/* !_JD_LOG_H_ */
