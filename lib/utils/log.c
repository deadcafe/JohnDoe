/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_GNU_SOURCE
# define _GNU_SOURCE
#endif

#include "log.h"

void (*jd_log_cb)(int, const char *, ...);

void
jd_set_logger(void (*logger)(int, const char *, ...))
{
	jd_log_cb = logger;
}
