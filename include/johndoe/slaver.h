/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_JD_SLAVER_H_
#define	_JD_SLAVER_H_

#include <sys/types.h>
#include <inttypes.h>
#include <stdbool.h>

#include "johndoe/fstream.h"

struct slaver_config {
	/* for socket handler */
	int domain;
	int protocol;
	const char *addr;
	uint16_t port;
	size_t msg_pl_size;

	void (*msg_handler)(void *,
			    struct fstream *,
			    const struct fstream_msg *);
	void (*err_handler)(void *,
			    struct fstream *,
			    int);

	/* for slaver */
	void * (*slaver_entry)(void *);
	void *ctx;
};

extern int jd_slaver_start(struct slaver_config *, bool);

#endif	/* !_JD_SLAVER_H_ */
