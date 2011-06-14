/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_JD_SOCKET_H_
#define	_JD_SOCKET_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>

struct fssock_option {
	const char *name;
	bool critical;
	int level;
	int optname;
	const void *optval;
	socklen_t optlen;
};

/*****************************************************************************
 *
 *****************************************************************************/
extern int fssock_add_fcntl(int, int);
extern int fssock_del_fcntl(int, int);
extern ssize_t fssock_set_option(int, const struct fssock_option *);
extern void fssock_close_socket(int);

#define	CLOSE(s_)				\
while ((s_) >= 0) {				\
	fssock_close_socket((s_));		\
	(s_) = -1;				\
}

#endif	/* !_JD_SOCKET_H_ */
