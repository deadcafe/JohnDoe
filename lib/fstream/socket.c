/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>

#include "johndoe/socket.h"
#include "log.h"

int
fssock_add_fcntl(int fd,
		 int opt)
{
	ERRBUFF();
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags == -1) {
		LOG(LOG_INFO, "failed at fcntl: %s\n", STRERR(errno));
		return -1;
	}

	LOG(LOG_DEBUG, "fd: %d  opt: %x  flags: %x\n", fd, opt, flags);
	if (flags & opt)
		return 0;
	flags |= opt;
	return fcntl(fd, F_SETFL, flags);
}

int
fssock_del_fcntl(int fd,
		 int opt)
{
	ERRBUFF();
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags == -1) {
		LOG(LOG_INFO, "failed at fcntl: %s\n", STRERR(errno));
		return -1;
	}

	LOG(LOG_DEBUG, "fd: %d  opt: x\n", fd, opt);
	if (!(flags & opt))
		return 0;
	flags &= ~opt;
	return fcntl(fd, F_SETFL, flags);
}

ssize_t
fssock_set_option(int fd,
		  const struct fssock_option *tbl)
{
	ssize_t i;
	int ecode = 0;
	ERRBUFF();

	for (i = 0; tbl[i].name; i++) {
		if (setsockopt(fd, tbl[i].level, tbl[i].optname,
			      tbl[i].optval, tbl[i].optlen) < 0) {
			ecode = errno;
			LOG(LOG_NOTICE,
			    "fd: %d option %s failed: %s\n", STRERR(ecode));

			if (tbl[i].critical)
				return -1;
		}
	}
	errno = ecode;
	return i;
}

void
fssock_close_socket(int sock)
{
	int backup = errno;

	LOG(LOG_DEBUG, "%d closed\n", sock);
	while (close(sock)) {
		if (errno != EINTR) {
			ERRBUFF();
			LOG(LOG_WARNING, "%d close failed: %s\n",
			    sock, STRERR(errno));
			break;
		}
	}
	errno = backup;
}
