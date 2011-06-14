/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <event.h>
#include <stdbool.h>

#include "johndoe/socket.h"
#include "johndoe/command.h"
#include "log.h"

struct cli_ctx {
	int sd;
	void (*err_cb)(void *, int);
	void *user_ctx;
	struct sock_info *console;
	struct sock_info *remote;
	struct timeval tout;
	struct event evt;
	int used;
};

struct sock_info {
	struct cli_ctx *ctx;
        const char *name;
	struct sock_info *another;
        int src;
        int dst;
        struct event evt;
};

/*****************************************************************************
 *	destroyers
 ****************************************************************************/
static void
destroy_sock_info(struct sock_info *info)
{
	ERRBUFF();

	LOG(LOG_DEBUG, "trace info: %p(%s)\n", info, info->name);

	if (info) {
		if (info->ctx) {
			if (event_del(&info->evt))
				LOG(LOG_NOTICE, "failed at event_del: %s\n",
				    STRERR(errno));
			info->ctx = NULL;
		}
		if (info->another) {
			info->another->another = NULL;
			info->another = NULL;
		}
		free(info);
	}
}

static void
destroy_cli_ctx(struct cli_ctx *ctx,
		int ecode)
{
	ERRBUFF();

	LOG(LOG_DEBUG, "trace ctx: %p  ecode: %d\n", ctx, ecode);

	if (ctx->console) {
		destroy_sock_info(ctx->console);
		ctx->console = NULL;
	}
	if (ctx->remote) {
		destroy_sock_info(ctx->remote);
		ctx->remote = NULL;
	}
	if (ctx->used) {
		if (event_del(&ctx->evt))
			LOG(LOG_NOTICE, "failed at event_del: %s\n",
			    STRERR(errno));
		ctx->used = 0;
	}
	if (ctx->sd > 0) {
		CLOSE(ctx->sd);
		ctx->sd = -1;
	}
	if (ecode && ctx->err_cb) {
		(*ctx->err_cb)(ctx->user_ctx, ecode);
		ctx->err_cb = NULL;
	}
	free(ctx);
}

/*****************************************************************************
 *	handlers
 *****************************************************************************/
static void
timeout_handler(int s __attribute__ ((unused)),
		short event __attribute__ ((unused)),
		void *arg)
{
	struct cli_ctx *ctx = arg;

	LOG(LOG_DEBUG, "trace ctx: %p\n", ctx);
	ctx->used = 0;
	destroy_cli_ctx(ctx, ECONNREFUSED);
}

static void
read_handler(int s,
	     short event __attribute__ ((unused)),
	     void *arg)
{
        ssize_t bytes;
        char buffer[1024 * 4];
        struct sock_info *info = arg;
	struct cli_ctx *ctx = info->ctx;
	ERRBUFF();

	LOG(LOG_DEBUG, "trace info: %p(%s)  ctx: %p\n", info, info->name, ctx);
	errno = 0;
        bytes = read(s, buffer, sizeof(buffer));
        if (bytes <= 0) {
		int ecode = errno;

                if (errno == EINTR || errno == EAGAIN)
                        return;
		LOG(LOG_INFO, "failed at read %d: %s\n", s, STRERR(ecode));

		if (ctx->remote == info) {
			destroy_cli_ctx(ctx, ecode);
		} else {
			destroy_sock_info(info);
			ctx->console = NULL;

			evtimer_set(&ctx->evt, timeout_handler, ctx);
			evtimer_add(&ctx->evt, &ctx->tout);
			ctx->used = 1;
		}
                return;
        }
	LOG(LOG_DEBUG, "read %d bytes\n", bytes);

        again:
	errno = 0;
	if (write(info->dst, buffer, bytes) <= 0) {
		int ecode = errno;

		if (errno == EINTR)
			goto again;
		else if (errno == EAGAIN)
			return;
		LOG(LOG_INFO, "failed at write: %s\n", STRERR(ecode));
		destroy_cli_ctx(ctx, ecode);
        }
}

static void
connect_handler(int sd,
		short event,
		void *arg)
{
	struct cli_ctx *ctx = arg;
	int ecode = 0;
	int oval = 0;
	socklen_t olen = sizeof(oval);
	ERRBUFF();

	LOG(LOG_DEBUG, "trace ctx: %p\n", ctx);
	ctx->used = 0;
	errno = 0;
	if (getsockopt(sd, SOL_SOCKET, SO_ERROR, &oval, &olen) || oval) {
		if (errno)
			ecode = errno;
		else
			ecode = oval;
		LOG(LOG_NOTICE, "failed at getsockopt: %s\n",
		    STRERR(errno));
		goto err;
	} else if (event & EV_TIMEOUT) {
		ecode = ETIMEDOUT;
		goto err;
	}

	if (event_add(&ctx->console->evt, NULL)) {
		ecode = errno;
		LOG(LOG_NOTICE, "failed at event_add: %s\n", STRERR(errno));
		goto err;
	}
	ctx->console->ctx = ctx;

	if (event_add(&ctx->remote->evt, NULL)) {
		ecode = errno;
		LOG(LOG_NOTICE, "failed at event_add: %s\n", STRERR(errno));
		goto err;
	}
	ctx->remote->ctx = ctx;
	return;
err:
	destroy_cli_ctx(ctx, ecode);
}

/*****************************************************************************
 *	creaters
 *****************************************************************************/
static struct sock_info *
create_sock_info(const char *name,
		   int src,
		   int dst)
{
	struct sock_info *info;

	if ((info = calloc(1, sizeof(*info))) != NULL) {
		info->src = src;
		info->dst = dst;
		info->name = name;

		event_set(&info->evt, src, EV_READ | EV_PERSIST,
			  read_handler, info);
		/* not add, now */
		LOG(LOG_DEBUG, "trace info: %p(%s)\n", info, info->name);
	}
	return info;
}

static struct cli_ctx *
create_cli_ctx(int sd,
	       const struct timeval *tout,
	       void (*err_cb)(void *, int),
	       void *user_ctx)
{
	struct cli_ctx *ctx;
	ERRBUFF();

	if ((ctx = calloc(1, sizeof(*ctx))) != NULL) {
		ctx->sd = sd;
		ctx->tout.tv_sec = tout->tv_sec;
		ctx->tout.tv_usec = tout->tv_usec;
		ctx->err_cb = err_cb;
		ctx->user_ctx = user_ctx;

		event_set(&ctx->evt, ctx->sd, EV_WRITE, connect_handler, ctx);
		if (event_add(&ctx->evt, &ctx->tout)) {
			LOG(LOG_NOTICE, "failed at event_add: %s\n",
			    STRERR(errno));
			free(ctx);
			return NULL;
		}
		ctx->used = 1;
		LOG(LOG_DEBUG, "trace ctx: %p\n", ctx);
	}
	return ctx;
}

static int
open_socket(const char *name,
	    uint16_t port)
{
	struct sockaddr_storage ss;
	socklen_t salen;
	int sock;
	ERRBUFF();

	sock = jd_cmd_open_client(name, port, &ss, &salen);
	if (sock < 0)
		return -1;

	errno = 0;
	if (connect(sock, (struct sockaddr *) &ss, salen) &&
	    errno != EINPROGRESS) {
		LOG(LOG_NOTICE, "failed at connect: %s\n", STRERR(errno));
		CLOSE(sock);
		return -1;
	}
        return sock;
}

int
jd_cmd_cli(const char *remote_name,
	    uint16_t port,
	    int in,
	    int out,
	    const struct timeval *tout,
	    void (*err_cb)(void *, int),
	    void *user_ctx)
{
	int sd = -1;
	struct cli_ctx *ctx;

	if (!remote_name) {
		errno = EINVAL;
		return -1;
	}

	if ((sd = open_socket(remote_name, port)) < 0)
		return -1;
	if ((ctx = create_cli_ctx(sd, tout, err_cb, user_ctx)) == NULL)
		goto end;
        if ((ctx->console = create_sock_info("console", in, sd)) == NULL)
		goto end;
        if ((ctx->remote = create_sock_info("remote", sd, out)) == NULL)
		goto end;
	ctx->console->another = ctx->remote;
	ctx->remote->another = ctx->console;
	return 0;
end:
	if (sd >= 0)
		CLOSE(sd);
	return -1;
}

/*
 * client setup
 */
static const int optval_true = 1;
static const int optval_false = 0;
static const struct linger optval_linger = {
	.l_onoff = 0,
	.l_linger = 0,
};

static const struct fssock_option fssock_client_options[] = {
	{
		.name = "SO_LINGER",
		.critical = true,
		.level = SOL_SOCKET,
		.optname = SO_LINGER,
		.optval = &optval_linger,
		.optlen = sizeof(optval_linger),
	},
	{
		.name = "SO_KEEPALIVE",
		.critical = true,
		.level = SOL_SOCKET,
		.optname = SO_KEEPALIVE,
		.optval = &optval_true,
		.optlen = sizeof(optval_true),
	},
	{
		.name = NULL,
	},
};

static int tcp_keep_idle = 1;
static int tcp_keep_cnt = 1;
static int tcp_keep_interval = 1;
static int tcp_syn_cnt = 1;
static const struct fssock_option tcp_client_options[] = {
	{
		.name = "TCP_KEEPIDLE",
		.critical = true,
		.level = SOL_TCP,
		.optname = TCP_KEEPIDLE,
		.optval = &tcp_keep_idle,
		.optlen = sizeof(tcp_keep_idle),
	},
	{
		.name = "TCP_KEEPCNT",
		.critical = true,
		.level = SOL_TCP,
		.optname = TCP_KEEPCNT,
		.optval = &tcp_keep_cnt,
		.optlen = sizeof(tcp_keep_cnt),
	},
	{
		.name = "TCP_KEEPINTVL",
		.critical = true,
		.level = SOL_TCP,
		.optname = TCP_KEEPINTVL,
		.optval = &tcp_keep_interval,
		.optlen = sizeof(tcp_keep_interval),
	},
#if 0
	{
		.name = "TCP_CORK",
		.critical = true,
		.level = SOL_TCP,
		.optname = TCP_CORK,
		.optval = &optval_true,
		.optlen = sizeof(optval_true),
	},
#endif
	{
		.name = "TCP_SYNCNT",
		.critical = true,
		.level = SOL_TCP,
		.optname = TCP_SYNCNT,
		.optval = &tcp_syn_cnt,
		.optlen = sizeof(tcp_syn_cnt),
	},
	{
		.name = NULL,
	},
};


int
jd_cmd_open_client(const char *name,
		   uint16_t port,
		   struct sockaddr_storage *ss,
		   socklen_t *salen)
{
	int sock;
	struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *) ss;
	struct sockaddr_in *sai4 = (struct sockaddr_in *) ss;
	struct sockaddr_un *sau = (struct sockaddr_un *) ss;
	ERRBUFF();

	memset(ss, 0, sizeof(*ss));
	if (inet_pton(AF_INET6, name, &sai6->sin6_addr) == 1) {
		if (!port) {
			errno = EINVAL;
			return -1;
		}
		sai6->sin6_family = AF_INET6;
		sai6->sin6_port = htons(port);
		*salen = sizeof(*sai6);
	} else if (inet_pton(AF_INET, name, &sai4->sin_addr) == 1) {
		if (!port) {
			errno = EINVAL;
			return -1;
		}
		sai4->sin_family = AF_INET;
		sai4->sin_port = htons(port);
		*salen = sizeof(*sai4);
	} else {
		sau->sun_family = AF_UNIX;
		strncpy(sau->sun_path, name, sizeof(sau->sun_path) - 1);
		*salen = sizeof(*sau);
	}

        if ((sock = socket(ss->ss_family,
			   SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
			   0)) < 0) {
		LOG(LOG_NOTICE, "failed at socket(): %s\n",
		    STRERR(errno));
		return -1;
	}
	if (fssock_set_option(sock, fssock_client_options) < 0) {
		CLOSE(sock);
		return -1;
	}
	if (ss->ss_family != AF_UNIX) {
		if (fssock_set_option(sock, tcp_client_options) < 0) {
			CLOSE(sock);
			return -1;
		}
	}
	return sock;
}
