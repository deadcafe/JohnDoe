/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

#include <assert.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>

#include "johndoe/socket.h"
#include "johndoe/fstream.h"
#include "log.h"


#define	MAGIC	0xdeadcafe

static const struct timeval send_TO = {
	.tv_sec = 3,
	.tv_usec = 0,
};

static inline void
free_msg_node(struct fstream_msg_node *node)
{
	LOG(LOG_DEBUG, "node: %p\n", node);
	free(node);
}

static inline struct fstream_msg_node *
alloc_msg_node(size_t len)
{
	struct fstream_msg_node *node;
	int ecode;

	if ((node = malloc(sizeof(*node) + len)) != NULL) {
		node->len = len;
		node->val.msg.len = 0;
		node->val.msg.type = 0;
	}
	ecode = errno;
	LOG(LOG_DEBUG, "node: %p  len: %lu\n", node, len);
	errno = ecode;
	return node;
}

static inline void
attach_fstream(struct fstream *fstream)
{
	fstream->refcnt++;
}

static inline void
detach_fstream(struct fstream *fstream)
{
	fstream->refcnt--;
	if (!fstream->refcnt) {
		free(fstream);
		LOG(LOG_DEBUG, "destroyed fstream: %p\n", fstream);
	}
}

static inline int
setup_event(struct fstream *fstream,
	    struct event *ev,
	    short type,
	    void (*handler)(int, short, void *),
	    int state)
{
	int ecode = 0;

	event_set(ev, fstream->sock, type, handler, fstream);
	if (event_add(ev, NULL)) {
		ERRBUFF();
		ecode = errno;
		LOG(LOG_NOTICE,
		    "failed at event_add: %s\n", STRERR(ecode));
	} else {
		fstream->state |= state;
		LOG(LOG_DEBUG, "state change: %p %x\n",
		    fstream, fstream->state);
	}
	return ecode;
}

static inline int
clear_event(struct fstream *fstream,
	    struct event *ev,
	    int state)
{
	int ecode = 0;

	if (event_del(ev)) {
		ERRBUFF();
		ecode = errno;
		LOG(LOG_NOTICE,
		    "failed at event_del: %s\n", STRERR(ecode));
	}
	fstream->state &= ~state;	/* ignore result */
	LOG(LOG_DEBUG, "state change: %p %x\n", fstream, fstream->state);
	return ecode;
}

static void
fstream_destroy_raw(struct fstream *fstream,
		    int ecode)
{
	struct fstream_msg_node *node;

	assert(fstream->refcnt > 0);
	LOG(LOG_DEBUG, "destroying fstream: %p  ecode: %d  state: %x\n",
	    fstream, ecode, fstream->state);

	while ((node = TAILQ_FIRST(&fstream->w_q)) != NULL) {
		TAILQ_REMOVE(&fstream->w_q, node, lnk);
		free_msg_node(node);
	}
	if (fstream->rbuff) {
		free_msg_node(fstream->rbuff);
		fstream->rbuff = NULL;
	}

	if (fstream->state & FSTREAM_W_WAIT)
		clear_event(fstream, &fstream->ev_w, FSTREAM_W_WAIT);
	if (fstream->state & FSTREAM_ALIVE)
		clear_event(fstream, &fstream->ev_r, FSTREAM_ALIVE);
	if (fstream->state)
		LOG(LOG_ERR, "unknown state: %x\n", fstream->state);

	if (fstream->sock >= 0) {
		CLOSE(fstream->sock);
		fstream->sock = -1;
	}

	if (fstream->err_cb) {
		void (*err_cb)(void *, struct fstream *, int);
		void *ctx;

		err_cb = fstream->err_cb;
		ctx = fstream->ctx;
		fstream->err_cb = NULL;
		fstream->ctx = NULL;
		if (ecode)
			(*err_cb)(ctx, fstream, ecode);
	}
	detach_fstream(fstream);
}

static void
recv_handler(int sock,
	     short event,
	     void *arg)
{
	struct fstream *fstream = arg;
	struct fstream_msg_node *rx = fstream->rbuff;
	int ecode = 0;
	ERRBUFF();

	LOG(LOG_DEBUG, "sock: %d  event: %d  fstream: %p\n",
	    sock, event, fstream);

	if (!(event & EV_READ))
		return;

	attach_fstream(fstream);
	while (fstream->state & FSTREAM_ALIVE) {
		ssize_t len;
		size_t size;

		if (rx->len < sizeof(struct fstream_msg))
			size = sizeof(struct fstream_msg) - rx->len;
		else
			size = ntohs(rx->val.msg.len) - rx->len;

		errno = 0;
		len = recv(fstream->sock, &rx->val.buff[rx->len], size,
			   MSG_DONTWAIT);
		if (len < 0) {
			if (errno == EAGAIN ||
			    errno == EWOULDBLOCK ||
			    errno == EINTR) {
				break;
			} else {
				ecode = errno;
				LOG(LOG_NOTICE,
				    "failed at recv(): %s\n", STRERR(ecode));
				break;
			}
		}
		if (!len) {
			ecode = ECONNRESET;
			break;
		}

		rx->len += len;
		fstream->stats.rx_bytes += len;
		if ((size_t)len < size)
			continue;
		if (ntohs(rx->val.msg.len) < sizeof(struct fstream_msg) ||
		    ntohs(rx->val.msg.len) > fstream->max_msg_size) {
			LOG(LOG_NOTICE, "invalid msg: %d\n",
			    ntohs(rx->val.msg.len));
			ecode = EINVAL;
			break;
		}

		if (rx->len < ntohs(rx->val.msg.len))
			continue;
		rx->len = 0;
		fstream->stats.rx_packets++;
		(*fstream->msg_cb)(fstream->ctx, fstream, &rx->val.msg);
	}

	if (ecode) {
		LOG(LOG_DEBUG, "fstream error: %d\n", ecode);
		fstream_destroy_raw(fstream, ecode);
	}
	detach_fstream(fstream);
}

static void send_handler(int sock, short event, void *arg);

static int
msg_send(struct fstream *fstream)
{
	struct fstream_msg_node *tx;
	int ecode = 0;
	ERRBUFF();

	assert(!(fstream->state & FSTREAM_W_WAIT));

	LOG(LOG_DEBUG, "fstream: %p\n", fstream);
	while ((tx = TAILQ_FIRST(&fstream->w_q)) != NULL) {
		ssize_t len;
		size_t size = ntohs(tx->val.msg.len);

		size -= tx->len;
		errno = 0;
		len = send(fstream->sock, &tx->val.buff[tx->len], size,
			   MSG_DONTWAIT);
		if (len < 0) {
			if (errno == EINTR) {
				continue;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				LOG(LOG_DEBUG, "waiting write socket.\n");
				return setup_event(fstream, &fstream->ev_w,
						   EV_WRITE, send_handler,
						   FSTREAM_W_WAIT);
			} else {
				ecode = errno;
				LOG(LOG_NOTICE,
				    "failed at send(): %s\n", STRERR(errno));
				break;
			}
		}
		tx->len += len;
		fstream->stats.tx_bytes += len;
		size -= len;
		if (!size) {
			TAILQ_REMOVE(&fstream->w_q, tx, lnk);
			free_msg_node(tx);
			fstream->stats.tx_packets++;
		}
	}
	return ecode;
}

static void
send_handler(int sock,
	     short event,
	     void *arg)
{
	struct fstream *fstream =  arg;
	int ecode;

	LOG(LOG_DEBUG, "sock: %d  event: %d  fstream: %p\n",
	    sock, event, fstream);

	fstream->state &= ~FSTREAM_W_WAIT;
	if ((ecode = msg_send(fstream)) != 0)
		fstream_destroy_raw(fstream, ecode);
}

/*
 * public functions
 */
#define	MSG2NODE(m_)	(struct fstream_msg_node *)((char*)(m_) - (offsetof(struct fstream_msg_node, val)))

/*
 * initializer/de-initializer
 */
static inline int
init_fstream(struct fstream *fstream,
	     int sock,
	     size_t max_msg_size,
	     void (*msg_cb)(void *, struct fstream *,
			   const struct fstream_msg *),
	     void (*err_cb)(void *, struct fstream *, int),
	     void *ctx)
{
	struct fstream_msg_node *node = NULL;
	int ret = -1;

	LOG(LOG_DEBUG, "fstream: %p  sock: %d  max: %lu\n",
	    fstream, sock, max_msg_size);

	memset(fstream, 0, sizeof(*fstream));
	TAILQ_INIT(&fstream->w_q);
	fstream->sock = -1;

	if ((node = alloc_msg_node(max_msg_size)) == NULL)
		goto end;

	node->len = 0;
	fstream->rbuff = node;
	fstream->max_msg_size = max_msg_size + sizeof(struct fstream_msg);
	fstream->msg_cb = msg_cb;
	fstream->err_cb = err_cb;
	fstream->ctx = ctx;
	fstream->sock = sock;

	if (setup_event(fstream, &fstream->ev_w, EV_WRITE,
			send_handler, FSTREAM_W_WAIT))
		goto end;
	if (setup_event(fstream, &fstream->ev_r, EV_READ | EV_PERSIST,
			recv_handler, FSTREAM_ALIVE))
		goto end;
	attach_fstream(fstream);
	ret = 0;
	LOG(LOG_DEBUG, "initialized fstream: %p\n", fstream);
end:
	if (ret) {
		if (node)
			free_msg_node(node);
		if (fstream->state & FSTREAM_W_WAIT)
			clear_event(fstream, &fstream->ev_w, FSTREAM_W_WAIT);
		if (fstream->state & FSTREAM_ALIVE)
			clear_event(fstream, &fstream->ev_r, FSTREAM_ALIVE);
	}
	return ret;
}

struct fstream *
fstream_create(int sock,
	       size_t max_payload_size,
	       void (*msg_cb)(void *, struct fstream *,
			      const struct fstream_msg *),
	       void (*err_cb)(void *, struct fstream *, int),
	       void *ctx)
{
	struct fstream *fstream;

	LOG(LOG_DEBUG, "sock: %d\n", sock);

	if (!msg_cb || !err_cb || sock < 0) {
		errno = EINVAL;
		return NULL;
	}

	if ((fstream = malloc(sizeof(*fstream))) != NULL) {
		if (init_fstream(fstream, sock, max_payload_size,
				msg_cb, err_cb, ctx)) {
			free(fstream);
			fstream = NULL;
		}
	}
	LOG(LOG_DEBUG, "created fstream: %p\n", fstream);
	return fstream;
}

void
fstream_destroy(struct fstream *fstream)
{
	LOG(LOG_DEBUG, "fstream: %p\n", fstream);
	fstream->err_cb = NULL;
	fstream->ctx = NULL;
	fstream_destroy_raw(fstream, 0);
}

/*
 * msg allocator
 */
struct fstream_msg *
fstream_msg_alloc(size_t len)
{
	struct fstream_msg_node *node;

	LOG(LOG_DEBUG, "len: %lu\n", len);
	if ((node = alloc_msg_node(sizeof(node->val.msg) + len)) != NULL)
		return &node->val.msg;
	return NULL;
}

void
fstream_msg_free(struct fstream_msg *msg)
{
	struct fstream_msg_node *node = MSG2NODE(msg);

	LOG(LOG_DEBUG, "msg: %p\n", msg);
	free_msg_node(node);
}

/*
 * post msg
 */
int
fstream_msg_post(struct fstream *fstream,
		struct fstream_msg *msg)
{
	struct fstream_msg_node *node = MSG2NODE(msg);
	int ret = -1;

	LOG(LOG_DEBUG, "fstream: %p  msg: %p  node: %p\n",
	    fstream, msg, node);

	if (ntohs(msg->len) > node->len ||
	    ntohs(msg->len) < sizeof(struct fstream_msg)) {
		LOG(LOG_NOTICE, "invalid msg: %p length: %u(%lu)\n",
		    msg, ntohs(msg->len), node->len);
		errno = EINVAL;
		return ret;
	}

	if (!(fstream->state & FSTREAM_ALIVE)) {
		LOG(LOG_NOTICE, "fstream is dead: %d\n", fstream->state);
		errno = ENOENT;
		return ret;
	}

	node->len = 0;
	TAILQ_INSERT_TAIL(&fstream->w_q, node, lnk);
	ret = 0;	/* msg is accepted, then result is success */

	if (!(fstream->state & FSTREAM_W_WAIT)) {
		int ecode;

		if ((ecode = msg_send(fstream)) != 0)
			fstream_destroy_raw(fstream, ecode);
	}
	return ret;
}

/*****************************************************************************
 *
 *****************************************************************************/
static const int optval_true = 1;
static const int optval_false = 0;
static const struct linger optval_linger = {
	.l_onoff = 0,
	.l_linger = 0,
};
static int tcp_keep_idle = 1;
static int tcp_keep_cnt = 1;
static int tcp_keep_interval = 1;
static const struct fssock_option tcp_option[] = {
	{
		.name = "IP_FREEBIND",
		.critical = true,
		.level = SOL_IP,
		.optname = IP_FREEBIND,
		.optval = &optval_true,
		.optlen = sizeof(optval_true),
	},
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
	{
		.name = "TCP_NODELAY",
		.critical = true,
		.level = SOL_TCP,
		.optname = TCP_NODELAY,
		.optval = &optval_true,
		.optlen = sizeof(optval_true),
	},
	{
		.name = NULL,
	},
};

static const struct fssock_option sctp_option[] = {
	{
		.name = "IP_FREEBIND",
		.critical = true,
		.level = SOL_IP,
		.optname = IP_FREEBIND,
		.optval = &optval_true,
		.optlen = sizeof(optval_true),
	},
	{
		.name = "SCTP_NODELAY",
		.critical = true,
		.level = SOL_SCTP,
		.optname = SCTP_NODELAY,
		.optval = &optval_true,
		.optlen = sizeof(optval_true),
	},
	{
		.name = NULL,
	},
};

static const struct fssock_option server_option[] = {
	{
		.name = "SO_LINGER",
		.critical = true,
		.level = SOL_SOCKET,
		.optname = SO_LINGER,
		.optval = &optval_linger,
		.optlen = sizeof(optval_linger),
	},
	{
		.name = "SO_REUSEADDR",
		.critical = true,
		.level = SOL_SOCKET,
		.optname = SO_REUSEADDR,
		.optval = &optval_true,
		.optlen = sizeof(optval_true),
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

static const struct fssock_option common_option[] = {
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

struct sock_profile {
	const char *name;
	int domain;
	int protocol;
	socklen_t salen;
	const struct fssock_option *option;
};

static const struct sock_profile profile_tbl[] = {
	{
		.name = "TCP over IPv6",
		.domain = AF_INET6,
		.salen = sizeof(struct sockaddr_in6),
		.option = tcp_option,
	},
	{
		.name = "SCTP over IPv6",
		.domain = AF_INET6,
		.protocol = IPPROTO_SCTP,
		.salen = sizeof(struct sockaddr_in6),
		.option = sctp_option,
	},
	{
		.name = "TCP over IPv4",
		.domain = AF_INET,
		.salen = sizeof(struct sockaddr_in),
		.option = tcp_option,
	},
	{
		.name = "SCTP over IPV4",
		.domain = AF_INET,
		.protocol = IPPROTO_SCTP,
		.salen = sizeof(struct sockaddr_in),
		.option = sctp_option,
	},
	{	.name = "UNIX(default)",
		.domain = AF_LOCAL,
		.salen = sizeof(struct sockaddr_un),
	},
};

static inline const struct sock_profile *
find_profile(int domain,
	     int protocol)
{
	const struct sock_profile *prof;

	prof = profile_tbl;
	while (prof->domain != AF_LOCAL) {
		if (prof->domain == domain && prof->protocol == protocol)
			break;
		prof++;
	}
	return prof;
}

static struct fstream_reception *
create_reception(void (*wakeup)(void *, struct fstream_reception *,
				int, int),
		 void *ctx)
{
	struct fstream_reception *reception;

	if ((reception = calloc(1, sizeof(*reception))) != NULL) {
		reception->sock = -1;
		reception->ctx = ctx;
		reception->wakeup = wakeup;
	}
	return reception;
}

static void
destroy_reception_raw(struct fstream_reception *reception,
		      int sock,
		      int ecode)
{
	ERRBUFF();

	if (reception->sock >= 0) {
		if (event_del(&reception->evt))
			LOG(LOG_NOTICE, "failed att event_del: %s\n",
			    STRERR(errno));
		CLOSE(reception->sock);
		reception->sock = -1;
	}
	if (reception->wakeup) {
		void (*wakeup)(void *, struct fstream_reception *, int, int);
		void *ctx = reception->ctx;

		wakeup = reception->wakeup;
		reception->wakeup = NULL;
		reception->ctx = NULL;
		(*wakeup)(ctx, reception, sock, ecode);
	}
	LOG(LOG_DEBUG, "destroyed reception: %p\n", reception);
	free(reception);
}

/*
 * listen,accept callback
 */
static void
listen_handler(int parent,
	       short event __attribute__((unused)),
	       void *arg)
{
	struct sockaddr_storage *peer;
	socklen_t sslen = sizeof(*peer);
	struct fstream_reception *reception = arg;
	int sock;
	int ecode = 0;
	ERRBUFF();

	peer = &reception->peer;
	memset(peer, 0, sizeof(*peer));
	if ((sock = accept4(parent, (struct sockaddr *) peer, &sslen,
			    SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
		ecode = errno;
		LOG(LOG_NOTICE, "failed at accept4(): %s\n", STRERR(errno));
		return;
	}
	if (fssock_set_option(sock, common_option) < 0) {
		ecode = errno;
		goto end;
	}
	if (reception->profile->option) {
		if (fssock_set_option(sock, reception->profile->option) < 0) {
			ecode = errno;
			goto end;
		}
	}
end:
	if (ecode) {
		CLOSE(sock);
		/* ignored event */
	} else {
		(*reception->wakeup)(reception->ctx, reception, sock, ecode);
	}
}

/*
 *
 */
struct fstream_reception *
fstream_waiting_accept(int domain,
		       int protocol,
		       const char *addr,
		       uint16_t port,
		       void (*wakeup)(void *, struct fstream_reception *,
				      int, int),
		       void *ctx)
{
	struct sockaddr_storage *ss;
	const struct sock_profile *profile;
	struct fstream_reception *reception;
	int sock;
	int ecode;
	ERRBUFF();

	if (!wakeup) {
		errno = EINVAL;
		return NULL;
	}
	if ((reception = create_reception(wakeup, ctx)) == NULL)
		return NULL;

	profile = find_profile(domain, protocol);
	sock = socket(profile->domain,
		      SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		      profile->protocol);
	if (sock < 0) {
		ecode = errno;
		goto err;
	}

	reception->profile = profile;
	ss = &reception->peer;
	if (profile->domain == AF_INET) {
		struct sockaddr_in *sai4 = (struct sockaddr_in *) ss;

		if (!port) {
			ecode = EINVAL;
			goto err;
		}
		if (addr) {
			if (inet_pton(AF_INET, addr, &sai4->sin_addr) != 1) {
				ecode = EINVAL;
				goto err;
			}
		}
		sai4->sin_family = AF_INET;
		sai4->sin_port = htons(port);
	} else if (profile->domain == AF_INET6) {
		struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *) ss;

		if (!port) {
			ecode = EINVAL;
			goto err;
		}
		if (addr) {
			if (inet_pton(AF_INET6, addr, &sai6->sin6_addr) != 1) {
				ecode = EINVAL;
				goto err;
			}
		} else {
			sai6->sin6_addr = in6addr_loopback;
		}

		sai6->sin6_family = AF_INET6;
		sai6->sin6_port = htons(port);
	} else {
		struct sockaddr_un *sau = (struct sockaddr_un *) ss;

		if (!addr) {
			ecode = EINVAL;
			goto err;
		}
		sau->sun_family = AF_UNIX;
		strncpy(sau->sun_path, addr, sizeof(sau->sun_path) -1);
		unlink(addr);
	}

	if (fssock_set_option(sock, server_option) < 0) {
		ecode = errno;
		goto err;
	}
	if (profile->option) {
		if (fssock_set_option(sock, profile->option) < 0) {
			ecode = errno;
			goto err;
		}
	}
	if (bind(sock, (struct sockaddr *)ss, profile->salen) < 0) {
		ecode = errno;
		LOG(LOG_NOTICE, "failed at bind: %s\n", STRERR(ecode));
		goto err;
	}
	if (listen(sock, 1) < 0) {
		ecode = errno;
		LOG(LOG_NOTICE, "failed at listen: %s\n", STRERR(ecode));
		goto err;
	}
	event_set(&reception->evt, sock, EV_READ | EV_PERSIST,
		  listen_handler, reception);
	if (event_add(&reception->evt, NULL)) {
		ecode = errno;
		LOG(LOG_NOTICE, "failed at event_add: %s\n", STRERR(ecode));
		goto err;
	}
	reception->sock = sock;
	LOG(LOG_DEBUG, "created reception: %p sock: %d  %s\n",
	    reception, reception->sock, profile->name);
	return reception;
err:
	destroy_reception_raw(reception, -1, 0);
	CLOSE(sock);
	errno = ecode;
	return NULL;
}

/*
 *
 */
void
fstream_destroy_reception(struct fstream_reception *reception)
{
	reception->wakeup = NULL;
	reception->ctx = NULL;
	destroy_reception_raw(reception, -1, 0);
}

/*
 * connected callback
 */
static void
connect_handler(int sock,
		short event,
		void *arg)
{
	struct fstream_reception *reception = arg;
	int oval = 0;
	socklen_t olen = sizeof(oval);
	int ecode = 0;

	errno = 0;
	if (event & EV_TIMEOUT) {
		ecode = ETIMEDOUT;
	} else if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &oval, &olen)
		   || oval) {
		if (errno)
			ecode = errno;
		else
			ecode = oval;
	}

	if (ecode)
		sock = -1;
	else
		reception->sock = -1;
	destroy_reception_raw(reception, sock, ecode);
}

/*
 *
 */
struct fstream_reception *
fstream_waiting_connect(int domain,
			int protocol,
			const char *addr,
			uint16_t port,
			const struct timeval *tout,
			void (*wakeup)(void *, struct fstream_reception *,
				       int, int),
			void *ctx)
{
	struct sockaddr_storage *ss;
	const struct sock_profile *profile;
	struct fstream_reception *reception;
	int sock;
	int ecode;
	ERRBUFF();

	if (!wakeup) {
		errno = EINVAL;
		return NULL;
	}
	if ((reception = create_reception(wakeup, ctx)) == NULL)
		return NULL;

	profile = find_profile(domain, protocol);
	sock = socket(profile->domain,
		      SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		      profile->protocol);
	if (sock < 0) {
		ecode = errno;
		goto err;
	}
	reception->profile = profile;
	ss = &reception->peer;
	if (profile->domain == AF_INET) {
		struct sockaddr_in *sai4 = (struct sockaddr_in *) ss;

		if (!port || !addr) {
			ecode = EINVAL;
			goto err;
		}
		if (inet_pton(AF_INET, addr, &sai4->sin_addr) != 1) {
			ecode = EINVAL;
			goto err;
		}
		sai4->sin_family = AF_INET;
		sai4->sin_port = htons(port);
	} else if (profile->domain == AF_INET6) {
		struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *) ss;

		if (!port || !addr) {
			ecode = EINVAL;
			goto err;
		}
		if (inet_pton(AF_INET6, addr, &sai6->sin6_addr) != 1) {
			ecode = EINVAL;
			goto err;
		}
		sai6->sin6_family = AF_INET6;
		sai6->sin6_port = htons(port);
		sai6->sin6_addr = in6addr_loopback;
	} else {
		struct sockaddr_un *sau = (struct sockaddr_un *) ss;

		sau->sun_family = AF_UNIX;
		strncpy(sau->sun_path, addr, sizeof(sau->sun_path) -1);
	}

	if (fssock_set_option(sock, common_option) < 0) {
		ecode = errno;
		goto err;
	}
	if (profile->option) {
		if (fssock_set_option(sock, profile->option) < 0) {
			ecode = errno;
			goto err;
		}
	}

	if (connect(sock, (struct sockaddr *) ss, profile->salen)) {
		ecode = errno;
		if (ecode != EINPROGRESS)
			goto err;
	}

	event_set(&reception->evt, sock, EV_WRITE, connect_handler, reception);
	if (event_add(&reception->evt, tout)) {
		ecode = errno;
		LOG(LOG_NOTICE, "failed at event_add: %s\n", STRERR(ecode));
		goto err;
	}
	reception->sock = sock;
	LOG(LOG_DEBUG, "created reception: %p sock: %d  %s\n",
	    reception, reception->sock, profile->name);
	return reception;
err:
	destroy_reception_raw(reception, -1, 0);
	CLOSE(sock);
	errno = ecode;
	return NULL;
}
