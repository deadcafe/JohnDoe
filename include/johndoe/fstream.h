/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_JD_FSTREAM_H_
#define	_JD_FSTREAM_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <inttypes.h>
#include <string.h>
#include <event.h>

/* stream message */
struct fstream_msg {
        uint16_t len;		/* network byte order */
        uint16_t type;		/* network byte order */
	uint8_t payload[0];
} __attribute__((packed));

/* statistics */
struct fstream_stats {
	size_t tx_packets;
	size_t tx_bytes;
	size_t rx_packets;
	size_t rx_bytes;
};

/*****************************************************************************
 *	Stream
 *****************************************************************************/
struct fstream_msg_node {
	TAILQ_ENTRY(fstream_msg_node) lnk;
	size_t len;
	union {
		char buff[sizeof(struct fstream_msg)];
		struct fstream_msg msg;
	} val;
};

enum {	/* bit assign */
	FSTREAM_DEAD = 0,
	FSTREAM_ALIVE = 1,	/* added read event */
	FSTREAM_W_WAIT = 2,	/* */
};

/*
 *
 */
struct fstream {
	int sock;
	unsigned int state;
	size_t refcnt;
	struct fstream_stats stats;
	size_t max_msg_size;
	struct event ev_w;
	struct event ev_r;
	struct fstream_msg_node *rbuff;
	TAILQ_HEAD(node_q, fstream_msg_node) w_q;
	void *ctx;
	void (*msg_cb)(void *, struct fstream *, const struct fstream_msg *);
	void (*err_cb)(void *, struct fstream *, int);
	void (*logger)(int, const char *, ...);
};

/*
 *
 */
struct fstream_reception {
	int sock;
	void (*wakeup)(void *, struct fstream_reception *, int, int);
	void *ctx;
	const struct sock_profile *profile;
	struct event evt;
	struct sockaddr_storage peer;
};


/*****************************************************************************
 *	API
 *****************************************************************************/
/*
 * listen socket.
 *  domain:	AF_INET/AF_INET6/AF_LOCAL
 *  protocol:	IPPROTO_SCTP/ZERO
 *  addr:	IP address or socket path
 *  port:	tcp/sctp port
 *  wakeup:	callback after accept().
 *  ctx:	something
 */
extern struct fstream_reception *
fstream_waiting_accept(int domain,
		       int protocol,
		       const char *addr,
		       uint16_t port,
		       void (*wakeup)(void *, struct fstream_reception *,
				      int, int),
		       void *ctx);

/*
 * connect socket.
 *  domain:	AF_INET/AF_INET6/AF_UNIX
 *  protocol:	IPPROTO_TCP/IPPROTO_SCTP
 *  addr:	IP address or socket path
 *  port:	tcp/sctp port
 *  wakeup:	callback after connected. Don't fstream_destroy() after waked up.
 *  ctx:	something
 *
 */
extern struct fstream_reception *
fstream_waiting_connect(int domain,
			int protocol,
			const char *addr,
			uint16_t port,
			const struct timeval *tout,
			void (*wakeup)(void *, struct fstream_reception *,
				       int, int),
			void *ctx);


/*
 * reception:	fstream_waiting_accept()/fstream_waiting_connect() value.
 */
extern void fstream_destroy_reception(struct fstream_reception *reception);

/* create Fstream ... bind socket with handler.
 *  sock:	socket descriptor.
 *  max_msg_size: MAX message payload length.
 *  rx_cb:	receive handler
 *  err_cb:	error handler
 *  ctx:		something
 */
extern struct fstream *fstream_create(int sock,
				      size_t max_payload_size,
				      void (*rx_cb)(void *, struct fstream *,
						    const struct fstream_msg *),
				      void (*err_cb)(void *, struct fstream *,
						     int),
				      void *ctx);

/*
 * destroy Fstream. don't call in err_cb.
 */
extern void fstream_destroy(struct fstream *);

/*
 * stream msg alocator/free.
 *  payload_size:	payload length.
 */
extern struct fstream_msg *fstream_msg_alloc(size_t payload_size);
extern void fstream_msg_free(struct fstream_msg *);

/*
 * stream msg post request.
 */
extern int fstream_msg_post(struct fstream *, struct fstream_msg *);

/*
 * clear stream statistics.
 */
static inline void
fstream_clear_stats(struct fstream *stream)
{
	memset(&stream->stats, 0, sizeof(stream->stats));
}

extern void fstream_set_logger(void (*)(int, const char *, ...));

#endif	/* !_JD_FSTREAM_H_ */
