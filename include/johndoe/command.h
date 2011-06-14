/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef _JD_COMMAND_H_
#define _JD_COMMAND_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <inttypes.h>
#include <event.h>

struct fscmd_handle;

/*
 * command table
 */
struct fscmd_table {
	const char *cmd;
	const char *help;
	void (*func)(struct fscmd_handle *, void *, int, char **);
	const struct fscmd_table *sub;
};

struct fscmd_node {
	const struct fscmd_table *tbl;
	TAILQ_ENTRY(fscmd_node) lnk;
	TAILQ_HEAD(fscmd_tree, fscmd_node) sub_tree;
};


/*
 * command socket
 */
enum {
	CMD_DEAD = 0,
	CMD_READY,
	CMD_LISTEN,
	CMD_ACCEPT,
	CMD_PARMANENT,
};

struct fscmd_handle {
	char *name;
	size_t refcnt;

	int state;
	int sock;
	struct event *evt;
	void *ctx;
	void (*err_cb)(struct fscmd_handle *, void *, int, int);

	struct fscmd_handle *parent;
	const char *prompt;
	struct fscmd_tree *cmd_tree;

	TAILQ_HEAD(fscmd_handle_list, fscmd_handle) child;
	TAILQ_ENTRY(fscmd_handle) lnk;
};

/*****************************************************************************
 *	API low
 *****************************************************************************/
extern struct fscmd_handle *fscmd_create(const char *,
					 void *,
					 struct fscmd_handle *,
					 const char *,
					 const struct fscmd_table *);
extern void fscmd_destroy(struct fscmd_handle *);

extern int fscmd_dispatch(struct fscmd_handle *, char *, size_t);
extern int fscmd_printf(struct fscmd_handle *, const char *, ...);

/* util */
extern void fscmd_unbind_socket(struct fscmd_handle *);
extern int fscmd_bind_socket(struct fscmd_handle *,
			     int, int,
			     void (*)(struct fscmd_handle *, void *,
				      int, int));

extern void fscmd_unbind_event(struct fscmd_handle *);
extern int fscmd_bind_event(struct fscmd_handle *,
			    short, void (*)(int, short, void *),
			    const struct timeval *);

/* for private used */
extern int fscmd_printf_raw(struct fscmd_handle *, int, const char *, ...);
#define	fscmd_printf(handle_,fmt_,...) fscmd_printf_raw((handle_),0,(fmt_),##__VA_ARGS__)

/*****************************************************************************
 *	API high(old style)
 *****************************************************************************/
extern void fscmd_close(struct fscmd_handle *);
extern struct fscmd_handle *fscmd_init(struct fscmd_handle *,
				       const char *,
				       const struct fscmd_table *,
				       uint16_t, const char *,
				       void (*)(struct fscmd_handle *,
						void *, int, int),
				       void *);
extern struct fscmd_handle *fscmd_bind_stdin(struct fscmd_handle *,
					     const char *,
					     const struct fscmd_table *,
					     void (*)(struct fscmd_handle *,
						      void *, int, int),
					     void *);
extern int fscmd_bind_file(struct fscmd_handle *,
			   const struct fscmd_table *,
			   const char *, int);

/*****************************************************************************
 *	cli
 *****************************************************************************/
extern int fscmd_cli(const char *remote_name,
		     uint16_t port,
		     int in,
		     int out,
		     const struct timeval *tout,
		     void (*err_cb)(void *, int),
		     void *user_ctx);

extern int fscmd_open_server(const char *, uint16_t,
			     struct sockaddr_storage *, socklen_t *);
extern int fscmd_open_client(const char *, uint16_t,
			     struct sockaddr_storage *, socklen_t *);

#endif /* _JD_COMMAND_H_ */
