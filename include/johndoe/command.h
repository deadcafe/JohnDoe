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

struct jd_cmd_handle;

/*
 * command table
 */
struct jd_cmd_table {
	const char *cmd;
	const char *help;
	void (*func)(struct jd_cmd_handle *, void *, int, char **);
	const struct jd_cmd_table *sub;
};

struct jd_cmd_node {
	const struct jd_cmd_table *tbl;
	TAILQ_ENTRY(jd_cmd_node) lnk;
	TAILQ_HEAD(jd_cmd_tree, jd_cmd_node) sub_tree;
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

struct jd_cmd_handle {
	char *name;
	size_t refcnt;

	int state;
	int sock;
	struct event *evt;
	void *ctx;
	void (*err_cb)(struct jd_cmd_handle *, void *, int, int);

	struct jd_cmd_handle *parent;
	const char *prompt;
	struct jd_cmd_tree *cmd_tree;

	TAILQ_HEAD(jd_cmd_handle_list, jd_cmd_handle) child;
	TAILQ_ENTRY(jd_cmd_handle) lnk;
};

/*****************************************************************************
 *	API low
 *****************************************************************************/
extern struct jd_cmd_handle *jd_cmd_create(const char *,
					   void *,
					   struct jd_cmd_handle *,
					   const char *,
					   const struct jd_cmd_table *);
extern void jd_cmd_destroy(struct jd_cmd_handle *);

extern int jd_cmd_dispatch(struct jd_cmd_handle *, char *, size_t);
extern int jd_cmd_printf(struct jd_cmd_handle *, const char *, ...);

/* util */
extern void jd_cmd_unbind_socket(struct jd_cmd_handle *);
extern int jd_cmd_bind_socket(struct jd_cmd_handle *,
			      int, int,
			      void (*)(struct jd_cmd_handle *, void *,
				       int, int));

extern void jd_cmd_unbind_event(struct jd_cmd_handle *);
extern int jd_cmd_bind_event(struct jd_cmd_handle *,
			     short, void (*)(int, short, void *),
			     const struct timeval *);

/* for private used */
extern int jd_cmd_printf_raw(struct jd_cmd_handle *, int, const char *, ...);
#define	jd_cmd_printf(handle_,fmt_,...) jd_cmd_printf_raw((handle_),0,(fmt_),##__VA_ARGS__)

/*****************************************************************************
 *	API high(old style)
 *****************************************************************************/
extern void jd_cmd_close(struct jd_cmd_handle *);
extern struct jd_cmd_handle *jd_cmd_init(struct jd_cmd_handle *,
					 const char *,
					 const struct jd_cmd_table *,
					 uint16_t, const char *,
					 void (*)(struct jd_cmd_handle *,
						  void *, int, int),
					 void *);
extern struct jd_cmd_handle *jd_cmd_bind_stdin(struct jd_cmd_handle *,
					       const char *,
					       const struct jd_cmd_table *,
					       void (*)(struct jd_cmd_handle *,
							void *, int, int),
					       void *);
extern int jd_cmd_bind_file(struct jd_cmd_handle *,
			    const struct jd_cmd_table *,
			    const char *, int);

/*****************************************************************************
 *	cli
 *****************************************************************************/
extern int jd_cmd_cli(const char *remote_name,
		      uint16_t port,
		      int in,
		      int out,
		      const struct timeval *tout,
		      void (*err_cb)(void *, int),
		      void *user_ctx);

extern int jd_cmd_open_server(const char *, uint16_t,
			      struct sockaddr_storage *, socklen_t *);
extern int jd_cmd_open_client(const char *, uint16_t,
			      struct sockaddr_storage *, socklen_t *);

#endif /* _JD_COMMAND_H_ */
