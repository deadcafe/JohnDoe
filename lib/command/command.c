/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <event.h>

#include "johndoe/socket.h"
#include "johndoe/command.h"
#include "log.h"

#define	PRINT_BUFFER_SIZE 512
#define LINE_BUFFER_SIZE 2048
#define	ARG_SIZE	32

static const struct jd_cmd_table basic_cmd_tbl[];

#define disp_prompt(s)	jd_cmd_printf_raw((s), 1, (s)->prompt)

/*****************************************************************************
 *	Command Tree
 *****************************************************************************/
static void
destroy_cmd_node(struct jd_cmd_node *node)
{
	struct jd_cmd_node *child;

	while ((child = TAILQ_FIRST(&node->sub_tree)) != NULL) {
		TAILQ_REMOVE(&node->sub_tree, child, lnk);
		destroy_cmd_node(child);
	}
	LOG(LOG_DEBUG, "destroyed node: %p  tbl: %p(%s)\n",
	    node, node->tbl, node->tbl->cmd);
	free(node);
}

static int add_cmd_table(struct jd_cmd_tree *head,
			     const struct jd_cmd_table *tbl);

static struct jd_cmd_node *
create_cmd_node(const struct jd_cmd_table *tbl)
{
	struct jd_cmd_node *node;

	if ((node = malloc(sizeof(*node))) != NULL) {
		node->tbl = tbl;
		TAILQ_INIT(&node->sub_tree);
		if (tbl->sub) {
			if (add_cmd_table(&node->sub_tree, tbl->sub)) {
				LOG(LOG_NOTICE,
				    "failed at add_jd_cmd_tbl()\n");
				destroy_cmd_node(node);
				node = NULL;
			}
		}
	}
	LOG(LOG_DEBUG, "created node: %p  tbl: %p(%s)\n", node, tbl, tbl->cmd);
	return node;
}

static int
add_cmd_table(struct jd_cmd_tree *head,
		  const struct jd_cmd_table *tbl)
{
	for (; tbl->cmd; tbl++) {
		struct jd_cmd_node *new, *node;

		LOG(LOG_DEBUG, "adding tbl: %p(%s)\n", tbl, tbl->cmd);

		if ((new = create_cmd_node(tbl)) == NULL) {
			LOG(LOG_NOTICE, "failed at create_cmd_node()\n");
			return -1;
		}

		TAILQ_FOREACH(node, head, lnk) {
			int cmp = strcmp(new->tbl->cmd, node->tbl->cmd);

			if (cmp <= 0) {
				TAILQ_INSERT_BEFORE(node, new, lnk);
				if (cmp == 0)
					destroy_cmd_node(node);
				goto done;
			}
		}
		TAILQ_INSERT_TAIL(head, new, lnk);
		LOG(LOG_DEBUG, "added table(%p) to %p\n", new, head);
	done:
		;
	}
	return 0;
}

static void
destroy_cmd_tree(struct jd_cmd_tree *tree)
{
	struct jd_cmd_node *node;

	LOG(LOG_DEBUG, "destroy tbl: %p\n", tree);
	while ((node = TAILQ_FIRST(tree)) != NULL) {
		TAILQ_REMOVE(tree, node, lnk);
		destroy_cmd_node(node);
	}
	free(tree);
}

static struct jd_cmd_tree *
create_cmd_tree(const struct jd_cmd_table *tbl)
{
	struct jd_cmd_tree *head;

	if ((head = malloc(sizeof(*head))) != NULL) {
		TAILQ_INIT(head);
		if (add_cmd_table(head, tbl)) {
			LOG(LOG_NOTICE, "failed at add_cmd_table()\n");
			free(head);
			head = NULL;
		}
	}
	LOG(LOG_DEBUG, "created table head: %p  tbl: %p(%s)\n",
	    head, tbl, tbl->cmd);
	return head;
}

/*****************************************************************************
 *	command handle operations
 *****************************************************************************/
static int
usage(struct jd_cmd_handle *handle,
      struct jd_cmd_tree *tree)
{
	struct jd_cmd_node *node;

	TAILQ_FOREACH(node, tree, lnk)
		jd_cmd_printf(handle, "\t%s:\t%s\n",
			       node->tbl->cmd, node->tbl->help);
	return 0;
}

static int
dispatch(struct jd_cmd_handle *handle,
	 struct jd_cmd_tree *tree,
	 int argc, char **argv)
{
	struct jd_cmd_node *node;

	TAILQ_FOREACH(node, tree, lnk) {
		int cmp;

		cmp = strcmp(node->tbl->cmd, argv[0]);
		if (cmp < 0)
			continue;
		else if (!cmp) {
			if (node->tbl->sub && argc > 1) {
				return dispatch(handle,
						&node->sub_tree,
						--argc, ++argv);
			} else if (node->tbl->func) {
				(*node->tbl->func)(handle, handle->ctx,
						   --argc, ++argv);
				return 0;
			}
		}
		break;
	}
	if (!strcmp("help", argv[0]) || !strcmp("?", argv[0]))
		return usage(handle, tree);
	return -1;
}

static inline int
line2args(char *line,
	  ssize_t len,
	  char **argv,
	  size_t size)
{
	int ac = 0;
	char *p = NULL;

	while (len && *line != '\0') {
		if (isspace(*line)) {
			*line = '\0';
			p = NULL;
		} else if (!p) {
			p = line;
			argv[ac++] = p;
			if ((size_t) ac > size)
				return -1;
		}
		line++;
		len--;
	}
	return ac;
}

static inline void
detach_handle(struct jd_cmd_handle *handle)
{
	handle->refcnt--;
	if (!handle->refcnt) {
		assert(handle->state == CMD_DEAD &&
		       TAILQ_EMPTY(&handle->child));

		LOG(LOG_DEBUG, "free command socket: %p(%s)\n",
		    handle, handle->name);
		if (handle->name)
			free(handle->name);
		free(handle);
	}
}

static inline void
attach_handle(struct jd_cmd_handle *handle)
{
	assert(handle->state != CMD_DEAD);
	handle->refcnt++;
}

static void
quit_exec(struct jd_cmd_handle *handle,
	  void *ctx __attribute__((unused)),
	  int argc __attribute__((unused)),
	  char **argv __attribute__((unused)))
{
	LOG(LOG_DEBUG, "state: %d  refcnt: %d\n",
	    handle->state, handle->refcnt);
	jd_cmd_printf(handle, "bye bye\n");
	jd_cmd_destroy(handle);
}

static const struct jd_cmd_table basic_cmd_tbl[] = {
	{
		.cmd = "quit",
		.func = quit_exec,
		.help = "Quit the shell"
	},
	{
		.cmd = "exit",
		.func = quit_exec,
		.help = "Quit the shell"
	},
	{
		.cmd = NULL,
	},
};

/*****************************************************************************
 *	API low
 *****************************************************************************/
struct jd_cmd_handle *
jd_cmd_create(const char *name,
	      void *ctx,
	      struct jd_cmd_handle *parent,
	      const char *prompt,
	      const struct jd_cmd_table *tbl)
{
	struct jd_cmd_handle *handle;

	if ((handle = calloc(1, sizeof(*handle))) != NULL) {
		TAILQ_INIT(&handle->child);
		handle->refcnt = 1;
		handle->sock = -1;
		handle->ctx = ctx;
		handle->state = CMD_READY;

		if (parent) {
			if (parent->state == CMD_DEAD) {
				errno = EINVAL;
				free(handle);
				return NULL;
			}
			handle->parent = parent;
			handle->prompt = parent->prompt;
			handle->cmd_tree = parent->cmd_tree;
			TAILQ_INSERT_TAIL(&parent->child, handle, lnk);
			attach_handle(parent);
		} else {
			if (!prompt || !tbl) {
				errno = EINVAL;
				free(handle);
				return NULL;
			}
			handle->prompt = prompt;
			handle->cmd_tree = create_cmd_tree(tbl);
			if (!handle->cmd_tree) {
				free(handle);
				return NULL;
			}
		}
		if (name)
			handle->name = strdup(name);

		LOG(LOG_INFO, "created command handle: %p(%s)\n",
		    handle, handle->name);
	}
	return handle;
}

static void
jd_cmd_destroy_raw(struct jd_cmd_handle *handle,
		   int ecode)
{
	struct jd_cmd_handle *child;

	LOG(LOG_DEBUG, "handle: %p(%s) sock: %d\n",
	    handle, handle->name, handle->sock);

	if (ecode && handle->err_cb) {
		void (*err_cb)(struct jd_cmd_handle *, void *,
			       int, int) = err_cb;
		int sock = handle->sock;

		jd_cmd_unbind_socket(handle);
		(*err_cb)(handle, handle->ctx, sock, ecode);
	} else {
		jd_cmd_unbind_socket(handle);
	}

	if (handle->sock >= 0)
		CLOSE(handle->sock);
	handle->sock = -1;
	handle->state = CMD_DEAD;

	if (handle->parent) {
		TAILQ_REMOVE(&handle->parent->child, handle, lnk);
		detach_handle(handle->parent);
		handle->prompt = NULL;
		handle->cmd_tree = NULL;
		handle->parent = NULL;
	}
	while ((child = TAILQ_FIRST(&handle->child)) != NULL)
		jd_cmd_destroy_raw(child, 0);

	if (handle->cmd_tree) {
		destroy_cmd_tree(handle->cmd_tree);
		handle->cmd_tree = NULL;
	}
	if (handle->prompt)
		handle->prompt = NULL;

	LOG(LOG_INFO, "destroyed command handle: %p(%s)\n",
	    handle, handle->name);
	detach_handle(handle);
}

void
jd_cmd_destroy(struct jd_cmd_handle *handle)
{
	handle->err_cb = NULL;
	jd_cmd_destroy_raw(handle, 0);
}

/*
 * register socket
 */
void
jd_cmd_unbind_socket(struct jd_cmd_handle *handle)
{
	jd_cmd_unbind_event(handle);
	switch (handle->state) {
	case CMD_LISTEN:
	case CMD_ACCEPT:
		LOG(LOG_DEBUG, "unbind socket: %d\n", handle->sock);
		CLOSE(handle->sock);
	case CMD_PARMANENT:
		handle->sock = -1;
		handle->err_cb = NULL;
		handle->state = CMD_READY;
		break;
	default:
		break;
	}
}

int
jd_cmd_bind_socket(struct jd_cmd_handle *handle,
		   int sock,
		   int state,
		   void (*err_cb)(struct jd_cmd_handle *, void *, int, int))
{
	if (sock < 0 || !err_cb || CMD_DEAD > state || CMD_PARMANENT < state) {
		errno = EINVAL;
		return -1;
	}
	if (handle->sock >= 0) {
		errno = EEXIST;
		return -1;
	}
	if (handle->state != CMD_READY) {
		errno = EPERM;
		return -1;
	}
	handle->sock = sock;
	handle->err_cb = err_cb;
	handle->state = state;
	return disp_prompt(handle);
}

/*
 * register event
 */
void
jd_cmd_unbind_event(struct jd_cmd_handle *handle)
{
	ERRBUFF();

	if (handle->evt) {
		LOG(LOG_DEBUG, "unbind socket event: %d\n", handle->sock);
		if (event_del(handle->evt))
			LOG(LOG_NOTICE, "failed at event_del: %s\n",
			    STRERR(errno));
		free(handle->evt);
		handle->evt = NULL;
	}
}

int
jd_cmd_bind_event(struct jd_cmd_handle *handle,
		  short event,
		  void (*handler)(int, short, void *),
		  const struct timeval *to)
{
	ERRBUFF();

	if (!event || !handler) {
		errno = EINVAL;
		return -1;
	}
	if (handle->evt) {
		errno = EEXIST;
		return -1;
	}
	if (handle->state <= CMD_READY || handle->sock < 0) {
		errno = EPERM;
		return -1;
	}
	if ((handle->evt = malloc(sizeof(*(handle->evt)))) == NULL) {
		LOG(LOG_NOTICE, "failed at malloc: %s\n", STRERR(errno));
		return -1;
	}
	event_set(handle->evt, handle->sock, event, handler, handle);
	if (event_add(handle->evt, to)) {
		LOG(LOG_NOTICE, "failed at event_add: %s\n", STRERR(errno));
		free(handle->evt);
		handle->evt = NULL;
		return -1;
	}
	return 0;
}

int
jd_cmd_dispatch(struct jd_cmd_handle *handle,
		char *line,
		size_t len)
{
	int ret;
	int argc;
	char *argv[ARG_SIZE];

	if (handle->state < CMD_READY) {
		errno = EPERM;
		return -1;
	}

	argc = line2args(line, len, argv, ARG_SIZE - 1);

	attach_handle(handle);
	if (argc > 0) {
		argv[argc] = NULL;
		ret = dispatch(handle, handle->cmd_tree, argc, argv);
		if (ret) {
			int i;

			jd_cmd_printf(handle,
				       "unknown command: ");
			for (i = 0; i < argc; i++)
				jd_cmd_printf(handle, "%s ", argv[i]);
			jd_cmd_printf(handle, "\n");
		}
	} else if (argc < 0) {
		jd_cmd_printf(handle, "too many token\n");
	}
	disp_prompt(handle);
	detach_handle(handle);
	return 0;
}

int
jd_cmd_printf_raw(struct jd_cmd_handle *handle,
		  int flags,
		  const char *fmt,
		  ...)
{
	va_list ap;
	char buff[PRINT_BUFFER_SIZE];
	size_t size;
	ssize_t len;

	if (handle->state == CMD_LISTEN)
		return 0;
	if (handle->state < CMD_READY || handle->sock < 0) {
		errno = EBADR;
		return -1;
	}

	va_start(ap, fmt);
	size = vsnprintf(buff, sizeof(buff), fmt, ap);
	va_end(ap);

	if (size > sizeof(buff))
		size = sizeof(buff) - 1;

	if (!flags)
		flags = MSG_NOSIGNAL | MSG_MORE;
	else
		flags = MSG_NOSIGNAL;
	len = 0;
	while (size) {
		ssize_t slen;

		errno = 0;
		slen = write(handle->sock, &buff[len], size);
		if (slen < 0) {
			if (errno == EINTR)
				continue;
			else if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;	/* ignore msg, sorry */

			jd_cmd_destroy_raw(handle, errno);
			return -1;
		}
		len += slen;
		size -= slen;
	}
	return 0;
}

/*****************************************************************************
 *	API high(old style) & utils
 *****************************************************************************/
void
jd_cmd_close(struct jd_cmd_handle *handle)
{
	jd_cmd_destroy(handle);
}

/*
 * default event handler
 */
static void
event_handler(int s __attribute__((unused)),
	      short event __attribute__((unused)),
	      void *arg)
{
	ssize_t bytes;
	struct jd_cmd_handle *handle = arg;
	char line[LINE_BUFFER_SIZE];

	LOG(LOG_DEBUG, "trace handle: %p\n", handle);

	errno = 0;
	bytes = read(handle->sock, line, sizeof(line) - 1);
	if (bytes <= 0) {
		struct jd_cmd_handle *handle = arg;

		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
			jd_cmd_destroy_raw(handle, errno);
		return;
	}
	LOG(LOG_DEBUG, "byte: %ld\n", bytes);
	if (bytes > 0) {
		ssize_t odd = bytes;
		char *p = line;

		line[bytes] = '\0';
		while (odd > 0) {
			size_t len;
			char *cr;

			if ((cr = memchr(p, '\n', odd)) == NULL) {
				LOG(LOG_INFO, "jamming: ignored %s\n", p);
 				break;
			}

			len = cr - p + 1;
			jd_cmd_dispatch(handle, p, len);
			odd -= len;
			p += len;
		}
	}
}

/*
 * jd_cmd_init callback(listen)
 */
static void
listen_handler(int s __attribute__ ((unused)),
	       short event __attribute__ ((unused)),
	       void *arg)
{
	struct sockaddr_storage ss;
	socklen_t sslen = sizeof(ss);
	struct jd_cmd_handle *handle, *parent = arg;
	int sd;
	char from[128];
	ERRBUFF();

	LOG(LOG_DEBUG, "trace parent: %p\n", parent);

	memset(&ss, 0, sizeof(ss));
	if ((sd = accept4(parent->sock, (struct sockaddr *)&ss, &sslen,
			  SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
		LOG(LOG_NOTICE, "failed at accept4(): %s\n",
		    STRERR(errno));
		return;
	}

	switch (ss.ss_family) {
	case AF_INET:
	{
		char buff[INET_ADDRSTRLEN];
		struct sockaddr_in *sai4 = (struct sockaddr_in *) &ss;

		inet_ntop(AF_INET, &sai4->sin_addr, buff, sizeof(buff));
		snprintf(from, sizeof(from), "%s:%d",
			 buff, ntohs(sai4->sin_port));
		break;
	}

	case AF_INET6:
	{
		char buff[INET6_ADDRSTRLEN];
		struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *) &ss;

		inet_ntop(AF_INET6, &sai6->sin6_addr, buff, sizeof(buff));
		snprintf(from, sizeof(from), "%s:%d",
			 buff, ntohs(sai6->sin6_port));
		break;
	}

	case AF_UNIX:
	{
		struct sockaddr_un *sau = (struct sockaddr_un *) &ss;

		snprintf(from, sizeof(from), "%s", sau->sun_path);
		break;
	}

	default:
		LOG(LOG_NOTICE, "unknown address family: %d\n", ss.ss_family);
		CLOSE(sd);
		return;
	}

	handle = jd_cmd_create(from, parent->ctx, parent, NULL, NULL);
	if (!handle) {
		CLOSE(sd);
		return;
	}
	if (jd_cmd_bind_socket(handle, sd, CMD_ACCEPT, parent->err_cb)) {
		jd_cmd_destroy(handle);
		CLOSE(sd);
		return;
	}
	if (jd_cmd_bind_event(handle, EV_READ | EV_PERSIST,
			       event_handler, NULL)) {
		jd_cmd_destroy(handle);
		CLOSE(sd);
		return;
	}
}

struct jd_cmd_handle *
jd_cmd_init(struct jd_cmd_handle *parent,
	    const char *prompt,
	    const struct jd_cmd_table *tbl,
	    uint16_t port,
	    const char *sock_name,
	    void (*err_cb)(struct jd_cmd_handle *,
			   void *, int, int),
	    void *ctx)
{
	struct sockaddr_storage ss;
	socklen_t salen;
	struct jd_cmd_handle *handle = NULL;
	int sock = -1;
	ERRBUFF();

	if ((!parent && (!prompt || !tbl)) || !err_cb) {
		errno = EINVAL;
		return NULL;
	}

	if ((sock = jd_cmd_open_server(sock_name, port, &ss, &salen)) < 0)
		return NULL;
	if (bind(sock, (struct sockaddr *)&ss, salen) < 0) {
		LOG(LOG_NOTICE, "failed at bind(): %s\n", STRERR(errno));
		CLOSE(sock);
		return NULL;
	}
	if (listen(sock, 1) < 0) {
		LOG(LOG_NOTICE, "failed at listen(): %s\n", STRERR(errno));
		CLOSE(sock);
		return NULL;
	}

	handle = jd_cmd_create(sock_name, ctx, parent, prompt, basic_cmd_tbl);
	if (!handle) {
		CLOSE(sock);
		return NULL;
	}
	if (add_cmd_table(handle->cmd_tree, tbl)) {
		jd_cmd_destroy(handle);
		CLOSE(sock);
		return NULL;
	}
	if (jd_cmd_bind_socket(handle, sock, CMD_LISTEN, err_cb)) {
		jd_cmd_destroy(handle);
		CLOSE(sock);
		return NULL;
	}
	if (jd_cmd_bind_event(handle, EV_READ | EV_PERSIST,
			       listen_handler, NULL)) {
		jd_cmd_destroy(handle);
		handle = NULL;
	}
	return handle;
}

struct jd_cmd_handle *
jd_cmd_bind_stdin(struct jd_cmd_handle *parent,
		  const char *prompt,
		  const struct jd_cmd_table *tbl,
		  void (*err_cb)(struct jd_cmd_handle *, void *, int, int),
		  void *ctx)
{
	struct jd_cmd_handle *handle;

	if (!err_cb || (!parent && (!prompt || !tbl))) {
		errno = EINVAL;
		return NULL;
	}

	handle = jd_cmd_create("stdin", ctx, parent, prompt, tbl);
	if (handle) {
		if (jd_cmd_bind_socket(handle, STDIN_FILENO, CMD_PARMANENT,
					err_cb)) {
			jd_cmd_destroy(handle);
			return NULL;
		}
		if (jd_cmd_bind_event(handle, EV_READ | EV_PERSIST,
				       event_handler, NULL)) {
			jd_cmd_destroy(handle);
			return NULL;
		}
	}
	return handle;
}

static void
err_handler(struct jd_cmd_handle *handle,
	    void *ctx __attribute__((unused)),
	    int sock __attribute__((unused)),
	    int ecode)
{
	ERRBUFF();

	LOG(LOG_INFO, "error handle: %p %s\n", handle, STRERR(ecode));
	jd_cmd_destroy(handle);
}

int
jd_cmd_bind_file(struct jd_cmd_handle *parent,
		 const struct jd_cmd_table *tbl,
		 const char *fname,
		  int out)
{
	FILE *fp = NULL;
	struct jd_cmd_handle *handle;
	int fline = -1;
	char prompt[64];
	ERRBUFF();

	if (!fname || (!parent && !tbl)) {
		errno = EINVAL;
		goto end;
	}

	if ((fp = fopen(fname, "r")) == NULL) {
		LOG(LOG_NOTICE, "Fail to open %s: %s\n", fname, STRERR(errno));
		goto end;
	}

	prompt[0] = '\0';
	fline = 0;
	handle = jd_cmd_create("fname", NULL, parent, prompt, tbl);
	if (handle) {
		char line[LINE_BUFFER_SIZE];

		/* dirty hack! */
		handle->prompt = prompt;
		snprintf(prompt, sizeof(prompt), "%s<%d> ", fname, ++fline);

		if (jd_cmd_bind_socket(handle, out, CMD_PARMANENT,
					err_handler)) {
			jd_cmd_destroy(handle);
			goto end;
		}

		while (fgets(line, sizeof(line), fp) != NULL) {
			snprintf(prompt, sizeof(prompt), "%s<%d> ",
				 fname, ++fline);
			jd_cmd_printf(handle, "%s", line);
			jd_cmd_dispatch(handle, line, strlen(line));
		}

		jd_cmd_unbind_socket(handle);
		jd_cmd_destroy(handle);
	}
end:
	if (fp)
		fclose(fp);
	return fline;
}

/*
 * server setup.
 */
static const int optval_true = 1;
static const int optval_false = 0;
static const struct linger optval_linger = {
	.l_onoff = 0,
	.l_linger = 0,
};
static const struct fssock_option fssock_server_options[] = {
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

static int tcp_keep_idle = 1;
static int tcp_keep_cnt = 1;
static int tcp_keep_interval = 1;
static const struct fssock_option tcp_server_options[] = {
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
		.name = NULL,
	},
};

int
jd_cmd_open_server(const char *name,
		   uint16_t port,
		   struct sockaddr_storage *ss,
		   socklen_t *salen)
{
	int sock;
	ERRBUFF();

	memset(ss, 0, sizeof(*ss));
	if (name == NULL || !strcmp(name, "ipv6")) {
		struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *) ss;

		if (!port) {
			errno = EINVAL;
			return -1;
		}
		sai6->sin6_family = AF_INET6;
		sai6->sin6_addr = in6addr_loopback;
		sai6->sin6_port = htons(port);
		*salen = sizeof(*sai6);
	} else if (!strcmp(name, "ipv4")) {
		struct sockaddr_in *sai4 = (struct sockaddr_in *) ss;

		if (!port) {
			errno = EINVAL;
			return -1;
		}
		sai4->sin_family = AF_INET;
//		sai4->sin_addr = INADDR_LOOPBACK;
		sai4->sin_port = htons(port);
		*salen = sizeof(*sai4);
	} else {
		struct sockaddr_un *sau = (struct sockaddr_un *) ss;

		sau->sun_family = AF_UNIX;
		strncpy(sau->sun_path, name , sizeof(sau->sun_path) -1);
		unlink(name);
		*salen = sizeof(*sau);
	}

	if ((sock = socket(ss->ss_family,
			   SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
			   0)) < 0) {
		LOG(LOG_NOTICE, "failed at socket(): %s\n",
		    STRERR(errno));
		return -1;
	}
	if (fssock_set_option(sock, fssock_server_options) < 0) {
		CLOSE(sock);
		return -1;
	}
	if (ss->ss_family != AF_UNIX) {
		if (fssock_set_option(sock, tcp_server_options) < 0) {
			CLOSE(sock);
			return -1;
		}
	}
	return sock;
}
