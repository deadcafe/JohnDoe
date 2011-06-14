/*
 * Copyright (c) 2011 NEC Corporation, All rights reserved.
 */

#ifndef	_GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>

#include <johndoe/command.h>
#include <johndoe/log.h>


static void
show_ver(struct jd_cmd_handle *handle,
	 void *ctx __attribute__((unused)),
	 int argc __attribute__((unused)),
	 char **argv __attribute__((unused)))
{
	jd_cmd_printf(handle, "this is test version\n");
}

static void
foobar(struct jd_cmd_handle *handle,
       void *ctx __attribute__((unused)),
       int argc,
       char **argv)
{
	jd_cmd_printf(handle, "exec foobar: argc: %d  argv[0]:%s\n",
		      argc, argv[0]);
}

static const struct jd_cmd_table foo_cmdset[] = {
	{
		.cmd = "bar",
		.func = foobar,
		.help = "test command#1",
	},
	{
		.cmd = NULL,
	},
};

static const struct jd_cmd_table cmdset[] = {
	{
		.cmd = "ver",
		.func = show_ver,
		.help = "show version",
	},
	{
		.cmd = "foo",
		.help = "test command",
		.sub = foo_cmdset,
	},
	{
		.cmd = NULL,
	},
};

static void
logger(int lv __attribute__((unused)),
       const char *fmt,
       ...)
{
       va_list ap;

       if (lv > LOG_INFO)
	       return;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
}

static void
server_err_handler(struct jd_cmd_handle *handle,
		   void *ctx __attribute__((unused)),
		   int sock __attribute__((unused)),
		   int ecode)
{
	fprintf(stderr, "catch server err: %s\n", strerror(ecode));
	jd_cmd_destroy(handle);
}

static struct jd_cmd_handle *
server(const char *remote,
       uint16_t port,
       const char *fname)
{
	struct jd_cmd_handle *sock;

	sock = jd_cmd_init(NULL, "hoge> ", cmdset, port, remote,
			   server_err_handler, NULL);
	if (!sock) {
		fprintf(stderr, "failed at command_init\n");
		return NULL;
	}
	if (!jd_cmd_bind_stdin(sock, NULL, NULL, server_err_handler, NULL)) {
		fprintf(stderr, "failed at command_bind_stdin\n");
	}
	if (fname) {
		if (jd_cmd_bind_file(sock, NULL, fname, STDOUT_FILENO) < 0) {
			fprintf(stderr, "failed at command_bind_file\n");
		}
	}
	return sock;
}

int
main(int argc,
     char **argv)
{
	int c;
	struct jd_cmd_handle *sock = NULL;
	char *fname = NULL;
	char *remote = "unix.socket";
	uint16_t port = 1443;

	fprintf(stderr, "%d argc: %d argv[0]: %s\n", getpid(), argc, argv[0]);

	while ((c = getopt(argc, argv, "f:p:r:")) != -1) {
                switch (c) {
		case 'f':
			fname = optarg;
			break;

		case 'p':
			port = atoi(optarg);
			break;

		case 'r':
			remote = optarg;
			break;

                default:
                        fprintf(stderr,
				"usage: [-f file] [-r remote] [-p port]n");
                        exit(0);
                }
        }

	event_init();
	signal(SIGPIPE, SIG_IGN);
	jd_set_logger(logger);

	sock = server(remote, port, fname);
	event_dispatch();
	jd_cmd_close(sock);

	fprintf(stderr, "done\n");
	return 0;
}
