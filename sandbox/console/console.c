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
cli_err_handler(void *ctx __attribute__((unused)),
		int ecode)
{
	fprintf(stderr, "catch cli err: %s\n", strerror(ecode));
}

int
main(int argc,
     char **argv)
{
	int c;
	char *remote = "unix.socket";
	uint16_t port = 1443;
	struct timeval tout = {
		.tv_sec = 0,
		.tv_usec = 500,
	};

	fprintf(stderr, "%d argc: %d argv[0]: %s\n", getpid(), argc, argv[0]);

	while ((c = getopt(argc, argv, "csp:r:")) != -1) {
                switch (c) {
		case 'p':
			port = atoi(optarg);
			break;
		case 'r':
			remote = optarg;
			break;
                default:
                        fprintf(stderr,
				"usage: [-r remote] [-p portn]");
                        exit(0);
                }
        }

	jd_set_logger(logger);
	event_init();
	signal(SIGPIPE, SIG_IGN);


	if (jd_cmd_cli(remote, port, STDIN_FILENO, STDOUT_FILENO,
		       &tout, cli_err_handler, NULL)) {
		perror("command_cli");
		exit(0);
	}

	event_dispatch();
	return 0;
}
