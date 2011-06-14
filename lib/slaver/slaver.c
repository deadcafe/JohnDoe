/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <stdarg.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>

#include "johndoe/slaver.h"
#include "log.h"

static void
socket_accepted(void *ctx,
		struct fstream_reception *reception __attribute__((unused)),
		int sock,
		int ecode)
{
	struct fstream *fstream;
	struct slaver_config *config = ctx;

	if (ecode) {
		LOG(LOG_ERR, "error: %d\n", ecode);
		exit(EXIT_FAILURE);
	}

	fstream = fstream_create(sock,
				 config->msg_pl_size,
				 config->msg_handler,
				 config->err_handler,
				 config->ctx);
	if (!fstream) {
		LOG(LOG_ERR, "failed at fstream_create: %d\n", errno);
		exit(EXIT_FAILURE);
	}
	LOG(LOG_DEBUG, "accepted\n");
}

static void *
socket_handler(void *arg)
{
	struct slaver_config *config = arg;

	LOG(LOG_DEBUG, "start\n");
	while (1) {
		struct fstream_reception *reception;

		reception = fstream_waiting_accept(config->domain,
						   config->protocol,
						   config->addr,
						   config->port,
						   socket_accepted,
						   config);
		if (!reception) {
			LOG(LOG_ERR, "failed at fstream_waiting_accept\n");
			exit(EXIT_FAILURE);
		}
		event_dispatch();
	}
	/* unreach */
	return NULL;
}

extern int pthread_create (pthread_t *__restrict __newthread,
			   __const pthread_attr_t *__restrict __attr,
			   void *(*__start_routine) (void *),
			   void *__restrict __arg) __attribute__ ((weak));
extern int pthread_attr_init (pthread_attr_t *__attr) __attribute__ ((weak));
extern int pthread_attr_setdetachstate (pthread_attr_t *__attr,
					int __detachstate)
	__attribute__ ((weak));
extern int pthread_attr_setaffinity_np (pthread_attr_t *__attr,
					size_t __cpusetsize,
					__const cpu_set_t *__cpuset)
	__attribute__ ((weak));
extern int pthread_setaffinity_np (pthread_t __th, size_t __cpusetsize,
				   __const cpu_set_t *__cpuset)
	__attribute__ ((weak));
extern int pthread_getaffinity_np (pthread_t __th, size_t __cpusetsize,
				   cpu_set_t *__cpuset)
	__attribute__ ((weak));

static inline bool
is_ready_pthread(void)
{
	if (!pthread_create ||
	    !pthread_attr_init ||
	    !pthread_attr_setdetachstate ||
	    !pthread_attr_setaffinity_np ||
	    !pthread_setaffinity_np ||
	    !pthread_getaffinity_np)
		return false;
	return true;
}

int
jd_slaver_start(struct slaver_config *config,
		bool no_idle)
{
	int i;
	pthread_t th;
	pthread_attr_t attr;
	cpu_set_t cpuset;
	int threads;
	int ecode;
	ERRBUFF();

	/* sanity check */
	if (!is_ready_pthread() ||
	    !config->msg_handler || !config->slaver_entry) {
		errno = EINVAL;
		return -1;
	}

	CPU_ZERO(&cpuset);
	ecode = pthread_getaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
	if (ecode) {
		LOG(LOG_ERR, "failed at getaffinity: %s\n", STRERR(ecode));
		goto end;
	}
	threads = CPU_COUNT(&cpuset);

	pthread_attr_init(&attr);
	ecode = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ecode) {
		LOG(LOG_ERR, "failed at pthread_attr_setdetachstate: %s",
		    STRERR(ecode));
		goto end;
	}

	if ((ecode = pthread_create(&th, &attr, socket_handler, config)) != 0) {
		LOG(LOG_ERR, "failed at pthread_create: %s\n",
		    STRERR(ecode));
		goto end;
	}
	LOG(LOG_INFO, "created socket_handler: %x\n", th);

	if (!no_idle) {
		struct sched_param param;

		memset(&param, 0, sizeof(param));
		if (sched_setscheduler(0, SCHED_IDLE, &param)) {
			ecode = errno;
			LOG(LOG_ERR, "failed at sched_setscheduler: %s\n",
			    STRERR(ecode));
			goto end;
		}
	}

	for (i = 1; i < threads; i++) {
		CPU_ZERO(&cpuset);
		CPU_SET(i, &cpuset);
		ecode = pthread_attr_setaffinity_np(&attr,
						    sizeof(cpuset), &cpuset);
		if (ecode) {
			LOG(LOG_ERR,
			    "failed at pthread_attr_setaffinity_np: %s",
			    STRERR(ecode));
			goto end;
		}
		ecode = pthread_create(&th, &attr,
				       config->slaver_entry, config->ctx);
		if (ecode) {
			LOG(LOG_ERR,
			    "failed at pthread_create: %s\n", STRERR(ecode));
			goto end;
		}
		LOG(LOG_INFO, "created slaver: %x\n", th);
	}

	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	ecode = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
	if (ecode) {
		LOG(LOG_ERR, "failed at pthread_setaffinity_np: %s\n",
		    STRERR(ecode));
		goto end;
	}
	(*config->slaver_entry)(config->ctx);

	/* unreach */
	return 0;
end:
	errno = ecode;
	return -1;
}
