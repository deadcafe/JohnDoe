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

/*****************************************************************************
 *	used pthread API
 *****************************************************************************/
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
extern int pthread_detach (pthread_t __th) __attribute__ ((weak));
extern pthread_t pthread_self (void) __attribute__ ((weak));

/*****************************************************************************
 *
 *****************************************************************************/
static void
socket_accepted(void *ctx,
		struct fstream_reception *reception __attribute__((unused)),
		int sock,
		int ecode)
{
	struct fstream *fstream;
	struct slaver_config *config = ctx;

	if (ecode) {
		ERRBUFF();
		LOG(LOG_ERR, "error: %s\n", STRERR(ecode));
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

static void
set_detach(void)
{
	int ecode;

	ecode = pthread_detach(pthread_self());
	if (ecode) {
		ERRBUFF();
		LOG(LOG_ERR, "failed at pthread_detach: %s\n", STRERR(ecode));
		exit(EXIT_FAILURE);
	}
}

static void *
socket_handler(void *arg)
{
	struct slaver_config *config = arg;

	LOG(LOG_DEBUG, "start\n");
	set_detach();
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


static inline bool
is_ready_pthread(void)
{
	if (!pthread_create ||
	    !pthread_attr_init ||
	    !pthread_attr_setdetachstate ||
	    !pthread_attr_setaffinity_np ||
	    !pthread_setaffinity_np ||
	    !pthread_getaffinity_np ||
	    !pthread_detach ||
	    !pthread_self)
		return false;
	return true;
}
struct slaver_affinity {
	int cpu;
	struct slaver_config *config;
};

static void *
slaver_loop(void *arg)
{
	cpu_set_t cpuset;
	struct slaver_affinity *affinity = arg;
	struct slaver_config *config = affinity->config;
	int ecode;

	set_detach();
	CPU_ZERO(&cpuset);
	CPU_SET(affinity->cpu, &cpuset);
	ecode = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
	if (ecode) {
		ERRBUFF();
		LOG(LOG_ERR, "failed at pthread_setaffinity_np: %s\n",
		    STRERR(ecode));
		exit(EXIT_FAILURE);
	}
	(*config->slaver_entry)(config->ctx);
	return arg;
}

int
jd_slaver_start(struct slaver_config *config,
		bool no_idle)
{
	int i;
	pthread_t th;
	cpu_set_t cpuset;
	int threads;
	int ecode;
	struct slaver_affinity *affinity = NULL;
	ERRBUFF();

	/* sanity check */
	if (!is_ready_pthread() ||
	    !config->msg_handler || !config->slaver_entry) {
		errno = EINVAL;
		return -1;
	}

	if ((ecode = pthread_create(&th, NULL, socket_handler, config)) != 0) {
		LOG(LOG_ERR, "failed at pthread_create: %s\n",
		    STRERR(ecode));
		goto end;
	}
	LOG(LOG_INFO, "created socket_handler: %x\n", th);

	CPU_ZERO(&cpuset);
	ecode = pthread_getaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
	if (ecode) {
		LOG(LOG_ERR, "failed at getaffinity: %s\n", STRERR(ecode));
		goto end;
	}
	threads = CPU_COUNT(&cpuset);
	if ((affinity = calloc(threads, sizeof(*affinity))) == NULL) {
		LOG(LOG_ERR, "not enough memory: %s\n", STRERR(errno));
		goto end;
	}
	affinity->cpu = 0;
	affinity->config = config;

	if (no_idle) {
		LOG(LOG_DEBUG, "slaver is not idle process\n");;
	} else {
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
		affinity[i].cpu = i;
		affinity[i].config = config;
		ecode = pthread_create(&th, NULL, slaver_loop, &affinity[i]);
		if (ecode) {
			LOG(LOG_ERR,
			    "failed at pthread_create: %s\n", STRERR(ecode));
			goto end;
		}
		LOG(LOG_INFO, "created slaver: %x\n", th);
	}
	slaver_loop(affinity);

	/* may be unreached */
	return 0;
end:
	if (affinity)
		free(affinity);
	errno = ecode;
	return -1;
}
