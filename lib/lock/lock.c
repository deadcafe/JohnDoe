/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#include "johndoe/lock.h"
#include "log.h"

struct raw_mutex {
	struct jd_mutex jd;
	pthread_mutex_t mutex;
};

extern int pthread_mutex_init (pthread_mutex_t *__mutex,
                               __const pthread_mutexattr_t *__mutexattr)
	__attribute__((weak));
extern int pthread_mutex_destroy (pthread_mutex_t *__mutex)
	__attribute__((weak));
extern int pthread_mutex_lock (pthread_mutex_t *__mutex)
	__attribute__((weak));
extern int pthread_mutex_unlock (pthread_mutex_t *__mutex)
	__attribute__((weak));
extern int pthread_mutexattr_init (pthread_mutexattr_t *__attr)
	__attribute__((weak));
extern int pthread_mutexattr_destroy (pthread_mutexattr_t *__attr)
	__attribute__((weak));
extern int pthread_mutexattr_setprotocol (pthread_mutexattr_t *__attr,
                                          int __protocol)
	__attribute__((weak));

static struct jd_mutex *
create_mutex(void *ctx __attribute__((unused)))
{
	struct raw_mutex *raw;

	if ((raw = malloc(sizeof(*raw))) != NULL) {
		pthread_mutexattr_t attr;

		pthread_mutexattr_init(&attr);
#if 0
		if (pthread_mutexattr_setprotocol) {
			int ecode;

			LOG(LOG_DEBUG, "RT ready.\n");
			ecode = pthread_mutexattr_setprotocol(&attr,
							      PTHREAD_PRIO_INHERIT);
			if (ecode) {
				ERRBUFF();

				LOG(LOG_NOTICE,
				    "failed at pthread_mutexattr_setprotocol: %s\n",
				    STRERR(ecode));
			}
		}
#endif

		pthread_mutex_init(&raw->mutex, &attr);
		pthread_mutexattr_destroy(&attr);
		raw->jd.ctx = &raw->mutex;
		return &raw->jd;
	}
	return NULL;
}

static void
destroy_mutex(struct jd_mutex *mutex)
{
	struct raw_mutex *raw = (struct raw_mutex *) mutex;
	int ecode;

	ecode = pthread_mutex_destroy(&raw->mutex);
	if (ecode) {
		ERRBUFF();
		LOG(LOG_ERR,
		    "failed at pthread_mutex_destroy: %s\n", STRERR(ecode));
	} else
		free(raw);
}

static void
lock_mutex(struct jd_mutex *mutex)
{
	struct raw_mutex *raw = (struct raw_mutex *) mutex;
	int ecode;

	ecode = pthread_mutex_lock(&raw->mutex);
	if (ecode) {
		ERRBUFF();
		LOG(LOG_ERR,
		    "failed at pthread_mutex_lock: %s\n", STRERR(ecode));
	}
}

static void
unlock_mutex(struct jd_mutex *mutex)
{
	struct raw_mutex *raw = (struct raw_mutex *) mutex;
	int ecode;

	ecode = pthread_mutex_unlock(&raw->mutex);
	if (ecode) {
		ERRBUFF();
		LOG(LOG_ERR,
		    "failed at pthread_mutex_unlock: %s\n", STRERR(ecode));
	}
}

static const struct jd_mutex_profile default_profile = {
	.create = create_mutex,
	.destroy = destroy_mutex,
	.lock = lock_mutex,
	.unlock = unlock_mutex,
};

const struct jd_mutex_profile *
jd_mutex_profile_default(void)
{
	if (!pthread_mutex_init || !pthread_mutex_destroy ||
	    !pthread_mutex_lock || !pthread_mutex_unlock ||
	    !pthread_mutexattr_init || !pthread_mutexattr_destroy)
		return NULL;
	return &default_profile;
}
