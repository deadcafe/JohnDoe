/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

#include "johndoe/cipher.h"

/*****************************************************************************
 *	common
 *****************************************************************************/
struct CRYPTO_dynlock_value {
	pthread_mutex_t mutex;
	unsigned long id;
	const char *file;
	int line;
};

extern pthread_t pthread_self (void) __attribute__ ((weak));
extern int pthread_mutex_lock (pthread_mutex_t *) __attribute__ ((weak));
extern int pthread_mutex_unlock (pthread_mutex_t *) __attribute__ ((weak));
extern int pthread_mutex_destroy (pthread_mutex_t *) __attribute__ ((weak));
extern int pthread_mutex_init (pthread_mutex_t *,
                               __const pthread_mutexattr_t *) __attribute__ ((weak));

static unsigned long
id_function(void)
{
        return (unsigned long) pthread_self();
}

static inline void
update_lock(struct CRYPTO_dynlock_value *lock,
	    const char *file,
	    int line)
{
	lock->file = file;
	lock->line = line;
	lock->id = id_function();
}

static void
dynlock_function(int mode,
		 struct CRYPTO_dynlock_value *lock,
		 const char *file,
		 int line)
{
	if (mode & CRYPTO_LOCK)
                pthread_mutex_lock(&lock->mutex);

	else
                pthread_mutex_unlock(&lock->mutex);
	update_lock(lock, file, line);
}

static struct CRYPTO_dynlock_value **static_mutex;
static void
lock_function(int mode,
	      int type,
	      const char *file,
	      int line)
{
	dynlock_function(mode, static_mutex[type], file, line);
}

static void
destroy_function(struct CRYPTO_dynlock_value *lock,
		 const char *file __attribute__((unused)),
		 int line __attribute__((unused)))
{
	pthread_mutex_destroy(&lock->mutex);
        free(lock);
}

static struct CRYPTO_dynlock_value *
create_function(const char *file,
		int line)
{
        struct CRYPTO_dynlock_value *lock;

        if ((lock = malloc(sizeof(*lock))) != NULL) {
		pthread_mutex_init(&lock->mutex, NULL);
		update_lock(lock, file, line);
	}
        return lock;
}

static int
thread_support(void)
{
	int type, num_locks;

	if (!pthread_self ||
	    !pthread_mutex_lock ||
	    !pthread_mutex_unlock ||
	    !pthread_mutex_init ||
	    !pthread_mutex_destroy)
		return 0;

	num_locks = CRYPTO_num_locks();
	static_mutex = calloc(num_locks,
			      sizeof(struct CRYPTO_dynlock_value *));
	if (!static_mutex)
		return -1;
	for (type = 0; type < num_locks; type++) {
                if ((static_mutex[type] = create_function(NULL, 0)) == NULL)
			return -1;
	}

	CRYPTO_set_locking_callback(lock_function);
	CRYPTO_set_dynlock_lock_callback(dynlock_function);
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_dynlock_create_callback(create_function);
	CRYPTO_set_dynlock_destroy_callback(destroy_function);
	return 0;
}

int
cipher_init(void)
{
	const char *err;

	OpenSSL_add_all_algorithms();
	if (thread_support()) {
		fprintf(stderr, "failed to initialize thread support.\n");
		return -1;
	}
	if ((err = dh_init()) != NULL) {
		fprintf(stderr, "failed to initialize DH %s\n", err);
		return -1;
	}
	return 0;
}

void
cipher_exit(void)
{
	dh_exit();
	EVP_cleanup();
}
