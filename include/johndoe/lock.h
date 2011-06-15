/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef	_JD_LOCK_H_
#define	_JD_LOCK_H_

#include <sys/types.h>

struct jd_mutex;
struct jd_mutex_profile {
	struct jd_mutex * (*create)(void *);
	void (*destroy)(struct jd_mutex *);
	void (*lock)(struct jd_mutex *);
	void (*unlock)(struct jd_mutex *);
};

struct jd_mutex {
	void *ctx;
	const struct jd_mutex_profile *profile;
};

/*
 * API
 */
static inline struct jd_mutex *
jd_create_mutex(const struct jd_mutex_profile *profile,
		void *ctx)
{
	return (*profile->create)(ctx);
}

static inline void
jd_destroy_mutex(struct jd_mutex *mutex)
{
	(*mutex->profile->destroy)(mutex);
}

static inline void
jd_lock_mutex(struct jd_mutex *mutex)
{
	(*mutex->profile->lock)(mutex);
}

static inline void
jd_unlock_mutex(struct jd_mutex *mutex)
{
	(*mutex->profile->unlock)(mutex);
}

extern const struct jd_mutex_profile *jd_mutex_profile_default(void);

#endif	/* !_JD_MUTEX_H_ */
