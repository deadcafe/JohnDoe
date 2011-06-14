/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

/*
 * Tiny Cache allocator
 */

#ifndef	_JD_MCACHE_H_
#define	_JD_MCACHE_H_

#include <sys/types.h>
#include <sys/queue.h>

struct mc_chunk;
TAILQ_HEAD(mc_chunk_lst, mc_chunk);

struct mcache;
TAILQ_HEAD(mcache_lst, mcache);

struct mcache {
	const char *name;
	struct mcache *parent;
	void (*destroy_cb)(struct mcache *, void *);
	void *destroy_arg;

	struct mc_chunk_lst chunks;
	size_t chunk_num;
	size_t wmark;
	struct mc_chunk *reserve;

	struct mcache_lst childs;
	size_t child_num;

	TAILQ_ENTRY(mcache) node;
};

/* for private used */
extern void * _mc_alloc_raw(struct mcache *,
			    size_t,
			    const char *,
			    const char *,
			    size_t);

/*
 * APIs
 */
#define mc_alloc(c_,s_)	_mc_alloc_raw((c_),(s_),__FILE__,__func__,__LINE__)
extern struct mcache *mc_create(struct mcache *,
				const char *,
				size_t,
				void (*)(struct mcache *, void *),
				void *);
extern void mc_destroy(struct mcache *);
extern void mc_free(void *);
extern void mc_flush(void *);
extern void mc_reset(struct mcache *);

extern int mc_walk(struct mcache *,
		   int (*cb)(void *, const char *, ...),
		   void *);
#endif	/* !_JD_MCACHE_H_ */
