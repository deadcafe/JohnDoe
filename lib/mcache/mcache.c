/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#include <sys/mman.h>
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include "johndoe/mcache.h"

#ifdef	ENABLE_MC_DEBUG
# include <stdio.h>
# define	DBGTRACE(f_, ...)	fprintf(stderr, f_, ##__VA_ARGS__)
#else
# define	DBGTRACE(f_, ...)
#endif

struct mc_obj {
	struct mc_chunk *chunk;
	size_t size;
#ifdef	ENABLE_MC_DEBUG
	const char *file;
	size_t line;
	const char *func;
#endif
	TAILQ_ENTRY(mc_obj) node;
	char body[0];
};

struct mc_chunk {
	struct mcache *cache;
	size_t size;
	TAILQ_HEAD(mc_obj_lst, mc_obj) objs;
	TAILQ_ENTRY(mc_chunk) node;
	char envelope[0];
};

/*
 *
 */
static inline void
create_obj(struct mc_chunk *chunk)
{
	struct mc_obj *obj = (struct mc_obj *) (chunk->envelope);

	DBGTRACE("%s(%d): chunk:%p obj:%p\n",
		 __func__, __LINE__, chunk, obj);
#ifdef ENABLE_MC_DEBUG
	obj->file = NULL;
	obj->func = NULL;
	obj->line = 0;
#endif
	obj->chunk = chunk;
	obj->size = chunk->size - sizeof(*chunk) - sizeof(*obj);
	TAILQ_INIT(&chunk->objs);
	TAILQ_INSERT_TAIL(&chunk->objs, obj, node);
}


static inline struct mc_obj *
split_obj(struct mc_chunk *chunk,
	  struct mc_obj *obj,
	  size_t size)
{
	struct mc_obj *next;

	next = (struct mc_obj *) (&obj->body[size]);
	next->chunk = obj->chunk;
	next->size = obj->size - size - sizeof(*next);
	obj->size = size;

#ifdef ENABLE_MC_DEBUG
	next->file = NULL;
	next->func = NULL;
	next->line = 0;
#endif
	TAILQ_INSERT_HEAD(&chunk->objs, next, node);

	DBGTRACE("%s(%d): chunk:%p obj:%p size:%lu\n",
		 __func__, __LINE__, chunk, obj, size);
	return obj;
}

static inline void
unmap_chunk(struct mc_chunk *chunk)
{
	DBGTRACE("%s(%d): unmap cache:%p chunk:%p\n",
		 __func__, __LINE__, chunk->cache, chunk);
	munmap(chunk, chunk->size);
}

static inline void
release_reserved(struct mcache *cache)
{
	unmap_chunk(cache->reserve);
	cache->reserve = NULL;
}

static inline void
release_chunk(struct mc_chunk *chunk)
{
	struct mcache *cache = chunk->cache;

	TAILQ_REMOVE(&cache->chunks, chunk, node);
	cache->chunk_num--;

	if (!cache->chunk_num) {
		if (cache->reserve)
			release_reserved(cache);
		unmap_chunk(chunk);
	} else if (!cache->reserve) {
		cache->reserve = chunk;
		DBGTRACE("%s(%d): reserve cache:%p chunk:%p\n",
			 __func__, __LINE__, cache, chunk);
	} else {
		unmap_chunk(chunk);
	}
}

static inline struct mc_obj *
join_obj(struct mc_obj *obj)
{
	struct mc_obj *prev = TAILQ_PREV(obj, mc_obj_lst, node);

	if (prev) {
		struct mc_chunk *chunk = obj->chunk;

		TAILQ_REMOVE(&chunk->objs, obj, node);
		prev->size += (obj->size + sizeof(*obj));

		DBGTRACE("%s(%d): chunk:%p obj:%p prev:%p size:%lu\n",
			 __func__, __LINE__, chunk, obj, prev, prev->size);

		if (TAILQ_FIRST(&chunk->objs) == TAILQ_LAST(&chunk->objs,
							    mc_obj_lst)) {
			release_chunk(chunk);
			prev = NULL;
		}
	}
	return prev;
}

static inline struct mc_chunk *
alloc_chunk(size_t size)
{
	struct mc_chunk *chunk;

	chunk = mmap(0, size,
		     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
		     -1, 0);
	if (chunk == MAP_FAILED)
		return NULL;
	DBGTRACE("%s(%d): size:%lu chunk:%p\n",
		 __func__, __LINE__, size, chunk);
	chunk->size = size;
	chunk->cache = NULL;
	create_obj(chunk);
	return chunk;
}

/*
 * Memory Cache APIs
 */
#define ALIGNOF(x) (((x)+(sizeof(void *))-1L)&~((sizeof(void *))-1L))

static inline void
link_cache(struct mcache *parent,
	   struct mcache *cache)
{
	if (parent) {
		DBGTRACE("%s(%d): cache:%p %s\n",
			 __func__, __LINE__, cache, cache->name);

		TAILQ_INSERT_TAIL(&parent->childs, cache, node);
		parent->child_num++;
		cache->parent = parent;
	}
}

static inline void
unlink_cache(struct mcache *cache)
{
	struct mcache *parent = cache->parent;

	if (parent) {
		DBGTRACE("%s(%d): cache:%p %s\n",
			 __func__, __LINE__, cache, cache->name);

		TAILQ_REMOVE(&parent->childs, cache, node);
		parent->child_num--;
		cache->parent = NULL;
	}
}

struct mcache *
mc_create(struct mcache *parent,
	  const char *name,
	  size_t size,
	  void (*destroy_cb)(struct mcache *, void *),
	  void *destroy_arg)
{
	struct mcache *cache;
	struct mc_chunk *chunk;
	struct mc_obj *obj;

	if ((chunk = alloc_chunk(size)) == NULL)
		return NULL;
	obj = split_obj(chunk, TAILQ_FIRST(&chunk->objs),
			ALIGNOF(sizeof(*cache)));
	cache = (struct mcache *) (obj->body);
	cache->name = name;
	cache->parent = NULL;
	chunk->cache = cache;
#ifdef ENABLE_MC_DEBUG
	obj->file = name;
	obj->func = __func__;
	obj->line = 0;
#endif
	TAILQ_INIT(&cache->chunks);
	TAILQ_INSERT_HEAD(&cache->chunks, chunk, node);
	TAILQ_INIT(&cache->childs);
	cache->chunk_num = 1;
	cache->child_num = 0;
	if ((cache->destroy_cb = destroy_cb) == NULL)
		destroy_arg = NULL;
	cache->destroy_arg = destroy_arg;
	link_cache(parent, cache);

	DBGTRACE("%s(%d): %s parent:%p size:%lu cache:%p\n",
		 __func__, __LINE__, name, parent, size, cache);
	return cache;
}

void
mc_destroy(struct mcache *cache)
{
	struct mc_chunk *chunk;
	struct mcache *child;

	DBGTRACE("%s(%d): cache:%p %s\n",
		 __func__, __LINE__, cache, cache->name);

	unlink_cache(cache);
	if (cache->destroy_cb)
		(*cache->destroy_cb)(cache, cache->destroy_arg);
	while ((child = TAILQ_FIRST(&cache->childs)) != NULL)
		mc_destroy(child);
	while ((chunk = TAILQ_FIRST(&cache->chunks)) != NULL) {
		struct mc_chunk *next = TAILQ_NEXT(chunk, node);

		release_chunk(chunk);
		if (!next)
			break;
	}
}

void *
_mc_alloc_raw(struct mcache *cache,
	      size_t size,
	      const char *file __attribute__((unused)),
	      const char *func __attribute__((unused)),
	      size_t line __attribute__((unused)))
{
	struct mc_chunk *chunk;
	struct mc_obj *obj = NULL;

	size = ALIGNOF(size);
	chunk = TAILQ_FIRST(&cache->chunks);
	if (chunk->size - sizeof(*chunk) - sizeof(*obj) < size)
		return NULL;
	while (!obj) {
		obj = TAILQ_FIRST(&chunk->objs);
		if (obj->size >= sizeof(*obj) + size) {
			obj = split_obj(chunk, obj, size);
		} else {
			if (cache->reserve) {
				chunk = cache->reserve;
				cache->reserve = NULL;
				create_obj(chunk);
			} else if ((chunk = alloc_chunk(chunk->size)) == NULL)
				return NULL;
			chunk->cache = cache;
			cache->chunk_num++;
			if (cache->wmark < cache->chunk_num)
				cache->wmark = cache->chunk_num;
			TAILQ_INSERT_HEAD(&cache->chunks, chunk, node);
			obj = NULL;
		}
	}
#ifdef ENABLE_MC_DEBUG
	obj->file = file;
	obj->func = func;
	obj->line = line;
#endif
	DBGTRACE("%s(%d): cache:%p %s size:%lu %p\n",
		 __func__, __LINE__, cache, cache->name, size, obj->body);
	return obj->body;
}

#define	PTR2OBJ(p)	(struct mc_obj *)((char*)p - (offsetof(struct mc_obj, body)))

void
mc_free(void *ptr)
{
	struct mc_obj *obj = PTR2OBJ(ptr);

#ifdef ENABLE_MC_DEBUG
	obj->file = NULL;
	obj->func = NULL;
	obj->line = 0;
#endif
	DBGTRACE("%s(%d): ptr:%p obj:%p\n", __func__, __LINE__, ptr, obj);
	join_obj(obj);
}

static void
flush(struct mc_obj *obj)
{
	struct mc_chunk *prev, *chunk = obj->chunk;

	DBGTRACE("%s(%d): obj:%p\n", __func__, __LINE__, obj);

	while ((prev = TAILQ_PREV(chunk, mc_chunk_lst, node)) != NULL)
		release_chunk(prev);
	if (TAILQ_PREV(obj, mc_obj_lst, node) == NULL)
		release_chunk(chunk);
	else
		while ((obj = join_obj(obj)) != NULL)
			;
}

void
mc_flush(void *ptr)
{
	flush(PTR2OBJ(ptr));
}

void
mc_reset(struct mcache *cache)
{
	struct mc_obj *prev, *obj = PTR2OBJ(cache);

	DBGTRACE("%s(%d): %s:%p reset\n",
		 __func__, __LINE__, cache->name, cache);

	if ((prev = TAILQ_PREV(obj, mc_obj_lst, node)) != NULL)
		flush(prev);
	if (cache->reserve)
		release_reserved(cache);
}

static inline int
walk_chunk(struct mc_chunk *chunk,
	   int (*cb)(void *, const char *fmt, ...),
	   void *arg)
{
	int ret;
	struct mc_obj *obj;

	ret = (*cb)(arg, " chunk:%p size:%lu envelope:%p\n",
		    chunk, chunk->size, chunk->envelope);
	if (ret)
		return ret;

	TAILQ_FOREACH(obj, &chunk->objs, node) {
#ifdef ENABLE_MC_DEBUG
		ret = (*cb)(arg, "  obj:%p size:%lu body:%p %s:%lu:%s()\n",
			    obj, obj->size, obj->body,
			    obj->file, obj->line, obj->func);
#else
		ret = (*cb)(arg, "  obj:%p size:%lu body:%p\n",
			    obj, obj->size, obj->body);
#endif
		if (ret)
			break;
	}
	return ret;
}

int
mc_walk(struct mcache *cache,
	int (*cb)(void *, const char *fmt, ...),
	void *arg)
{
	int ret;
	struct mc_chunk *chunk;
	struct mcache *child;

	ret = (*cb)(arg, "cache:%p %s chunks:%lu warter mark:%lu reserve:%p\n",
		    cache, cache->name, cache->chunk_num, cache->wmark,
		    cache->reserve);
	if (ret)
		return ret;
	TAILQ_FOREACH(chunk, &cache->chunks, node) {
		ret = walk_chunk(chunk, cb, arg);
		if (ret)
			break;
	}
	TAILQ_FOREACH(child, &cache->childs, node) {
		 ret = (*cb)(arg, " childs:%p %s\n", child, child->name);
		 if (ret)
			 return ret;
	 }
	return ret;
}
