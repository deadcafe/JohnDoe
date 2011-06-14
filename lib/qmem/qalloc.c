/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "qalloc.h"

#define QMEM_CHUNK_SIZE (4*1024)
#define QMEM_DEBUG
#define QMEM_MALLOC_FALLBACK
#define QMEM_POISON

#ifdef QMEM_DEBUG
# include <stdio.h>
# define qmem_debug(fmt, args...) fprintf(stderr, fmt, ## args)
#else
# define qmem_debug(fmt, args...)
#endif

#define	QMEM_MARK	0xcfcfcfcfcfcfcfcf
#define QMEM_ZERO_MEM	0x1


struct qmem_guard {
	size_t mark[2];
};

struct qmem_object;

struct qmem_chunk
{
	size_t mark0;
	struct qmem_object *last_obj;
	caddr_t next_free;
	caddr_t limit;
	size_t count;
	size_t *tail_mark;
	size_t mark1;

	char content[0];
};

struct qmem_object {
	size_t mark0;

# define QMEM_MALLOC	 1234
# define QMEM_CHUNK	 5678
	size_t alloc_type;
	struct qmem_chunk *chunk;
	struct qmem_object *prev;
	size_t size;

	const char *file;
	const char *func;
	size_t line;
	size_t mark1;
	size_t *tail_mark;

	char data[];
};


#define qmem_to_object(d) (void*)((char*)d - (offsetof(struct qmem_object, data)))

static inline void
qprint_chunk(const struct qmem_chunk *chunk)
{
	qmem_debug("%s: address=%p\n", __func__, chunk);
	qmem_debug("\tlimit=%p\n", chunk->limit);
	qmem_debug("\tcount=%lu\n", chunk->count);
}

static inline void
qprint_object(const struct qmem_object *object)
{
	qmem_debug("%s: address=%p\n", __func__, object);
	qmem_debug("\tchunk=%p\n", object->chunk);
	qmem_debug("\tsize=%lu\n", object->size);
	qmem_debug("\talloc_type=%lu\n", object->alloc_type);
	qmem_debug("\tdata start=%p\n", object->data);
}

static inline void
qprint_mem(const struct qmem *qmem)
{
	qmem_debug("%s: address=%p\n", __func__, qmem);
	qmem_debug("\tcurrent=%p\n", qmem->current);
	qmem_debug("\tsaved=%p\n", qmem->saved);
	qmem_debug("\tchk_count=%lu\n", qmem->chk_count);
	qmem_debug("\tchk_alloc_error=%lu\n", qmem->chk_alloc_error);
	qmem_debug("\tchk_total_count=%lu\n", qmem->chk_total_count);
	qmem_debug("\tobj_count=%lu\n", qmem->obj_count);
	qmem_debug("\tobj_malloc_count=%lu\n", qmem->obj_malloc_count);
	qmem_debug("\tobj_total_count=%lu\n", qmem->obj_total_count);
	qmem_debug("\tobj_ignored_free=%lu\n", qmem->obj_ignored_free);
}

static inline int
verify_chunk(struct qmem_chunk *chunk)
{
	if (chunk->mark0 != QMEM_MARK ||
	    chunk->mark1 != QMEM_MARK ||
	    *chunk->tail_mark != QMEM_MARK) {
		qmem_debug("chunk is bad\n");
		abort();
	}
	return 0;
}

static inline struct qmem_chunk *
create_chunk(size_t size)
{
	struct qmem_chunk *chunk = mmap(0, size,
					PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS,
					-1, 0);

	if (chunk == MAP_FAILED) {
		qmem_debug("could not alloc chunk: %d\n", errno);
		return NULL;
	}

	chunk->next_free = chunk->content;
	chunk->limit = ((caddr_t) chunk) + (size - sizeof(size_t));
	chunk->tail_mark = (size_t *)(chunk->limit);
	chunk->last_obj = NULL;
	chunk->count = 0;
	chunk->mark0 = QMEM_MARK;
	chunk->mark1 = QMEM_MARK;
	*(chunk->tail_mark) = QMEM_MARK;

	return chunk;
}

static inline int
add_chunk(struct qmem *qmem)
{
	if (qmem->saved) {
		qmem->current = qmem->saved;
		qmem->saved = NULL;
	} else {
		if ((qmem->current = create_chunk(qmem->chk_size))
		    == NULL) {
			qmem->chk_alloc_error++;
			return -1;
		}
		qmem->chk_count++;
		qmem->chk_total_count++;
	}
	qprint_chunk(qmem->current);
	return 0;
}

static inline void
free_chunk(struct qmem *qmem,
	   struct qmem_chunk *chunk)
{
	qmem_debug("removing chunk %p\n", chunk);
	qprint_chunk(chunk);

	if (munmap(chunk, (chunk->limit - (caddr_t)chunk)))
		qmem_debug("failed munmap:%p %d\n", chunk, errno);
	qmem->chk_count--;
}

static inline void
set_size(struct qmem *qmem,
	 size_t chunk_size)
{
	if (chunk_size)
		qmem->chk_size = chunk_size;
	else
		qmem->chk_size = QMEM_CHUNK_SIZE;

	if (qmem->saved) {
		free_chunk(qmem, qmem->saved);
		qmem->saved = NULL;
	}
}

static inline void *
init_obj(const char *file,
	 int line,
	 const char *func,
	 struct qmem *qmem,
	 struct qmem_chunk *chunk,
	 size_t size,
	 size_t type,
	 struct qmem_object *obj,
	 int flags)
{
	if (obj) {
		struct qmem_object *prev = NULL;

		if ((obj->chunk = chunk) == NULL) {
			qmem->obj_malloc_count++;
		} else {
			chunk->count++;
			chunk->next_free += sizeof(obj) +sizeof(size_t) + size;
			prev = chunk->last_obj;
			chunk->last_obj = obj;
			qmem->obj_count++;
			qmem->obj_total_count++;
		}
		obj->file = file;
		obj->line = line;
		obj->func = func;
		obj->prev = prev;
		obj->size = size;
		obj->alloc_type = type;
		obj->tail_mark = (size_t *)(&obj->data[size]);
		obj->mark0 = QMEM_MARK;
		obj->mark1 = QMEM_MARK;
		*(obj->tail_mark) = QMEM_MARK;

		if (flags & QMEM_ZERO_MEM)
			memset(obj->data, 0, size);

		qmem_debug("add new object:%p data:%p\n", obj, obj->data);
		return obj->data;
	}
	return NULL;
}

static inline struct qmem_object *
verify_obj(struct qmem_object *start)
{
	struct qmem_object *obj;

	for (obj = start; obj; obj = obj->prev) {
		if (obj->mark0 != QMEM_MARK ||
		    obj->mark1 != QMEM_MARK ||
		    *(obj->tail_mark) != QMEM_MARK)
			return obj;
	}
	return NULL;
}

/*
 *
 */
void
qmem_init(struct qmem *qmem,
	size_t chunk_size)
{
	qmem_debug("init a new queue_allocator %p with chunk_size %lu\n",
		 qmem,
		 chunk_size ? chunk_size : QMEM_CHUNK_SIZE);

	memset(qmem, 0, sizeof(*qmem));
	set_size(qmem, chunk_size);
	add_chunk(qmem);
}

void *
qmem_alloc(const char *file,
	   int line,
	   const char *func,
	   struct qmem *qmem,
	   size_t size,
	   unsigned int flags)
{
	struct qmem_object *obj;
	struct qmem_chunk *chunk;

	size += 15;
	size &= ~(0x0f);
	qmem_debug("add new object size %lu\n", size);

	if ((size + sizeof(*obj) + sizeof(size_t))
	    > (qmem->chk_size - sizeof(*chunk) - sizeof(size_t))) {
		obj = malloc(sizeof(*obj) +sizeof(size_t) + size);
		return init_obj(file, line, func,
				   qmem, NULL, size, QMEM_MALLOC,
				   obj, flags);
	}

	chunk = qmem->current;
	if (chunk == NULL ||
	    (size + sizeof(*obj) + sizeof(size_t)) >
	    (size_t)(chunk->limit - chunk->next_free)) {
		qmem_debug("chunk is full with %lu objects\n", chunk->count);
		qprint_mem(qmem);
		add_chunk(qmem);
		chunk = qmem->current;
	}

	return init_obj(file, line, func,
			   qmem, chunk, size, QMEM_CHUNK,
			   (struct qmem_object *) chunk->next_free, flags);
}

void
qmem_free(struct qmem *qmem,
	  void *ptr)
{
	struct qmem_object *obj = qmem_to_object(ptr);
	struct qmem_object *ng;

	qmem_debug("object deletion at %p\n", obj);

	if ((ng = verify_obj(obj)) != NULL) {
		qmem_debug("alart: obj: %p is bad(%s:%lu:%s)\n",
			 ng, ng->file, ng->line, ng->func);
		abort();
	}

	if (obj->alloc_type == QMEM_MALLOC) {
		qmem_debug("object %p was malloced, free it\n", obj);
		qmem->obj_malloc_count--;
		free(obj);
	} else if (obj->alloc_type == QMEM_CHUNK) {
		struct qmem_chunk *chunk = obj->chunk;

		verify_chunk(chunk);

		chunk->count--;
		qmem->obj_count--;

		memset(obj, 0xcf, sizeof(*obj) + obj->size + sizeof(size_t));

		if (!chunk->count) {
			qmem_debug("chunk %p count is 0\n", obj);

			if (qmem->current == chunk)
				qmem->current = NULL;
			free_chunk(qmem, chunk);
			add_chunk(qmem);
		}
	}
	else {
		qmem->obj_ignored_free++;
	}
}
