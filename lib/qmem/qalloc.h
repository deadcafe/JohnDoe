/*
 * Copyright (C) 2011, deadcafe.beef@gmail.com
 * All rights reserved.
 */

#ifndef _JD_QMEM_H_
#define _JD_QMEM_H_

#include <sys/types.h>

struct qmem_chunk;

struct qmem {
	struct qmem_chunk *current;
	struct qmem_chunk *saved;

	size_t chk_size;
	size_t chk_count;
	size_t chk_alloc_error;
	size_t chk_total_count;
	size_t obj_count;
	size_t obj_total_count;
	size_t obj_malloc_count;
	size_t obj_ignored_free;
};

extern void qmem_init(struct qmem *qa_mem, size_t chunk_size);
extern void *qmem_alloc(const char *file,
			int line,
			const char *func,
			struct qmem *qmem,
			size_t size,
			unsigned int flags);
extern void qmem_free(struct qmem *qmem,
		      void *ptr);

#define	QMALLOC(q,s)	qmem_alloc(__FILE__,__LINE__,__FUNC__,(q),(s))
#define	QMFREE(q,p)	qmem_free((q),(p))

#endif /* _JD_QMEM_H_ */
