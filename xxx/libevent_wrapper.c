#include <sys/time.h>
#include <sys/types.h>
#include <sys/tree.h>

#include <assert.h>
#include <errno.h>
#include <event.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include "libevent_wrapper.h"

#if 1
#include <stdio.h>
#include <stdlib.h>

#define	MALLOC(_s)	malloc((_s))
#define	FREE(_p)	free((_p))

#endif


#define	UNUSED	__attribute__((unused))

#define	BASE_STATE_INITIALIZED	0
#define	BASE_STATE_RUNNING	1
#define	BASE_STATE_STOP		2

#define	CTX_STATE_INVALID	1
#define CTX_STATE_ADDED_DB	(1 << 1)
#define	CTX_STATE_ADDED_EV	(1 << 2)

#define	CTX_TYPE_TIMER		1
#define	CTX_TYPE_FD		2
#define	CTX_TYPE_SIGNAL		3

struct _ctx_t;

typedef struct _ev_base_t {
  int state;
  struct event_base *base;
  RB_HEAD(ctx_db, _ctx_t) head;
  external_callback_t ext_cb;
} ev_base_t;


typedef struct _ctx_t {
  RB_ENTRY( _ctx_t ) node;
  int refcnt;
  int state;

  short type;
  short flags;
  int fd;

  struct event *ev;
  ev_base_t *base;

  union {
    struct {
      event_fd_callback read_cb;
      void *read_data;

      event_fd_callback write_cb;
      void *write_data;
    } fd_val;

    struct {
      timer_callback timer_cb;
      void *timer_data;
      struct timeval tm;
    } timer_val;
  } u;

} ctx_t;


static pthread_key_t Key;	/* for thread safe */
static ev_base_t *Base;		/*for none thread safe */


/**************************************************************************
 * base functions
 **************************************************************************/
static ev_base_t *
create_ev_base(pthread_key_t *key)
{
  ev_base_t *ev_base;

  if ((ev_base = MALLOC(sizeof(*ev_base)))) {
    memset(ev_base, 0, sizeof(*ev_base));
    if (!(ev_base->base = event_base_new())) {
      FREE(ev_base);
      return NULL;
    }
    if (key) {
      if (pthread_setspecific(*key, ev_base)) {
        event_base_free(ev_base->base);
        FREE(ev_base);
        return NULL;
      }
    }
  }
  return ev_base;
}

static void
free_ev_base(ev_base_t *ev_base)
{
  /*
   * crean
   */
  FREE(ev_base);
}

static void
destroy_ev_base(ev_base_t *ev_base)
{
  pthread_setspecific(Key, NULL);
  free_ev_base(ev_base);
}

static void
base_destructor(void *arg)
{
  ev_base_t *ev_base = arg;

  if (ev_base)
    free_ev_base(ev_base);
}

#define	SAFE	true
#define UNSAFE	false

static inline ev_base_t *
get_ev_base(bool safe)
{
  ev_base_t *base = NULL;

  if (safe)
    base = pthread_getspecific(Key);
  else
    base = Base;

  assert(base);
  return base;
}

/**************************************************************************
 * ctx functions
 **************************************************************************/
static void handler_core(int fd, short flags, void *arg);

static inline int
cmp_ctx(const ctx_t *c0, const ctx_t *c1) {
  int ret;

  ret = c0->type - c0->type;
  if (ret)
    return ret;
  if (c0->type == CTX_TYPE_FD)
    ret = c0->fd - c1->fd;
  else if (c0->type == CTX_TYPE_TIMER) {
    ;
  } else {
    ;
  }
  return ret;
}

RB_GENERATE_STATIC(ctx_db, _ctx_t, node, cmp_ctx);


static inline ctx_t *
create_ctx(ev_base_t *ev_base, short type)
{
  ctx_t *ctx;

  if ((ctx = MALLOC(sizeof(*ctx)))) {
    memset(ctx, 0, sizeof(*ctx));
    if ((ctx->ev = event_new(ev_base->base, -1, 0, handler_core, ctx)) == NULL) {
      FREE(ctx);
      return NULL;
    }
    ctx->type = type;
    ctx->base = ev_base;
    ctx->refcnt = 1;
    ctx->fd = -1;
  }
  return ctx;
}

static inline void
attach_ctx(ctx_t *ctx)
{
  ctx->refcnt++;
}

static inline void
detach_ctx(ctx_t *ctx)
{
  ctx->refcnt--;
  if (!ctx->refcnt) {
    assert((ctx->state & ~CTX_STATE_INVALID) == 0);
    assert(ctx->fd < 0);

    if (ctx->ev)
      event_free(ctx->ev);
  }
}

static inline ctx_t *
find_ctx_fd(ev_base_t *ev_base, int fd)
{
  ctx_t key;

  key.type = CTX_TYPE_FD;
  key.fd = fd;
  return RB_FIND(ctx_db, &ev_base->head, &key);
}

static inline void
add_db_ctx(ev_base_t *ev_base, ctx_t *ctx)
{
  ctx_t *old;

  assert(!(ctx->state & CTX_STATE_ADDED_DB));
  old = RB_INSERT(ctx_db, &ev_base->head, ctx);
  assert(!old);
  attach_ctx(ctx);
  ctx->state |= CTX_STATE_ADDED_DB;
}

static inline void
del_db_ctx(ev_base_t *ev_base, ctx_t *ctx)
{
  if (ctx->state & CTX_STATE_ADDED_DB) {
    ctx->state &= ~CTX_STATE_ADDED_DB;
    RB_REMOVE(ctx_db, &ev_base->head, ctx);
    detach_ctx(ctx);
  }
}

static inline void
del_ev_ctx(ctx_t *ctx)
{
  if (ctx->state & CTX_STATE_ADDED_EV) {
    ctx->state &= ~CTX_STATE_ADDED_EV;
    event_del(ctx->ev);
    ctx->flags = 0;
    ctx->u.fd_val.read_cb = NULL;
    ctx->u.fd_val.write_cb = NULL;
    detach_ctx(ctx);
  }
}

static void
handler_core(int fd, short flags, void *arg)
{
  ctx_t *ctx = arg;

  assert(ctx && ctx->fd == fd);
  attach_ctx(ctx);
  if (!(flags & EV_PERSIST)) {
    ctx->state &= ~CTX_STATE_ADDED_EV;
    detach_ctx(ctx);
  }

  ctx->flags &= (short) ~(flags & (EV_READ | EV_WRITE));

  if (flags & EV_READ) {
    ctx->u.fd_val.read_cb(fd, ctx->u.fd_val.read_data);
  }
  if (flags & EV_WRITE) {
    ctx->u.fd_val.write_cb(fd, ctx->u.fd_val.write_data);
  }
  if (flags & EV_TIMEOUT) {
    ;
  }
  if (flags & EV_SIGNAL) {
    ;
  }

  /* reset event */

  detach_ctx(ctx);
}


/***************************************************************************
 * wrapping functions
 ***************************************************************************/
static void
init_event_handler_r(void) {
  ev_base_t *ev_base;

  ev_base = create_ev_base(&Key);
  assert(ev_base);
}

static void
init_event_handler_x(void) {
  ev_base_t *ev_base;

  ev_base = create_ev_base(NULL);
  assert(ev_base);
}

/***************************************************************************
 *
 ***************************************************************************/
static void
finalize_event_handler_r(void) {
  ev_base_t *ev_base = get_ev_base(SAFE);
  destroy_ev_base(ev_base);
}

static void
finalize_event_handler_x(void) {
  free_ev_base(Base);
  Base = NULL;
}

/***************************************************************************
 *
 ***************************************************************************/
static bool
run_event_handler_once_raw(ev_base_t *ev_base, int timeout_usec UNUSED) {

  if (ev_base->ext_cb) {
    external_callback_t cb = ev_base->ext_cb;

    ev_base->ext_cb = NULL;
    cb();
  }

  /* block */
  if (event_base_loop(ev_base->base, EVLOOP_ONCE) < 0)
    return false;
  return true;
}

#if 0
static bool
run_event_handler_once_r( int timeout_usec ) {
  return run_event_handler_once_raw(get_ev_base(SAFE), timeout_usec);
}
#endif

static bool
run_event_handler_once_x( int timeout_usec ) {
  return run_event_handler_once_raw(get_ev_base(UNSAFE), timeout_usec);
}

/***************************************************************************
 *
 ***************************************************************************/
static bool
start_event_handler_raw(ev_base_t *ev_base) {
  ev_base->state = BASE_STATE_RUNNING;
  while (ev_base->state == BASE_STATE_RUNNING) {
    if (!run_event_handler_once_raw(ev_base, 0))
      break;
  }
  return true;
}

static bool
start_event_handler_r(void) {
  return start_event_handler_raw(get_ev_base(SAFE));
}

static bool
start_event_handler_x(void) {
  return start_event_handler_raw(get_ev_base(UNSAFE));
}

/***************************************************************************
 *
 ***************************************************************************/
static void
stop_event_handler_raw(ev_base_t *ev_base) {
  ev_base->state = BASE_STATE_STOP;
}

static void
stop_event_handler_r(void) {
  stop_event_handler_raw(get_ev_base(SAFE));
}

static void
stop_event_handler_x(void) {
  stop_event_handler_raw(get_ev_base(UNSAFE));
}

/***************************************************************************
 *
 ***************************************************************************/
static bool
set_fd_handler_raw(ev_base_t *ev_base,
                   int fd,
                   event_fd_callback read_cb, void *read_d,
                   event_fd_callback write_cb, void *write_d) {
  ctx_t *ctx;
  assert(fd >= 0);

  if ((ctx = create_ctx(ev_base, CTX_TYPE_FD))) {
    ctx->fd = fd;
    ctx->u.fd_val.read_cb = read_cb;
    ctx->u.fd_val.read_data = read_d;
    ctx->u.fd_val.write_cb = write_cb;
    ctx->u.fd_val.write_data = write_d;
    add_db_ctx(ev_base, ctx);

    detach_ctx(ctx);
    return true;
  }
  return false;
}

static void
set_fd_handler_r(int fd,
                 event_fd_callback read_cb, void *read_d,
                 event_fd_callback write_cb, void *write_d) {
  set_fd_handler_raw(get_ev_base(SAFE), fd, read_cb, read_d, write_cb, write_d);
}

static void
set_fd_handler_x(int fd,
                 event_fd_callback read_cb, void *read_d,
                 event_fd_callback write_cb, void *write_d) {
  set_fd_handler_raw(get_ev_base(UNSAFE), fd, read_cb, read_d, write_cb, write_d);
}

/***************************************************************************
 *
 ***************************************************************************/
static bool
delete_fd_handler_raw(ev_base_t *ev_base, int fd) {
  ctx_t *ctx;

  if ((ctx = find_ctx_fd(ev_base, fd))) {
    attach_ctx(ctx);
    {
      del_ev_ctx(ctx);
      del_db_ctx(ev_base, ctx);
      ctx->state |= CTX_STATE_INVALID;
    }
    detach_ctx(ctx);
    return true;
  }
  return false;
}

static void
delete_fd_handler_r(int fd) {
  delete_fd_handler_raw(get_ev_base(SAFE), fd);
}

static void
delete_fd_handler_x(int fd) {
  delete_fd_handler_raw(Base, fd);
}

/***************************************************************************
 *
 ***************************************************************************/
static bool
set_readable_raw(ev_base_t *ev_base, int fd, bool set) {
  ctx_t *ctx;

  if ((ctx = find_ctx_fd(ev_base, fd))) {
    if (set)
      ctx->flags |= EV_READ;
    else
      ctx->flags &= ~EV_READ;
    return true;
  }
  return false;
}

static void
set_readable_r(int fd, bool state) {
  set_readable_raw(get_ev_base(SAFE), fd, state);
}

static void
set_readable_x(int fd, bool state) {
  set_readable_raw(Base, fd, state);
}

/***************************************************************************
 *
 ***************************************************************************/
static bool
set_writable_raw(ev_base_t *ev_base, int fd, bool set) {
  ctx_t *ctx;

  if ((ctx = find_ctx_fd(ev_base, fd))) {
    if (set)
      ctx->flags |= EV_WRITE;
    else
      ctx->flags &= ~EV_WRITE;
    return true;
  }
  return false;
}

static void
set_writable_r(int fd, bool state) {
  set_writable_raw(get_ev_base(SAFE), fd, state);
}

static void
set_writable_x(int fd, bool state) {
  set_writable_raw(Base, fd, state);
}

/***************************************************************************
 *
 ***************************************************************************/
static bool
readable_raw(ev_base_t *ev_base, int fd) {
  ctx_t *ctx;

  if ((ctx = find_ctx_fd(ev_base, fd))) {
    if (!(ctx->flags & EV_READ))
      return true;
  }
  return false;
}

static bool
readable_r(int fd) {
  return readable_raw(get_ev_base(SAFE), fd);
}

static bool
readable_x(int fd) {
  return readable_raw(Base, fd);
}

/***************************************************************************
 *
 ***************************************************************************/
static bool
writable_raw(ev_base_t *ev_base, int fd) {
  ctx_t *ctx;

  if ((ctx = find_ctx_fd(ev_base, fd))) {
    if (!(ctx->flags & EV_WRITE))
      return true;
  }
  return false;
}

static bool
writable_r(int fd) {
  return writable_raw(get_ev_base(SAFE), fd);
}

static bool
writable_x(int fd) {
  return writable_raw(Base, fd);
}

/***************************************************************************
 *
 ***************************************************************************/
static bool
set_external_callback_raw(ev_base_t *ev_base, external_callback_t cb) {
  if (ev_base->ext_cb)
    return false;
  ev_base->ext_cb = cb;
  return true;
}

static bool
set_external_callback_r(external_callback_t cb) {
  return set_external_callback_raw(get_ev_base(SAFE), cb);
}

static bool
set_external_callback_x(external_callback_t cb) {
  return set_external_callback_raw(Base, cb);
}

/***************************************************************************
 *
 ***************************************************************************/
static void
init_event_wrapper(void) {
  init_event_handler     = init_event_handler_x;
  finalize_event_handler = finalize_event_handler_x;
  start_event_handler    = start_event_handler_x;
  stop_event_handler     = stop_event_handler_x;
  run_event_handler_once = run_event_handler_once_x;
  set_fd_handler         = set_fd_handler_x;
  delete_fd_handler      = delete_fd_handler_x;
  set_readable           = set_readable_x;
  set_writable           = set_writable_x;
  readable               = readable_x;
  writable               = writable_x;
  set_external_callback  = set_external_callback_x;

  init_event_handler_safe     = init_event_handler_r;
  finalize_event_handler_safe = finalize_event_handler_r;
  start_event_handler_safe    = start_event_handler_r;
  stop_event_handler_safe     = stop_event_handler_r;
  //  run_event_handler_once_safe = run_event_handler_once_r;
  set_fd_handler_safe         = set_fd_handler_r;
  delete_fd_handler_safe      = delete_fd_handler_r;
  set_readable_safe           = set_readable_r;
  set_writable_safe           = set_writable_r;
  readable_safe               = readable_r;
  writable_safe               = writable_r;
  set_external_callback_safe  = set_external_callback_r;
}

/*
 * XXX: timer code. not yet.
 */


/**************************************************************************
 * wrapper initializer
 **************************************************************************/
bool
init_libevent_wrapper(void)
{
  if (pthread_key_create(&Key, base_destructor))
    return false;

  init_event_wrapper();
  return true;
}

bool
finalize_libevent_wrapper(void)
{
  if (pthread_key_delete(Key))
    return false;
  return true;
}


