/*
 * loop.h
 * Purpose: Declares the epoll event-loop control surface, including the
 * callback signature and descriptor registration helpers used by TCP, UDP,
 * and upcoming signal/timer integrations.
 */

#ifndef EPOLL_ECHO_LOOP_H
#define EPOLL_ECHO_LOOP_H

#include "platform.h"

#ifdef __cplusplus
extern "C" {
#endif

struct loop_context;

/*
 * loop_event_cb
 * ctx: Loop instance that dispatched the event.
 * fd: File descriptor whose readiness triggered the callback.
 * events: Bitmask from epoll_wait (EPOLLIN/OUT/RDHUP/ERR/HUP/...)
 * userdata: Opaque pointer set during loop_add; typically points to module
 *           state such as a listener or per-connection struct.
 * Notes: Callbacks run on the single event-loop thread and may invoke
 *        loop_add/mod/del on other descriptors. They must avoid blocking I/O.
 */
typedef void (*loop_event_cb)(struct loop_context *ctx,
                              int fd,
                              uint32_t events,
                              void *userdata);

#define LOOP_EVENT_DEFAULT                                                     \
    (EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP)

/*
 * loop_on_tick_cb
 * ctx: Loop instance delivering the timer tick.
 * now_epoch_sec: Wall-clock seconds since the Unix epoch captured via
 *                CLOCK_REALTIME when the tick fired.
 * userdata: Opaque pointer supplied when registering the hook.
 * Notes: Used by higher-level modules (stats, UDP) to perform recurring work
 *        such as expiring peers or reporting metrics.
 */
typedef void (*loop_on_tick_cb)(struct loop_context *ctx,
                                uint64_t now_epoch_sec,
                                void *userdata);

/*
 * loop_init
 * ctx_out: Output pointer that receives a fully initialized loop_context.
 * Returns: 0 on success, -1 with errno set on failure.
 * Notes: Creates the epoll instance and internal bookkeeping arrays. The
 *        caller owns the context and must release it via loop_free().
 */
int loop_init(struct loop_context **ctx_out);

/*
 * loop_add
 * fd: Descriptor to monitor (must already be non-blocking).
 * events: Epoll mask to register (typically LOOP_EVENT_DEFAULT initially).
 * cb/userdata: Callback invoked for every readiness notification.
 * Returns: 0 on success, -1 with errno preserved.
 * Notes: Fails if the fd is already registered. Callbacks execute in the
 *        order reported by epoll_wait().
 */
int loop_add(struct loop_context *ctx,
             int fd,
             uint32_t events,
             loop_event_cb cb,
             void *userdata);

/*
 * loop_mod
 * fd: Descriptor previously registered via loop_add.
 * events: Replacement epoll mask. Use to toggle EPOLLOUT when a write queue
 *         transitions between empty and non-empty states.
 * Returns: 0 on success, -1 with errno preserved.
 */
int loop_mod(struct loop_context *ctx, int fd, uint32_t events);

/*
 * loop_del
 * fd: Descriptor to remove from the epoll set.
 * Effect: Issues EPOLL_CTL_DEL and tears down associated callback storage.
 * Returns: 0 on success or -1 if the descriptor was not registered.
 */
int loop_del(struct loop_context *ctx, int fd);

/*
 * loop_run
 * ctx: Event loop created by loop_init().
 * Effect: Blocks in epoll_wait() and dispatches callbacks until
 *         loop_shutdown() is invoked or a fatal epoll error occurs.
 */
void loop_run(struct loop_context *ctx);

/*
 * loop_shutdown
 * ctx: Event loop context.
 * Effect: Signals loop_run() to exit after in-flight callbacks complete and
 *         wakes the epoll wait so shutdown observes the request immediately.
 *         Safe to call from inside a callback.
 */
void loop_shutdown(struct loop_context *ctx);

/*
 * loop_request_shutdown
 * ctx: Event loop context.
 * Effect: Marks shutdown_requested=true and delegates to loop_shutdown() so
 *         the epoll wait exits. Use when an orderly shutdown (signals,
 *         /shutdown command) is desired and callers want to record intent.
 */
void loop_request_shutdown(struct loop_context *ctx);

/*
 * loop_shutdown_requested
 * ctx: Event loop context (may be NULL).
 * Returns: true if a graceful shutdown has been requested via signal or
 *          loop_request_shutdown(); false otherwise. Helpful for main()
 *          logic that needs to distinguish between fatal errors and a
 *          normal termination path.
 */
bool loop_shutdown_requested(const struct loop_context *ctx);

/*
 * loop_set_tick_hook
 * ctx: Event loop context that owns the timerfd.
 * hook: Callback invoked once per 1-second timer tick; pass NULL to disable.
 * userdata: Opaque pointer replayed to the hook for module-specific state.
 * Effect: Registers (or clears) the handler that receives timer ticks.
 *         The hook executes on the loop thread, so it must avoid blocking.
 */
void loop_set_tick_hook(struct loop_context *ctx,
                        loop_on_tick_cb hook,
                        void *userdata);

/*
 * loop_free
 * ctx: Event loop context (may be NULL).
 * Effect: Unregisters all remaining descriptors, closes the epoll fd, and
 *         releases memory allocated by loop_init().
 */
void loop_free(struct loop_context *ctx);

#ifdef __cplusplus
}
#endif

#endif /* EPOLL_ECHO_LOOP_H */
