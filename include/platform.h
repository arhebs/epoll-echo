/*
 * platform.h
 * Purpose: Centralizes feature-test macros, ubiquitous system headers, and
 * compiler attributes required by the epoll-echo daemon. This file should be
 * included before any other project header to guarantee the same GNU/Linux
 * compilation environment across all modules.
 */

#ifndef EPOLL_ECHO_PLATFORM_H
#define EPOLL_ECHO_PLATFORM_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#if !defined(__linux__)
#error "epoll-echo targets GNU/Linux only"
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdnoreturn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define EPOLL_ECHO_ATTR_PRINTF(fmt_idx, arg_idx) __attribute__((format(printf, fmt_idx, arg_idx)))
#define EPOLL_ECHO_ATTR_NORETURN __attribute__((noreturn))
#define EPOLL_ECHO_ATTR_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#define EPOLL_ECHO_ATTR_UNUSED __attribute__((unused))
#define EPOLL_ECHO_ATTR_COLD __attribute__((cold))
#define EPOLL_ECHO_ATTR_HOT __attribute__((hot))
#define EPOLL_ECHO_ATTR_NODISCARD __attribute__((warn_unused_result))
#define EPOLL_ECHO_ATTR_PURE __attribute__((pure))

#define EPOLL_ECHO_FALLTHROUGH __attribute__((fallthrough))
#define EPOLL_ECHO_LIKELY(expr) __builtin_expect(!!(expr), 1)
#define EPOLL_ECHO_UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#define EPOLL_ECHO_ASSUME(expr) ((expr) ? (void)0 : __builtin_unreachable())
#define EPOLL_ECHO_UNREACHABLE() __builtin_unreachable()

#define EPOLL_ECHO_STRINGIFY_IMPL(x) #x
#define EPOLL_ECHO_STRINGIFY(x) EPOLL_ECHO_STRINGIFY_IMPL(x)
#define EPOLL_ECHO_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

#endif /* EPOLL_ECHO_PLATFORM_H */
