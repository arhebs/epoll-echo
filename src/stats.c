/*
 * stats.c
 * Purpose: Implements the core counters for epoll-echo plus the UDP peer
 * tracking window. The window keeps `(ip,port)` fingerprints for 60 seconds,
 * records lifetime sightings for total client counts, and exposes helpers to
 * age peers out during timer ticks.
 */

#include "stats.h"

#include "common.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define STATS_UDP_ACTIVE_INITIAL_BUCKETS 64U
#define STATS_UDP_SEEN_INITIAL_BUCKETS 128U
#define STATS_UDP_LOAD_FACTOR_NUM 3U
#define STATS_UDP_LOAD_FACTOR_DEN 4U

struct stats_udp_peer_key {
    sa_family_t family;
    uint16_t port;
    uint32_t scope_id;
    uint8_t addr[16];
};

struct stats_udp_peer_entry {
    struct stats_udp_peer_key key;
    uint64_t last_seen;
    struct stats_udp_peer_entry *next;
};

struct stats_udp_seen_entry {
    struct stats_udp_peer_key key;
    struct stats_udp_seen_entry *next;
};

struct stats_udp_window {
    struct stats_udp_peer_entry **active_buckets;
    size_t active_bucket_count;
    size_t active_bucket_mask;
    size_t active_size;

    struct stats_udp_seen_entry **seen_buckets;
    size_t seen_bucket_count;
    size_t seen_bucket_mask;
    size_t seen_size;
};

static void stats_set_udp_active(struct ep_stats *stats, size_t active)
{
    if (!stats) {
        return;
    }

    if (active > UINT32_MAX) {
        stats->udp_active_60s = UINT32_MAX;
        return;
    }

    stats->udp_active_60s = (uint32_t)active;
}

static uint64_t stats_udp_hash_bytes(const void *data, size_t len)
{
    const unsigned char *cursor = data;
    uint64_t hash = 1469598103934665603ULL; /* FNV-1a offset basis */

    for (size_t i = 0; i < len; ++i) {
        hash ^= cursor[i];
        hash *= 1099511628211ULL; /* FNV prime */
    }

    return hash;
}

static uint64_t stats_udp_hash_key(const struct stats_udp_peer_key *key)
{
    if (!key) {
        return 0;
    }

    return stats_udp_hash_bytes(key, sizeof(*key));
}

static bool stats_udp_keys_equal(const struct stats_udp_peer_key *lhs,
                                 const struct stats_udp_peer_key *rhs)
{
    if (!lhs || !rhs) {
        return false;
    }

    if (lhs->family != rhs->family || lhs->port != rhs->port ||
        lhs->scope_id != rhs->scope_id) {
        return false;
    }

    return memcmp(lhs->addr, rhs->addr, sizeof(lhs->addr)) == 0;
}

static int stats_udp_key_from_sockaddr(struct stats_udp_peer_key *key,
                                       const struct sockaddr_storage *addr,
                                       socklen_t addr_len)
{
    if (!key || !addr) {
        errno = EINVAL;
        return -1;
    }

    memset(key, 0, sizeof(*key));

    if (addr->ss_family == AF_INET) {
        if (addr_len < (socklen_t)sizeof(struct sockaddr_in)) {
            errno = EINVAL;
            return -1;
        }

        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        key->family = AF_INET;
        key->port = in->sin_port;
        memcpy(key->addr, &in->sin_addr, sizeof(in->sin_addr));
        return 0;
    }

    if (addr->ss_family == AF_INET6) {
        if (addr_len < (socklen_t)sizeof(struct sockaddr_in6)) {
            errno = EINVAL;
            return -1;
        }

        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        key->family = AF_INET6;
        key->port = in6->sin6_port;
        key->scope_id = in6->sin6_scope_id;
        memcpy(key->addr, &in6->sin6_addr, sizeof(in6->sin6_addr));
        return 0;
    }

    errno = EAFNOSUPPORT;
    return -1;
}

static bool stats_udp_need_resize(size_t size, size_t bucket_count)
{
    if (bucket_count == 0) {
        return false;
    }

    size_t threshold =
        (bucket_count * STATS_UDP_LOAD_FACTOR_NUM) / STATS_UDP_LOAD_FACTOR_DEN;
    return size >= threshold;
}

static int stats_udp_window_resize_active(struct stats_udp_window *window,
                                          size_t new_count)
{
    if (!window || new_count == 0 ||
        (new_count & (new_count - 1)) != 0) { /* must be power-of-two */
        errno = EINVAL;
        return -1;
    }

    struct stats_udp_peer_entry **new_buckets =
        calloc(new_count, sizeof(*new_buckets));
    if (!new_buckets) {
        return -1;
    }

    size_t new_mask = new_count - 1;

    if (window->active_buckets) {
        for (size_t i = 0; i < window->active_bucket_count; ++i) {
            struct stats_udp_peer_entry *entry = window->active_buckets[i];
            while (entry) {
                struct stats_udp_peer_entry *next = entry->next;
                size_t idx = stats_udp_hash_key(&entry->key) & new_mask;
                entry->next = new_buckets[idx];
                new_buckets[idx] = entry;
                entry = next;
            }
        }
        free(window->active_buckets);
    }

    window->active_buckets = new_buckets;
    window->active_bucket_count = new_count;
    window->active_bucket_mask = new_mask;
    return 0;
}

static int stats_udp_window_resize_seen(struct stats_udp_window *window,
                                        size_t new_count)
{
    if (!window || new_count == 0 ||
        (new_count & (new_count - 1)) != 0) {
        errno = EINVAL;
        return -1;
    }

    struct stats_udp_seen_entry **new_buckets =
        calloc(new_count, sizeof(*new_buckets));
    if (!new_buckets) {
        return -1;
    }

    size_t new_mask = new_count - 1;

    if (window->seen_buckets) {
        for (size_t i = 0; i < window->seen_bucket_count; ++i) {
            struct stats_udp_seen_entry *entry = window->seen_buckets[i];
            while (entry) {
                struct stats_udp_seen_entry *next = entry->next;
                size_t idx = stats_udp_hash_key(&entry->key) & new_mask;
                entry->next = new_buckets[idx];
                new_buckets[idx] = entry;
                entry = next;
            }
        }
        free(window->seen_buckets);
    }

    window->seen_buckets = new_buckets;
    window->seen_bucket_count = new_count;
    window->seen_bucket_mask = new_mask;
    return 0;
}

static int stats_udp_window_reserve_active(struct stats_udp_window *window)
{
    if (!window) {
        errno = EINVAL;
        return -1;
    }

    size_t next_size = window->active_size + 1;
    if (!stats_udp_need_resize(next_size, window->active_bucket_count)) {
        return 0;
    }

    if (window->active_bucket_count > (SIZE_MAX >> 1)) {
        errno = ENOMEM;
        return -1;
    }

    return stats_udp_window_resize_active(window,
                                          window->active_bucket_count << 1);
}

static int stats_udp_window_reserve_seen(struct stats_udp_window *window)
{
    if (!window) {
        errno = EINVAL;
        return -1;
    }

    size_t next_size = window->seen_size + 1;
    if (!stats_udp_need_resize(next_size, window->seen_bucket_count)) {
        return 0;
    }

    if (window->seen_bucket_count > (SIZE_MAX >> 1)) {
        errno = ENOMEM;
        return -1;
    }

    return stats_udp_window_resize_seen(window,
                                        window->seen_bucket_count << 1);
}

static void stats_udp_window_free_active(struct stats_udp_window *window)
{
    if (!window || !window->active_buckets) {
        return;
    }

    for (size_t i = 0; i < window->active_bucket_count; ++i) {
        struct stats_udp_peer_entry *entry = window->active_buckets[i];
        while (entry) {
            struct stats_udp_peer_entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(window->active_buckets);
    window->active_buckets = NULL;
    window->active_bucket_count = 0;
    window->active_bucket_mask = 0;
    window->active_size = 0;
}

static void stats_udp_window_free_seen(struct stats_udp_window *window)
{
    if (!window || !window->seen_buckets) {
        return;
    }

    for (size_t i = 0; i < window->seen_bucket_count; ++i) {
        struct stats_udp_seen_entry *entry = window->seen_buckets[i];
        while (entry) {
            struct stats_udp_seen_entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(window->seen_buckets);
    window->seen_buckets = NULL;
    window->seen_bucket_count = 0;
    window->seen_bucket_mask = 0;
    window->seen_size = 0;
}

static void stats_udp_window_update_active_metric(struct stats_udp_window *window,
                                                  struct ep_stats *stats)
{
    size_t active = window ? window->active_size : 0;
    stats_set_udp_active(stats, active);
}

static bool stats_udp_peer_expired(const struct stats_udp_peer_entry *entry,
                                   uint64_t now_epoch_sec)
{
    uint64_t window_span = (uint64_t)EPOLL_ECHO_UDP_PEER_WINDOW_SEC;

    if (!entry) {
        return false;
    }

    if (now_epoch_sec <= entry->last_seen) {
        return false;
    }

    return (now_epoch_sec - entry->last_seen) > window_span;
}

/*
 * stats_init
 * stats: Pointer to the counter structure to reset.
 * Effect: Zeroes all counters so a fresh process lifetime can start tracking
 *         totals. Safe to call multiple times (idempotent reset).
 */
void stats_init(struct ep_stats *stats)
{
    if (!stats) {
        return;
    }

    memset(stats, 0, sizeof(*stats));
}

/*
 * stats_note_tcp_connected
 * stats: Global counter block.
 * Effect: Records a newly accepted TCP client by incrementing both the total
 *         lifetime counter and the instantaneous connected count.
 */
void stats_note_tcp_connected(struct ep_stats *stats)
{
    if (!stats) {
        return;
    }

    stats->tcp_connected_now++;
    stats->total_clients++;
}

/*
 * stats_note_tcp_disconnected
 * stats: Global counter block.
 * Effect: Decrements the instantaneous TCP connection count when a client
 *         disconnects. Guarded against underflow if called redundantly.
 */
void stats_note_tcp_disconnected(struct ep_stats *stats)
{
    if (!stats || stats->tcp_connected_now == 0) {
        return;
    }

    stats->tcp_connected_now--;
}

/*
 * stats_get_total_clients
 * stats: Counter snapshot.
 * Returns: The lifetime total of TCP accepts plus unique UDP peers.
 */
uint64_t stats_get_total_clients(const struct ep_stats *stats)
{
    return stats ? stats->total_clients : 0;
}

/*
 * stats_get_tcp_connected_now
 * stats: Counter snapshot.
 * Returns: Number of currently connected TCP clients. Helpful for /stats and
 *          capacity enforcement logic.
 */
uint32_t stats_get_tcp_connected_now(const struct ep_stats *stats)
{
    return stats ? stats->tcp_connected_now : 0;
}

/*
 * stats_get_udp_active_60s
 * stats: Counter snapshot.
 * Returns: Number of UDP peers seen in the trailing 60-second window.
 */
uint32_t stats_get_udp_active_60s(const struct ep_stats *stats)
{
    return stats ? stats->udp_active_60s : 0;
}

/*
 * stats_udp_window_create
 * window_out: Output pointer that receives the UDP peer window handle.
 * Returns: 0 on success, -1 with errno set (EINVAL for bad args, ENOMEM on OOM).
 * Notes: Allocates hash tables for both the active 60s window and the lifetime
 *        seen-set used to guard total client increments.
 */
int stats_udp_window_create(struct stats_udp_window **window_out)
{
    if (!window_out) {
        errno = EINVAL;
        return -1;
    }

    struct stats_udp_window *window = calloc(1, sizeof(*window));
    if (!window) {
        return -1;
    }

    if (stats_udp_window_resize_active(window,
                                       STATS_UDP_ACTIVE_INITIAL_BUCKETS) != 0) {
        int err = errno;
        stats_udp_window_destroy(window);
        errno = err;
        return -1;
    }

    if (stats_udp_window_resize_seen(window,
                                     STATS_UDP_SEEN_INITIAL_BUCKETS) != 0) {
        int err = errno;
        stats_udp_window_destroy(window);
        errno = err;
        return -1;
    }

    *window_out = window;
    return 0;
}

/*
 * stats_udp_window_destroy
 * window: Previously allocated window.
 * Effect: Releases hash buckets and their nodes; accepts NULL for convenience.
 */
void stats_udp_window_destroy(struct stats_udp_window *window)
{
    if (!window) {
        return;
    }

    stats_udp_window_free_active(window);
    stats_udp_window_free_seen(window);
    free(window);
}

/*
 * stats_udp_window_record_peer
 * window: UDP peer window handle.
 * stats: Global counter block to update when unique peers are tracked.
 * addr/addr_len: Remote endpoint associated with the datagram.
 * now_epoch_sec: Current CLOCK_REALTIME seconds used for the 60s window.
 * Returns: 0 on success, -1 with errno set on argument errors.
 */
int stats_udp_window_record_peer(struct stats_udp_window *window,
                                 struct ep_stats *stats,
                                 const struct sockaddr_storage *addr,
                                 socklen_t addr_len,
                                 uint64_t now_epoch_sec)
{
    if (!window || !stats || !addr) {
        errno = EINVAL;
        return -1;
    }

    if (now_epoch_sec == 0) {
        time_t fallback = time(NULL);
        if (fallback > 0) {
            now_epoch_sec = (uint64_t)fallback;
        }
    }

    struct stats_udp_peer_key key;
    if (stats_udp_key_from_sockaddr(&key, addr, addr_len) != 0) {
        return -1;
    }

    uint64_t hash = stats_udp_hash_key(&key);
    size_t bucket_idx = hash & window->active_bucket_mask;
    struct stats_udp_peer_entry *entry =
        window->active_buckets[bucket_idx];
    while (entry) {
        if (stats_udp_keys_equal(&entry->key, &key)) {
            entry->last_seen = now_epoch_sec;
            return 0;
        }
        entry = entry->next;
    }

    struct stats_udp_seen_entry *pending_seen = NULL;
    bool peer_seen_before = false;
    size_t seen_bucket_idx = 0;

    /* Prepare lifetime bookkeeping so we know whether to bump totals. */
    if (window->seen_buckets) {
        seen_bucket_idx = hash & window->seen_bucket_mask;
        struct stats_udp_seen_entry *seen =
            window->seen_buckets[seen_bucket_idx];
        while (seen) {
            if (stats_udp_keys_equal(&seen->key, &key)) {
                peer_seen_before = true;
                break;
            }
            seen = seen->next;
        }
    }

    if (!peer_seen_before) {
        if (stats_udp_window_reserve_seen(window) != 0) {
            return -1;
        }

        pending_seen = calloc(1, sizeof(*pending_seen));
        if (!pending_seen) {
            return -1;
        }
        pending_seen->key = key;
    }

    if (stats_udp_window_reserve_active(window) != 0) {
        free(pending_seen);
        return -1;
    }

    struct stats_udp_peer_entry *new_entry = calloc(1, sizeof(*new_entry));
    if (!new_entry) {
        free(pending_seen);
        return -1;
    }

    new_entry->key = key;
    new_entry->last_seen = now_epoch_sec;
    bucket_idx = hash & window->active_bucket_mask;
    new_entry->next = window->active_buckets[bucket_idx];
    window->active_buckets[bucket_idx] = new_entry;
    window->active_size++;

    stats_udp_window_update_active_metric(window, stats);

    if (!peer_seen_before) {
        seen_bucket_idx = hash & window->seen_bucket_mask;
        pending_seen->next = window->seen_buckets[seen_bucket_idx];
        window->seen_buckets[seen_bucket_idx] = pending_seen;
        window->seen_size++;
        stats->total_clients++;
    } else {
        free(pending_seen);
    }

    return 0;
}

/*
 * stats_udp_window_handle_tick
 * window: UDP peer window handle.
 * stats: Counter snapshot to refresh after aging.
 * now_epoch_sec: Current CLOCK_REALTIME seconds for expiration logic.
 * Returns: 0 on success, -1 for invalid parameters.
 * Notes: Removes peers whose last_seen is more than 60 seconds in the past and
 *        updates the udp_active_60s counter accordingly.
 */
int stats_udp_window_handle_tick(struct stats_udp_window *window,
                                 struct ep_stats *stats,
                                 uint64_t now_epoch_sec)
{
    if (!window || !stats) {
        errno = EINVAL;
        return -1;
    }

    if (!window->active_buckets || window->active_bucket_count == 0) {
        stats_udp_window_update_active_metric(window, stats);
        return 0;
    }

    size_t removed = 0;

    for (size_t i = 0; i < window->active_bucket_count; ++i) {
        struct stats_udp_peer_entry **prev = &window->active_buckets[i];
        struct stats_udp_peer_entry *entry = *prev;

        while (entry) {
            if (stats_udp_peer_expired(entry, now_epoch_sec)) {
                *prev = entry->next;
                free(entry);
                entry = *prev;
                if (window->active_size > 0) {
                    window->active_size--;
                }
                removed++;
                continue;
            }

            prev = &entry->next;
            entry = entry->next;
        }
    }

    if (removed > 0) {
        stats_udp_window_update_active_metric(window, stats);
    }

    return 0;
}
