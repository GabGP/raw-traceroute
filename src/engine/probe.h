/*
 * probe.h - Probe orchestration and event-driven reply listener.
 *
 * Manages probe lifecycle, PID-derived port demuxing, and event-driven
 * reply wait loops using monotonic RTT timing.
 */

#ifndef PROBE_H
#define PROBE_H

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

#include "packet.h"
#include "raw_socket.h"

#define PROBE_BASE_PORT      33434
#define PID_PORT_MASK        0x7FFF
#define PID_PORT_OFFSET      0x8000
#define INITIAL_IP_ID        1

#define MS_PER_SEC           1000.0
#define NS_PER_MS            1000000.0
#define MS_PER_SEC_INT       1000
#define NS_PER_MS_LONG       1000000L
#define NS_PER_SEC_LONG      1000000000L
#define NS_PER_US_LONG       1000L

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC         1
#endif

#define PROBE_ENGINE_SUCCESS    0
#define PROBE_ENGINE_ERROR      (-1)
#define SELECT_TIMEOUT_ZERO     0
#define RECVFROM_FLAGS_DEFAULT  0

/* Outcome of waiting for a probe reply */
typedef enum {
    PROBE_TIMEOUT,      /* no matching reply before the deadline */
    PROBE_REPLY,        /* matching ICMP reply received */
    PROBE_INTERRUPTED   /* a signal (EINTR) cut the wait short */
} probe_result_t;

typedef struct {
    int send_fd;
    int recv_fd;
    uint16_t src_port;
    struct in_addr src_ip;
    struct in_addr dst_ip;
} probe_engine_t;

/* Initializes probe engine, creates raw sockets, and derives unique source port */
int probe_engine_init(probe_engine_t *engine, struct in_addr src, struct in_addr dst);

/* Closes open socket descriptors */
void probe_engine_close(probe_engine_t *engine);

/*
 * Crafts and sends a single 60-byte UDP probe with specific TTL and destination port.
 * Stale packets are drained from the receive socket first, so replies to earlier
 * probes cannot be mistaken for the reply to this one.
 * Writes the CLOCK_MONOTONIC send time to *sent, taken immediately before sendto().
 */
int probe_send(probe_engine_t *engine, int ttl, uint16_t dst_port, uint16_t ip_id,
               struct timespec *sent);

/*
 * Waits up to timeout_s for an ICMP reply matching dst_port and engine->src_port.
 * Returns PROBE_INTERRUPTED if a signal arrives while waiting; the caller decides
 * whether to stop.
 */
probe_result_t probe_wait_reply(probe_engine_t *engine, const struct timespec *sent, int timeout_s,
                     uint16_t dst_port, struct in_addr *from, icmp_reply_t *reply,
                     double *rtt_ms);

/* Pauses execution for ms milliseconds using nanosleep */
void probe_sleep_ms(int ms);

/* Utility function returning elapsed milliseconds between two timespecs */
double probe_elapsed_ms(const struct timespec *from, const struct timespec *to);

#endif /* PROBE_H */
