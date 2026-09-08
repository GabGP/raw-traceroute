/*
 * probe.h - Probe transmission and raw socket engine interface.
 *
 * Manages raw socket descriptors (IP_HDRINCL send socket and ICMP receive
 * socket), PID-derived port demuxing, and event-driven reply wait loops.
 */

#ifndef PROBE_H
#define PROBE_H

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

#include "packet.h"

#define PROBE_BASE_PORT      33434
#define PID_PORT_MASK        0x7FFF
#define PID_PORT_OFFSET      0x8000
#define RECV_BUFFER_SIZE     2048
#define INITIAL_IP_ID        1

#define MS_PER_SEC           1000.0
#define NS_PER_MS            1000000.0
#define US_PER_MS            1000.0
#define MS_PER_SEC_INT       1000
#define NS_PER_MS_LONG       1000000L
#define NS_PER_SEC_LONG      1000000000L
#define NS_PER_US_LONG       1000L

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC      1
#endif

typedef struct {
    int send_fd;        /* SOCK_RAW, IPPROTO_RAW with IP_HDRINCL */
    int recv_fd;        /* SOCK_RAW, IPPROTO_ICMP */
    uint16_t src_port;  /* PID-derived fixed port */
    struct in_addr src_ip;
    struct in_addr dst_ip;
} probe_engine_t;

/* Initializes probe engine, creates raw sockets, and derives unique source port */
int probe_engine_init(probe_engine_t *engine, struct in_addr src, struct in_addr dst);

/* Closes open socket descriptors */
void probe_engine_close(probe_engine_t *engine);

/* Flushes any stale or extraneous replies from the raw ICMP receive queue */
void probe_drain_replies(probe_engine_t *engine);

/* Crafts and sends a single 60-byte UDP probe with specific TTL and destination port */
int probe_send(probe_engine_t *engine, int ttl, uint16_t dst_port, uint16_t ip_id);

/* Waits up to timeout_s for an ICMP reply matching dst_port and engine->src_port */
int probe_wait_reply(probe_engine_t *engine, const struct timespec *sent, int timeout_s,
                     uint16_t dst_port, struct in_addr *from, icmp_reply_t *reply,
                     double *rtt_ms);

/* Utility function returning elapsed milliseconds between two timespecs */
double probe_elapsed_ms(const struct timespec *from, const struct timespec *to);

#endif /* PROBE_H */
