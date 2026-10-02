/*
 * probe.c - Probe orchestration and event-driven reply listener.
 *
 * Coordinates probe packet creation and transmission via raw_socket,
 * and awaits correlated ICMP replies using select() with monotonic RTT.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "probe.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>

double probe_elapsed_ms(const struct timespec *from, const struct timespec *to)
{
    return (double)(to->tv_sec - from->tv_sec) * 1000.0
         + (double)(to->tv_nsec - from->tv_nsec) / 1e6;
}

void probe_sleep_ms(int ms)
{
    if (ms <= 0) return;
    struct timespec pause;
    pause.tv_sec  = ms / 1000;
    pause.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&pause, NULL);
}

void probe_engine_close(probe_engine_t *engine)
{
    raw_socket_close(&engine->send_fd);
    raw_socket_close(&engine->recv_fd);
}

int probe_engine_init(probe_engine_t *engine, struct in_addr src, struct in_addr dst)
{
    engine->send_fd  = -1;
    engine->recv_fd  = -1;
    engine->src_ip   = src;
    engine->dst_ip   = dst;
    engine->src_port = (uint16_t)((getpid() & PID_PORT_MASK) | PID_PORT_OFFSET);

    engine->send_fd = raw_socket_create_send();
    if (engine->send_fd < 0) {
        return -1;
    }

    engine->recv_fd = raw_socket_create_recv();
    if (engine->recv_fd < 0) {
        probe_engine_close(engine);
        return -1;
    }
    return 0;
}

int probe_send(probe_engine_t *engine, int ttl, uint16_t dst_port, uint16_t ip_id,
               struct timespec *sent)
{
    uint8_t buf[PROBE_LEN] __attribute__((aligned(4)));

    /* Discard stale replies from earlier probes before sending */
    raw_socket_drain(engine->recv_fd);
    build_probe_packet(buf, engine->src_ip.s_addr, engine->dst_ip.s_addr,
                       (uint8_t)ttl, engine->src_port, dst_port, ip_id);

    /* Timestamp right before transmission so RTT excludes drain/build time */
    clock_gettime(CLOCK_MONOTONIC, sent);
    return raw_socket_send(engine->send_fd, buf, PROBE_LEN, engine->dst_ip);
}

probe_result_t probe_wait_reply(probe_engine_t *engine, const struct timespec *sent, int timeout_s,
                               uint16_t dst_port, struct in_addr *from, icmp_reply_t *reply,
                               double *rtt_ms)
{
    uint8_t buf[RECV_BUFFER_SIZE] __attribute__((aligned(4)));
    struct sockaddr_in sa;
    socklen_t slen;
    struct timespec now, deadline;
    struct timeval tv;
    fd_set rfds;
    time_t sec;
    long nsec;
    ssize_t n;
    int rc;

    deadline = *sent;
    deadline.tv_sec += timeout_s;

    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        sec = deadline.tv_sec - now.tv_sec;
        nsec = deadline.tv_nsec - now.tv_nsec;
        if (nsec < 0) {
            sec--;
            nsec += 1000000000L;
        }
        if (sec < 0 || (sec == 0 && nsec <= 0)) return PROBE_TIMEOUT;

        tv.tv_sec  = sec;
        tv.tv_usec = (suseconds_t)(nsec / 1000L);

        FD_ZERO(&rfds);
        FD_SET(engine->recv_fd, &rfds);
        rc = select(engine->recv_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            return errno == EINTR ? PROBE_INTERRUPTED : PROBE_TIMEOUT;
        }
        if (rc == 0) return PROBE_TIMEOUT;

        slen = sizeof(sa);
        n = recvfrom(engine->recv_fd, buf, sizeof(buf), 0,
                     (struct sockaddr *)&sa, &slen);
        if (n < 0) {
            return errno == EINTR ? PROBE_INTERRUPTED : PROBE_TIMEOUT;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);

        if (!parse_icmp_reply(buf, (int)n, engine->src_port, reply)) continue;
        if (reply->probe_port != dst_port) continue;

        *from   = sa.sin_addr;
        *rtt_ms = probe_elapsed_ms(sent, &now);
        return PROBE_REPLY;
    }
}
