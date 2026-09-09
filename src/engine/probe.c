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
    return (double)(to->tv_sec - from->tv_sec) * MS_PER_SEC
         + (double)(to->tv_nsec - from->tv_nsec) / NS_PER_MS;
}

void probe_sleep_ms(int ms)
{
    if (ms <= 0) return;
    struct timespec pause;
    pause.tv_sec  = ms / MS_PER_SEC_INT;
    pause.tv_nsec = (long)(ms % MS_PER_SEC_INT) * NS_PER_MS_LONG;
    nanosleep(&pause, NULL);
}

void probe_engine_close(probe_engine_t *engine)
{
    raw_socket_close(&engine->send_fd);
    raw_socket_close(&engine->recv_fd);
}

int probe_engine_init(probe_engine_t *engine, struct in_addr src, struct in_addr dst)
{
    engine->send_fd  = INVALID_SOCKET_FD;
    engine->recv_fd  = INVALID_SOCKET_FD;
    engine->src_ip   = src;
    engine->dst_ip   = dst;
    engine->src_port = (uint16_t)((getpid() & PID_PORT_MASK) | PID_PORT_OFFSET);

    engine->send_fd = raw_socket_create_send();
    if (engine->send_fd < 0) {
        return PROBE_ENGINE_ERROR;
    }

    engine->recv_fd = raw_socket_create_recv();
    if (engine->recv_fd < 0) {
        probe_engine_close(engine);
        return PROBE_ENGINE_ERROR;
    }
    return PROBE_ENGINE_SUCCESS;
}

int probe_send(probe_engine_t *engine, int ttl, uint16_t dst_port, uint16_t ip_id)
{
    uint8_t buf[PROBE_LEN] __attribute__((aligned(4)));

    raw_socket_drain(engine->recv_fd);
    build_probe_packet(buf, engine->src_ip.s_addr, engine->dst_ip.s_addr,
                       (uint8_t)ttl, engine->src_port, dst_port, ip_id);

    return raw_socket_send(engine->send_fd, buf, PROBE_LEN, engine->dst_ip);
}

int probe_wait_reply(probe_engine_t *engine, const struct timespec *sent, int timeout_s,
                     uint16_t dst_port, struct in_addr *from, icmp_reply_t *reply,
                     double *rtt_ms, const volatile sig_atomic_t *interrupted)
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
        if (interrupted && *interrupted) return PROBE_REPLY_TIMEOUT;
        clock_gettime(CLOCK_MONOTONIC, &now);
        sec = deadline.tv_sec - now.tv_sec;
        nsec = deadline.tv_nsec - now.tv_nsec;
        if (nsec < 0) {
            sec--;
            nsec += NS_PER_SEC_LONG;
        }
        if (sec < 0 || (sec == 0 && nsec <= 0)) return PROBE_REPLY_TIMEOUT;

        tv.tv_sec  = sec;
        tv.tv_usec = (suseconds_t)(nsec / NS_PER_US_LONG);

        FD_ZERO(&rfds);
        FD_SET(engine->recv_fd, &rfds);
        rc = select(engine->recv_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                if (interrupted && *interrupted) return PROBE_REPLY_TIMEOUT;
                continue;
            }
            return PROBE_REPLY_TIMEOUT;
        }
        if (rc == SELECT_TIMEOUT_ZERO) return PROBE_REPLY_TIMEOUT;

        slen = sizeof(sa);
        n = recvfrom(engine->recv_fd, buf, sizeof(buf), RECVFROM_FLAGS_DEFAULT,
                     (struct sockaddr *)&sa, &slen);
        if (n < 0) {
            if (errno == EINTR) {
                if (interrupted && *interrupted) return PROBE_REPLY_TIMEOUT;
                continue;
            }
            return PROBE_REPLY_TIMEOUT;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);

        if (!parse_icmp_reply(buf, (int)n, engine->src_port, reply)) continue;
        if (reply->probe_port != dst_port) continue;

        *from   = sa.sin_addr;
        *rtt_ms = probe_elapsed_ms(sent, &now);
        return PROBE_REPLY_RECEIVED;
    }
}
