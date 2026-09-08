/*
 * probe.c - Raw socket lifecycle, packet transmission, and reply listener.
 *
 * Handles creation of raw sockets with IP_HDRINCL, sends handcrafted UDP
 * probes, and awaits correlated ICMP replies using select() with monotonic RTT.
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

void probe_engine_close(probe_engine_t *engine)
{
    if (engine->send_fd >= 0) { close(engine->send_fd); engine->send_fd = -1; }
    if (engine->recv_fd >= 0) { close(engine->recv_fd); engine->recv_fd = -1; }
}

int probe_engine_init(probe_engine_t *engine, struct in_addr src, struct in_addr dst)
{
    int on = 1;

    engine->send_fd  = -1;
    engine->recv_fd  = -1;
    engine->src_ip   = src;
    engine->dst_ip   = dst;
    engine->src_port = (uint16_t)((getpid() & PID_PORT_MASK) | PID_PORT_OFFSET);

    engine->send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (engine->send_fd < 0) {
        perror("traceroute: socket(SOCK_RAW, IPPROTO_RAW)");
        return -1;
    }
    if (setsockopt(engine->send_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("traceroute: setsockopt(IP_HDRINCL)");
        probe_engine_close(engine);
        return -1;
    }

    engine->recv_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (engine->recv_fd < 0) {
        perror("traceroute: socket(SOCK_RAW, IPPROTO_ICMP)");
        probe_engine_close(engine);
        return -1;
    }
    return 0;
}

void probe_drain_replies(probe_engine_t *engine)
{
    uint8_t dummy[RECV_BUFFER_SIZE];
    while (recvfrom(engine->recv_fd, dummy, sizeof(dummy), MSG_DONTWAIT, NULL, NULL) > 0) {
    }
}

int probe_send(probe_engine_t *engine, int ttl, uint16_t dst_port, uint16_t ip_id)
{
    uint8_t buf[PROBE_LEN] __attribute__((aligned(4)));
    struct sockaddr_in to;

    probe_drain_replies(engine);
    build_probe_packet(buf, engine->src_ip.s_addr, engine->dst_ip.s_addr,
                       (uint8_t)ttl, engine->src_port, dst_port, ip_id);

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr   = engine->dst_ip;
    to.sin_port   = htons(dst_port);

    if (sendto(engine->send_fd, buf, PROBE_LEN, 0,
               (struct sockaddr *)&to, sizeof(to)) != PROBE_LEN) {
        return -1;
    }
    return 0;
}

int probe_wait_reply(probe_engine_t *engine, const struct timespec *sent, int timeout_s,
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
            nsec += NS_PER_SEC_LONG;
        }
        if (sec < 0 || (sec == 0 && nsec <= 0)) return 0;

        tv.tv_sec  = sec;
        tv.tv_usec = (suseconds_t)(nsec / NS_PER_US_LONG);

        FD_ZERO(&rfds);
        FD_SET(engine->recv_fd, &rfds);
        rc = select(engine->recv_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (rc == 0) return 0;

        slen = sizeof(sa);
        n = recvfrom(engine->recv_fd, buf, sizeof(buf), 0, (struct sockaddr *)&sa, &slen);
        if (n < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);

        if (!parse_icmp_reply(buf, (int)n, engine->src_port, reply)) continue;
        if (reply->probe_port != dst_port) continue;

        *from   = sa.sin_addr;
        *rtt_ms = probe_elapsed_ms(sent, &now);
        return 1;
    }
}
