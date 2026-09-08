/*
 * traceroute.c - Orchestrator and presentation loop for raw traceroute.
 *
 * Coordinates the outer TTL hop loop and inner probe query loop, measures RTT,
 * formats inline ECMP routing output, and halts upon reaching the destination.
 * Zero third-party packet libraries or subprocess system calls.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "packet.h"
#include "cli.h"
#include "network.h"
#include "probe.h"

#define SHELL_EXIT_BASE      128
#define EXIT_INTERRUPTED     (SHELL_EXIT_BASE + SIGINT)

static volatile sig_atomic_t g_interrupted = 0;

static void handle_signal(int sig)
{
    (void)sig;
    g_interrupted = 1;
}

int main(int argc, char **argv)
{
    traceroute_config_t cfg;
    probe_engine_t engine;
    struct in_addr dst_addr, src_addr, last_addr, from;
    char dst_ip[INET_ADDRSTRLEN], label[LABEL_BUFFER_SIZE];
    uint16_t dst_port = PROBE_BASE_PORT, ip_id = INITIAL_IP_ID;
    int ttl, q, have_last, done = 0;
    struct timespec sent, pause;
    icmp_reply_t reply;
    double rtt = 0.0;

    struct sigaction sa;

    /* 1. Parse command-line flags and validate parameter bounds */
    if (cli_parse(argc, argv, &cfg) < 0) return EXIT_FAILURE;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* 2. Enforce CAP_NET_RAW root privileges before opening raw sockets */
    if (geteuid() != 0) {
        fprintf(stderr, "traceroute: raw sockets require root privileges; run it with sudo\n");
        return EXIT_FAILURE;
    }

    /* 3. Resolve destination hostname and discover local egress source IP */
    if (network_resolve_target(cfg.host, &dst_addr) < 0) return EXIT_FAILURE;
    if (network_get_source_addr(dst_addr, &src_addr) < 0) {
        perror("traceroute: cannot determine local source address");
        return EXIT_FAILURE;
    }

    inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));
    printf("traceroute to %s (%s), %d hops max, %d byte packets\n",
           cfg.host, dst_ip, cfg.max_ttl, PROBE_LEN);

    /* 4. Initialize probe engine: open raw sockets and derive source port */
    if (probe_engine_init(&engine, src_addr, dst_addr) < 0) return EXIT_FAILURE;

    /* 5. Hop loop: increment TTL from first_ttl up to max_ttl */
    for (ttl = cfg.first_ttl; ttl <= cfg.max_ttl && !done && !g_interrupted; ttl++) {
        last_addr.s_addr = 0;
        have_last = 0;
        printf("%2d ", ttl);
        fflush(stdout);

        /* Send nqueries probes for the current hop */
        for (q = 0; q < cfg.nqueries; q++) {
            if (g_interrupted) break;
            clock_gettime(CLOCK_MONOTONIC, &sent);
            if (probe_send(&engine, ttl, dst_port, ip_id++) < 0) {
                printf("\n");
                perror("traceroute: sendto");
                probe_engine_close(&engine);
                return EXIT_FAILURE;
            }

            /* Wait for matching ICMP reply until timeout */
            if (!probe_wait_reply(&engine, &sent, cfg.waittime_s, dst_port, &from, &reply, &rtt)) {
                printf(" *"); /* Probe timed out */
            } else {
                /* Print address label on first reply or when ECMP changes path */
                if (!have_last || from.s_addr != last_addr.s_addr) {
                    network_format_addr(from, cfg.numeric, label, sizeof(label));
                    printf(" %s", label);
                    last_addr = from;
                    have_last = 1;
                }
                printf("  %.3f ms", rtt);

                /* Destination reached: port unreachable (normal) or delivery error */
                if (reply.type == ICMP_DEST_UNREACH) {
                    if (reply.code != ICMP_PORT_UNREACH_CODE) printf(" !%d", reply.code);
                    done = 1;
                }
            }
            fflush(stdout);

            dst_port++;
            /* Pause between consecutive probes if configured and more probes follow */
            if (cfg.sendwait_ms > 0 && !done && !g_interrupted &&
                (q < cfg.nqueries - 1 || ttl < cfg.max_ttl)) {
                pause.tv_sec  = cfg.sendwait_ms / MS_PER_SEC_INT;
                pause.tv_nsec = (long)(cfg.sendwait_ms % MS_PER_SEC_INT) * NS_PER_MS_LONG;
                nanosleep(&pause, NULL);
            }
        }
        printf("\n");
        fflush(stdout);
    }

    /* 6. Clean up socket descriptors */
    probe_engine_close(&engine);
    return g_interrupted ? EXIT_INTERRUPTED : EXIT_SUCCESS;
}
