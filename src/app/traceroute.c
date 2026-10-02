/*
 * traceroute.c - Orchestrator and presentation loop for raw traceroute.
 *
 * Coordinates the outer TTL hop loop and inner probe query loop, measures RTT,
 * delegates presentation to display module, and halts upon reaching destination.
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
#include "display.h"

#define SHELL_EXIT_BASE         128
#define EXIT_INTERRUPTED        (SHELL_EXIT_BASE + SIGINT)
#define ROOT_UID                0
#define PROBE_LAST_INDEX_OFFSET 1
#define INITIAL_DONE_STATE      0
#define TERMINAL_DONE_STATE     1
#define SIGNAL_SET_STATE        1

static volatile sig_atomic_t g_interrupted = 0;

static void handle_signal(int sig)
{
    (void)sig;
    g_interrupted = SIGNAL_SET_STATE;
}

int main(int argc, char **argv)
{
    traceroute_config_t cfg;
    probe_engine_t engine;
    struct in_addr dst_addr, src_addr, from;
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t dst_port = PROBE_BASE_PORT, ip_id = INITIAL_IP_ID;
    int ttl, q, done = INITIAL_DONE_STATE;
    struct timespec sent;
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
    if (geteuid() != ROOT_UID) {
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
    display_header(cfg.host, dst_ip, cfg.max_ttl, PROBE_LEN);

    /* 4. Initialize probe engine: open raw sockets and derive source port */
    if (probe_engine_init(&engine, src_addr, dst_addr) < 0) return EXIT_FAILURE;

    /* 5. Hop loop: increment TTL from first_ttl up to max_ttl */
    for (ttl = cfg.first_ttl; ttl <= cfg.max_ttl && !done && !g_interrupted; ttl++) {
        display_hop_start(ttl);

        /* Send nqueries probes for the current hop */
        for (q = 0; q < cfg.nqueries; q++) {
            if (g_interrupted) break;
            if (probe_send(&engine, ttl, dst_port, ip_id++, &sent) < 0) {
                printf("\n");
                perror("traceroute: sendto");
                probe_engine_close(&engine);
                return EXIT_FAILURE;
            }

            /* Wait for matching ICMP reply until timeout */
            if (!probe_wait_reply(&engine, &sent, cfg.waittime_s, dst_port, &from, &reply, &rtt, &g_interrupted)) {
                display_probe_timeout();
            } else {
                display_probe_reply(from, rtt, &reply, cfg.numeric);
                if (reply.type == ICMP_DEST_UNREACH) {
                    done = TERMINAL_DONE_STATE;
                }
            }

            dst_port++;
            /* Pause between consecutive probes if configured and more probes follow */
            if (!g_interrupted && cfg.sendwait_ms > 0 &&
                (q < cfg.nqueries - PROBE_LAST_INDEX_OFFSET || (!done && ttl < cfg.max_ttl))) {
                probe_sleep_ms(cfg.sendwait_ms);
            }
        }
        display_hop_end();
    }

    /* 6. Clean up socket descriptors */
    probe_engine_close(&engine);
    return g_interrupted ? EXIT_INTERRUPTED : EXIT_SUCCESS;
}
