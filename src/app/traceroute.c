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
#define SIGNAL_SET_STATE        1

/* What the hop loop should do after one hop has been traced */
typedef enum {
    HOP_CONTINUE,       /* keep going with the next TTL */
    HOP_REACHED,        /* destination answered (ICMP unreachable): stop */
    HOP_INTERRUPTED,    /* SIGINT/SIGTERM received: stop */
    HOP_FAILED          /* probe could not be sent: stop with an error */
} hop_status_t;

static volatile sig_atomic_t g_interrupted = 0;

static void handle_signal(int sig)
{
    (void)sig;
    g_interrupted = SIGNAL_SET_STATE;
}

/*
 * Sends cfg->nqueries probes for one TTL and prints the hop row.
 * dst_port and ip_id advance once per probe and persist across hops.
 * Pacing: -z pause after a probe unless it is the last one of the trace.
 */
static hop_status_t trace_hop(probe_engine_t *engine, const traceroute_config_t *cfg,
                              int ttl, uint16_t *dst_port, uint16_t *ip_id)
{
    struct in_addr from;
    struct timespec sent;
    icmp_reply_t reply;
    hop_display_t hop;
    probe_result_t wait = PROBE_TIMEOUT;
    double rtt = 0.0;
    int reached = 0, q;

    display_hop_start(&hop, ttl);
    for (q = 0; q < cfg->nqueries && !g_interrupted; q++) {
        if (probe_send(engine, ttl, *dst_port, (*ip_id)++, &sent) < 0) {
            printf("\n");
            perror("traceroute: sendto");
            return HOP_FAILED;
        }

        wait = probe_wait_reply(engine, &sent, cfg->waittime_s, *dst_port, &from, &reply, &rtt);
        if (wait == PROBE_INTERRUPTED) {
            break;  /* Ctrl-C: end the row without a '*' */
        } else if (wait == PROBE_TIMEOUT) {
            display_probe_timeout();
        } else {
            display_probe_reply(&hop, from, rtt, &reply, cfg->numeric);
            if (reply.type == ICMP_DEST_UNREACH) {
                reached = 1;
            }
        }

        (*dst_port)++;
        /* Pause if more probes follow in this hop, or another hop will follow */
        if (!g_interrupted && cfg->sendwait_ms > 0 &&
            (q < cfg->nqueries - 1 || (!reached && ttl < cfg->max_ttl))) {
            probe_sleep_ms(cfg->sendwait_ms);
        }
    }
    display_hop_end();

    if (g_interrupted || wait == PROBE_INTERRUPTED) return HOP_INTERRUPTED;
    return reached ? HOP_REACHED : HOP_CONTINUE;
}

int main(int argc, char **argv)
{
    traceroute_config_t cfg;
    probe_engine_t engine;
    struct in_addr dst_addr, src_addr;
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t dst_port = PROBE_BASE_PORT, ip_id = INITIAL_IP_ID;
    hop_status_t status = HOP_CONTINUE;
    int ttl;
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
    for (ttl = cfg.first_ttl; ttl <= cfg.max_ttl && !g_interrupted; ttl++) {
        status = trace_hop(&engine, &cfg, ttl, &dst_port, &ip_id);
        if (status != HOP_CONTINUE) break;
    }

    /* 6. Clean up socket descriptors */
    probe_engine_close(&engine);
    if (status == HOP_FAILED) return EXIT_FAILURE;
    return g_interrupted ? EXIT_INTERRUPTED : EXIT_SUCCESS;
}
