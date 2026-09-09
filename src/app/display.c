/*
 * display.c - Console presentation and formatting for raw traceroute.
 *
 * Implements hop row printing, timeout indications, RTT millisecond
 * formatting, ICMP error annotations, and ECMP inline address changes.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "display.h"
#include "network.h"

#include <stdio.h>
#include <string.h>

#define HOP_NOT_SEEN 0
#define HOP_SEEN     1

static struct in_addr g_last_addr;
static int g_have_last = HOP_NOT_SEEN;

void display_header(const char *host, const char *dst_ip, int max_ttl, int probe_len)
{
    printf("traceroute to %s (%s), %d hops max, %d byte packets\n",
           host, dst_ip, max_ttl, probe_len);
}

void display_hop_start(int ttl)
{
    g_last_addr.s_addr = 0;
    g_have_last = HOP_NOT_SEEN;
    printf("%2d ", ttl);
    fflush(stdout);
}

void display_probe_timeout(void)
{
    printf(" *");
    fflush(stdout);
}

void display_probe_reply(struct in_addr from, double rtt_ms, const icmp_reply_t *reply, int numeric)
{
    char label[LABEL_BUFFER_SIZE];

    /* Print address label on first reply or when ECMP changes path */
    if (!g_have_last || from.s_addr != g_last_addr.s_addr) {
        network_format_addr(from, numeric, label, sizeof(label));
        printf(" %s", label);
        g_last_addr = from;
        g_have_last = HOP_SEEN;
    }
    printf("  %.3f ms", rtt_ms);

    /* Destination reached: delivery error code annotation if not normal port unreachable */
    if (reply->type == ICMP_DEST_UNREACH && reply->code != ICMP_PORT_UNREACH_CODE) {
        printf(" !%d", reply->code);
    }
    fflush(stdout);
}

void display_hop_end(void)
{
    printf("\n");
    fflush(stdout);
}
