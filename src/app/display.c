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

#define UNREACH_FALLBACK_SIZE 8

/* Maps an ICMP Destination Unreachable code to Linux traceroute's annotation letter */
static const char *unreach_suffix(uint8_t code, char *buf, size_t len)
{
    switch (code) {
    case ICMP_NET_UNREACH_CODE:
    case ICMP_NET_UNKNOWN_CODE:
    case ICMP_HOST_ISOLATED_CODE:
    case ICMP_NET_TOS_CODE:          return " !N";
    case ICMP_HOST_UNREACH_CODE:
    case ICMP_HOST_UNKNOWN_CODE:
    case ICMP_HOST_TOS_CODE:         return " !H";
    case ICMP_PROTO_UNREACH_CODE:    return " !P";
    case ICMP_PORT_UNREACH_CODE:     return "";
    case ICMP_FRAG_NEEDED_CODE:      return " !F";
    case ICMP_SRC_ROUTE_FAILED_CODE: return " !S";
    case ICMP_NET_PROHIBITED_CODE:
    case ICMP_HOST_PROHIBITED_CODE:
    case ICMP_ADMIN_PROHIBITED_CODE: return " !X";
    case ICMP_PREC_VIOLATION_CODE:   return " !V";
    case ICMP_PREC_CUTOFF_CODE:      return " !C";
    default:
        snprintf(buf, len, " !%d", code);
        return buf;
    }
}

void display_header(const char *host, const char *dst_ip, int max_ttl, int probe_len)
{
    printf("traceroute to %s (%s), %d hops max, %d byte packets\n",
           host, dst_ip, max_ttl, probe_len);
}

void display_hop_start(hop_display_t *hop, int ttl)
{
    hop->last_addr.s_addr = 0;
    hop->have_last = 0;
    printf("%2d ", ttl);
    fflush(stdout);
}

void display_probe_timeout(void)
{
    printf(" *");
    fflush(stdout);
}

void display_probe_reply(hop_display_t *hop, struct in_addr from, double rtt_ms, const icmp_reply_t *reply, int numeric)
{
    char label[LABEL_BUFFER_SIZE];

    /* Print address label on first reply or when ECMP changes path */
    if (!hop->have_last || from.s_addr != hop->last_addr.s_addr) {
        network_format_addr(from, numeric, label, sizeof(label));
        printf(" %s", label);
        hop->last_addr = from;
        hop->have_last = 1;
    }
    printf("  %.3f ms", rtt_ms);

    /* Destination unreachable: annotate with a letter unless normal port unreachable */
    if (reply->type == ICMP_DEST_UNREACH) {
        char fallback[UNREACH_FALLBACK_SIZE];
        printf("%s", unreach_suffix(reply->code, fallback, sizeof(fallback)));
    }
    fflush(stdout);
}

void display_hop_end(void)
{
    printf("\n");
    fflush(stdout);
}
