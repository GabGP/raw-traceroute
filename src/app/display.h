/*
 * display.h - Console presentation and formatting for raw traceroute.
 *
 * Encapsulates terminal output formatting, probe timeout indication,
 * RTT millisecond display, ICMP error code annotations, and ECMP
 * route-change detection without polluting the hop loop orchestrator.
 */

#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdint.h>
#include <netinet/in.h>
#include "icmp_header.h"

/* Per-hop state: lets display_probe_reply() print an address only when it changes */
typedef struct {
    struct in_addr last_addr;   /* address of the previous replying probe */
    int have_last;              /* nonzero once a reply was printed in this hop */
} hop_display_t;

/* Prints banner header before probe execution begins */
void display_header(const char *host, const char *dst_ip, int max_ttl, int probe_len);

/* Starts a hop row and initialises the caller-owned hop state */
void display_hop_start(hop_display_t *hop, int ttl);

/* Prints timeout indicator (' *') */
void display_probe_timeout(void);

/* Formats probe reply: handles ECMP address change, prints RTT and ICMP error codes */
void display_probe_reply(hop_display_t *hop, struct in_addr from, double rtt_ms, const icmp_reply_t *reply, int numeric);

/* Finishes the hop row with a newline and flushes stdout */
void display_hop_end(void);

#endif /* DISPLAY_H */
