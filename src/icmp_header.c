/*
 * icmp_header.c - ICMP reply parser and probe correlator according to RFC 792.
 *
 * Dissects ICMP Time Exceeded and Destination Unreachable packets, extracts
 * quoted inner IP and UDP headers, and validates demultiplexing identifiers.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "icmp_header.h"
#include "ip_header.h"
#include "udp_header.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int parse_icmp_reply(const uint8_t *packet, int len, uint16_t src_port,
                     icmp_reply_t *reply)
{
    ip_header_t inner_iph;
    udp_header_t inner_udph;
    int outer_ihl, icmp_off, inner_off, inner_ihl, udp_off;

    /* 1. Outer IP header: validate size and extract IHL */
    if (len < IP_HEADER_LEN) return 0;
    outer_ihl = (packet[0] & IPV4_IHL_MASK) * IPV4_WORD_BYTES;
    if (outer_ihl < IP_HEADER_LEN || len < outer_ihl + ICMP_HEADER_LEN) {
        return 0;
    }

    /* 2. ICMP header: only Time Exceeded (11) and Dest Unreachable (3) quote probe */
    icmp_off = outer_ihl;
    reply->type = packet[icmp_off + ICMP_TYPE_OFFSET];
    reply->code = packet[icmp_off + ICMP_CODE_OFFSET];
    if (reply->type != ICMP_TIME_EXCEEDED && reply->type != ICMP_DEST_UNREACH) {
        return 0;
    }

    /* 3. Quoted inner IP header: verify protocol is UDP */
    inner_off = icmp_off + ICMP_HEADER_LEN;
    if (len < inner_off + IP_HEADER_LEN) {
        return 0;
    }
    memcpy(&inner_iph, packet + inner_off, sizeof(inner_iph));
    inner_ihl = (inner_iph.ihl_version & IPV4_IHL_MASK) * IPV4_WORD_BYTES;
    if (inner_ihl < IP_HEADER_LEN || inner_iph.protocol != IPPROTO_UDP) {
        return 0;
    }

    /* 4. Quoted inner UDP header: first 8 bytes contain original probe ports */
    udp_off = inner_off + inner_ihl;
    if (len < udp_off + UDP_HEADER_LEN) {
        return 0;
    }
    memcpy(&inner_udph, packet + udp_off, sizeof(inner_udph));
    if (ntohs(inner_udph.src_port) != src_port) {
        return 0; /* Foreign traffic (parallel ping, other process, etc.) */
    }

    reply->probe_port = ntohs(inner_udph.dst_port);
    return 1;
}
