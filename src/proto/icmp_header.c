/*
 * icmp_header.c - ICMP reply parser and inner datagram demultiplexing.
 *
 * Dissects raw ICMP datagrams, extracts quoted original IPv4 and UDP headers,
 * and validates source port correlation to reject unrelated network traffic.
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

    /* 1. Outer IP header: from the responding router */
    if (len < IP_HEADER_LEN) return ICMP_PARSE_INVALID;
    outer_ihl = (packet[IPV4_FIRST_BYTE_OFFSET] & IPV4_IHL_MASK) * IPV4_WORD_BYTES;
    if (outer_ihl < IP_HEADER_LEN || len < outer_ihl + ICMP_HEADER_LEN) {
        return ICMP_PARSE_INVALID;
    }

    /* 2. ICMP header: only Time Exceeded and Dest Unreachable quote original datagram */
    icmp_off = outer_ihl;
    reply->type = packet[icmp_off + ICMP_TYPE_OFFSET];
    reply->code = packet[icmp_off + ICMP_CODE_OFFSET];
    if (reply->type != ICMP_TIME_EXCEEDED && reply->type != ICMP_DEST_UNREACH) {
        return ICMP_PARSE_INVALID;
    }

    /* 3. Inner quoted IP header: must be UDP to belong to our probe */
    inner_off = icmp_off + ICMP_HEADER_LEN;
    if (len < inner_off + IP_HEADER_LEN) {
        return ICMP_PARSE_INVALID;
    }
    memcpy(&inner_iph, packet + inner_off, sizeof(inner_iph));
    inner_ihl = (inner_iph.ihl_version & IPV4_IHL_MASK) * IPV4_WORD_BYTES;
    if (inner_ihl < IP_HEADER_LEN || inner_iph.protocol != IPPROTO_UDP) {
        return ICMP_PARSE_INVALID;
    }

    /* 4. First 8 bytes of quoted UDP header: ports identifying our probe */
    udp_off = inner_off + inner_ihl;
    if (len < udp_off + UDP_HEADER_LEN) {
        return ICMP_PARSE_INVALID;
    }
    memcpy(&inner_udph, packet + udp_off, sizeof(inner_udph));
    if (ntohs(inner_udph.src_port) != src_port) {
        return ICMP_PARSE_INVALID; /* Unrelated traffic (parallel ping, other process) */
    }

    reply->probe_port = ntohs(inner_udph.dst_port);
    return ICMP_PARSE_VALID;
}

