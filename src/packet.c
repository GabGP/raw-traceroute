/*
 * packet.c - Handcrafted packet construction and ICMP reply parsing.
 *
 * Implements RFC 1071 checksums, IPv4 pseudo-header generation, 60-byte UDP
 * probe datagram crafting, and ICMP error reply dissection and demuxing.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "packet.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* Computes RFC 1071 Internet Checksum with 32-bit carry fold */
uint16_t calculate_checksum(const void *buffer, int size)
{
    const uint8_t *p = (const uint8_t *)buffer;
    unsigned long sum = 0;
    uint16_t word;

    while (size > 1) {
        memcpy(&word, p, sizeof(word));
        sum += word;
        p += sizeof(word);
        size -= (int)sizeof(word);
    }
    if (size == 1) sum += *p;

    while (sum >> CKSUM_SHIFT) {
        sum = (sum & CKSUM_MASK) + (sum >> CKSUM_SHIFT);
    }

    return (uint16_t)(~sum);
}

/* Computes UDP checksum over 12-byte IPv4 pseudo-header + UDP segment */
uint16_t calculate_udp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                const void *udp_segment, int udp_segment_len)
{
    uint8_t pseudo_packet[sizeof(pseudo_header_t) + PROBE_LEN];
    pseudo_header_t psh;
    int total_len;

    if (udp_segment_len < 0 || udp_segment_len > PROBE_LEN) return 0;
    total_len = (int)sizeof(pseudo_header_t) + udp_segment_len;

    psh.src_addr   = src_addr;
    psh.dst_addr   = dst_addr;
    psh.zero       = 0;
    psh.protocol   = IPPROTO_UDP;
    psh.udp_length = htons((uint16_t)udp_segment_len);

    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), udp_segment, (size_t)udp_segment_len);

    return calculate_checksum(pseudo_packet, total_len);
}

/* Assembles complete 60-byte UDP probe: IP header, UDP header, zero payload */
void build_probe_packet(uint8_t *buf, uint32_t src_addr, uint32_t dst_addr,
                        uint8_t ttl, uint16_t src_port, uint16_t dst_port,
                        uint16_t ip_id)
{
    ip_header_t iph;
    udp_header_t udph;
    const int udp_len = UDP_SEGMENT_LEN;

    memset(buf, 0, PROBE_LEN);

    /* --- IP Header (RFC 791) --- */
    memset(&iph, 0, sizeof(iph));
    iph.ihl_version  = (IPV4_VERSION << IPV4_VERSION_SHIFT) | IPV4_IHL_MIN_WORDS;
    iph.tos          = 0;
    iph.total_length = htons((uint16_t)PROBE_LEN);
    iph.id           = htons(ip_id);
    iph.flags_fo     = 0;
    iph.ttl          = ttl;
    iph.protocol     = IPPROTO_UDP;
    iph.checksum     = 0;
    iph.src_addr     = src_addr;
    iph.dst_addr     = dst_addr;
    iph.checksum     = calculate_checksum(&iph, IP_HEADER_LEN);
    memcpy(buf, &iph, sizeof(iph));

    /* --- UDP Header (RFC 768) --- */
    memset(&udph, 0, sizeof(udph));
    udph.src_port = htons(src_port);
    udph.dst_port = htons(dst_port);
    udph.length   = htons((uint16_t)udp_len);
    udph.checksum = 0;
    memcpy(buf + IP_HEADER_LEN, &udph, sizeof(udph));

    udph.checksum = calculate_udp_checksum(src_addr, dst_addr,
                                           buf + IP_HEADER_LEN, udp_len);
    memcpy(buf + IP_HEADER_LEN, &udph, sizeof(udph));
}

/* Dissects ICMP reply, matching against our PID-derived source port */
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
    reply->type = packet[icmp_off];
    reply->code = packet[icmp_off + 1];
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
