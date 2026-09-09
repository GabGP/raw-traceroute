/*
 * checksum.c - RFC 1071 Internet Checksum implementation.
 *
 * Implements 16-bit one's complement addition with 32-bit carry folding
 * and UDP pseudo-header checksum generation according to RFC 768 / RFC 1071.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "checksum.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_PSEUDO_SEGMENT_LEN 1480

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
    if (size == 1) {
        uint16_t odd = 0;
        memcpy(&odd, p, 1);
        sum += odd;
    }

    while (sum >> CKSUM_SHIFT) {
        sum = (sum & CKSUM_MASK) + (sum >> CKSUM_SHIFT);
    }

    return (uint16_t)(~sum);
}

uint16_t calculate_udp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                const void *udp_segment, int udp_segment_len)
{
    uint8_t pseudo_packet[sizeof(pseudo_header_t) + MAX_PSEUDO_SEGMENT_LEN];
    pseudo_header_t psh;
    int total_len;

    if (udp_segment_len < 0 || udp_segment_len > MAX_PSEUDO_SEGMENT_LEN) {
        return 0;
    }
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
