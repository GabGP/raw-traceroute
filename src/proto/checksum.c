/*
 * checksum.c - Internet checksum (RFC 1071) calculation and UDP pseudo-header.
 *
 * Implements 16-bit one's complement addition with 32-bit carry folding,
 * and builds temporary IPv4 pseudo-headers for transport checksums.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "checksum.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

uint16_t calculate_checksum(const void *buffer, int size)
{
    const uint16_t *buf = (const uint16_t *)buffer;
    unsigned long sum = 0;

    while (size > CKSUM_ODD_BYTE_LEN) {
        sum += *buf++;
        size -= CKSUM_WORD_BYTES;
    }
    if (size == CKSUM_ODD_BYTE_LEN) {
        sum += *(const uint8_t *)buf;
    }

    while (sum >> CKSUM_SHIFT) {
        sum = (sum & CKSUM_MASK) + (sum >> CKSUM_SHIFT);
    }

    return (uint16_t)(~sum);
}

uint16_t calculate_udp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                const void *udp_segment, int udp_segment_len)
{
    if (udp_segment_len < 0 || udp_segment_len > MAX_UDP_SEGMENT_LEN) {
        return 0;
    }

    int total_len = (int)sizeof(pseudo_header_t) + udp_segment_len;
    uint8_t pseudo_packet[sizeof(pseudo_header_t) + MAX_UDP_SEGMENT_LEN] __attribute__((aligned(4)));

    pseudo_header_t *psh = (pseudo_header_t *)pseudo_packet;
    psh->src_addr   = src_addr;
    psh->dst_addr   = dst_addr;
    psh->zero       = PSEUDO_ZERO_BYTE;
    psh->protocol   = IPPROTO_UDP;
    psh->udp_length = htons((uint16_t)udp_segment_len);

    memcpy(pseudo_packet + sizeof(pseudo_header_t), udp_segment, (size_t)udp_segment_len);

    return calculate_checksum(pseudo_packet, total_len);
}


