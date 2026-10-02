/*
 * checksum.c - Internet checksum (RFC 1071) calculation and UDP pseudo-header.
 *
 * Implements 16-bit one's complement addition with 32-bit carry folding,
 * and builds temporary IPv4 pseudo-headers for transport checksums.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "checksum.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

uint32_t checksum_add(uint32_t sum, const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint16_t word;

    while (len > 1) {
        memcpy(&word, bytes, sizeof(word)); /* alignment-safe 16-bit read */
        sum += word;
        bytes += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += *bytes; /* odd trailing byte: zero-padded word */
    }
    return sum;
}

uint16_t checksum_finish(uint32_t sum)
{
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

uint16_t calculate_checksum(const void *buffer, int size)
{
    return checksum_finish(checksum_add(0, buffer, (size_t)size));
}

uint16_t calculate_udp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                const udp_header_t *udph,
                                const void *payload, uint16_t payload_len)
{
    pseudo_header_t psh;
    uint32_t udp_len = (uint32_t)UDP_HEADER_LEN + payload_len;
    uint32_t sum;

    if (udp_len > UINT16_MAX) {
        return 0;
    }

    psh.src_addr   = src_addr;
    psh.dst_addr   = dst_addr;
    psh.zero       = 0;
    psh.protocol   = IPPROTO_UDP;
    psh.udp_length = htons((uint16_t)udp_len);

    sum = checksum_add(0, &psh, sizeof(psh));
    sum = checksum_add(sum, udph, sizeof(*udph));
    sum = checksum_add(sum, payload, payload_len); /* only chunk that may be odd */
    return checksum_finish(sum);
}
