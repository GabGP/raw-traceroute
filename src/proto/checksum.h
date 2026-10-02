/*
 * checksum.h - Internet checksum (RFC 1071) and UDP pseudo-header.
 *
 * Provides an accumulating one's complement sum (so a checksum can span
 * several buffers without copying them) and the UDP checksum of RFC 768.
 */

#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

#include "udp_header.h"

#pragma pack(push, 1)
/* IPv4 pseudo-header for UDP checksum calculation (RFC 768, 12 bytes) */
typedef struct {
    uint32_t src_addr;      /* Source IP address */
    uint32_t dst_addr;      /* Destination IP address */
    uint8_t  zero;          /* Fixed zero byte */
    uint8_t  protocol;      /* IPPROTO_UDP (17) */
    uint16_t udp_length;    /* UDP header length + payload length */
} pseudo_header_t;
#pragma pack(pop)

#define PSEUDO_HEADER_LEN       ((int)sizeof(pseudo_header_t))

/*
 * Adds 'len' bytes of 'data' to the running 16-bit one's complement sum
 * 'sum' (start with 0) and returns the new partial sum. Carries are folded
 * later by checksum_finish(). Words are read in host order, as RFC 1071
 * allows. Only the LAST chunk may have odd length: a trailing odd byte is
 * treated as if padded with a zero byte.
 */
uint32_t checksum_add(uint32_t sum, const void *data, size_t len);

/* Folds the carries of a partial sum into 16 bits and complements it. */
uint16_t checksum_finish(uint32_t sum);

/*
 * Internet checksum (RFC 1071) of one contiguous buffer, e.g. an IPv4 header.
 * Equivalent to checksum_finish(checksum_add(0, buffer, size)).
 */
uint16_t calculate_checksum(const void *buffer, int size);

/*
 * UDP checksum (RFC 768) over the IPv4 pseudo-header, the UDP header and the
 * payload, summed in place without building a temporary segment.
 * The header is summed as given: zero udph->checksum first to compute a
 * checksum, or leave the sent value to verify (a valid segment yields 0).
 * src_addr and dst_addr must be in network byte order.
 * Returns 0 if header + payload would not fit the 16-bit UDP length field.
 */
uint16_t calculate_udp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                const udp_header_t *udph,
                                const void *payload, uint16_t payload_len);

#endif /* CHECKSUM_H */
