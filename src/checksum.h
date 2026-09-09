/*
 * checksum.h - RFC 1071 Internet Checksum and UDP pseudo-header calculations.
 *
 * Provides one's complement Internet checksum computation and IPv4
 * pseudo-header checksum generation for transport-layer validation.
 */

#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>

#define CKSUM_SHIFT             16
#define CKSUM_MASK              0xFFFF

#pragma pack(push, 1)
/* IPv4 Pseudo-Header for UDP Checksum (RFC 768, 12 bytes) */
typedef struct {
    uint32_t src_addr;      /* Source IPv4 address */
    uint32_t dst_addr;      /* Destination IPv4 address */
    uint8_t  zero;          /* Fixed to 0 */
    uint8_t  protocol;      /* IPPROTO_UDP (17) */
    uint16_t udp_length;    /* Length of UDP header + payload */
} pseudo_header_t;
#pragma pack(pop)

#define PSEUDO_HEADER_LEN       ((int)sizeof(pseudo_header_t))

/* Computes standard RFC 1071 one's complement Internet checksum */
uint16_t calculate_checksum(const void *buffer, int size);

/* Computes UDP checksum over 12-byte IPv4 pseudo-header + UDP segment */
uint16_t calculate_udp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                const void *udp_segment, int udp_segment_len);

#endif /* CHECKSUM_H */
