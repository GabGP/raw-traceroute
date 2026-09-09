/*
 * checksum.h - Internet checksum (RFC 1071) and UDP pseudo-header.
 *
 * Provides one's complement checksum calculation and IPv4 pseudo-header
 * construction for UDP datagrams (RFC 768).
 */

#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

#define CKSUM_SHIFT             16
#define CKSUM_MASK              0xFFFF
#define CKSUM_WORD_BYTES        2
#define CKSUM_ODD_BYTE_LEN      1
#define PSEUDO_ZERO_BYTE        0
#define MAX_UDP_SEGMENT_LEN     1480

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
 * Generic Internet checksum calculation (RFC 1071).
 * Used for IPv4 headers and, together with the pseudo-header, UDP datagrams.
 * 'buffer' must point to data of size 'size' in bytes.
 */
uint16_t calculate_checksum(const void *buffer, int size);

/*
 * Computes UDP checksum over the UDP segment and IPv4 pseudo-header
 * (source IP, destination IP, protocol, length) as mandated by RFC 768.
 * udp_segment points to the UDP header followed by payload,
 * and udp_segment_len is its total length (header + payload).
 * src_addr and dst_addr must already be in network byte order.
 */
uint16_t calculate_udp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                const void *udp_segment, int udp_segment_len);

#endif /* CHECKSUM_H */

