/*
 * udp_header.h - UDP header structure and utilities (RFC 768).
 *
 * Defines the packed 8-byte structure and constructor function
 * with checksum computation over the IPv4 pseudo-header.
 */

#ifndef UDP_HEADER_H
#define UDP_HEADER_H

#include <stdint.h>

/*
 * UDP header structure (RFC 768), 8 bytes.
 */
#pragma pack(push, 1)
typedef struct {
    uint16_t src_port;      /* PID-derived source port */
    uint16_t dst_port;      /* Destination port (33434 + probe index) */
    uint16_t length;        /* Total UDP length (header + payload) */
    uint16_t checksum;      /* UDP checksum (RFC 768) */
} udp_header_t;
#pragma pack(pop)

#define UDP_HEADER_LEN            ((int)sizeof(udp_header_t))
#define UDP_CKSUM_ZERO_SUBSTITUTE 0xFFFF
#define UDP_INITIAL_CHECKSUM      0
#define UDP_CKSUM_COMPUTED_ZERO   0

/*
 * Populates udph with standard UDP header values.
 * Computes the checksum including the IP pseudo-header per RFC 768.
 */
void build_udp_header(udp_header_t *udph, uint32_t src_addr, uint32_t dst_addr,
                      uint16_t src_port, uint16_t dst_port,
                      const void *payload, uint16_t payload_len);

#endif /* UDP_HEADER_H */

