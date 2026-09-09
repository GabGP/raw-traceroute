/*
 * udp_header.h - UDP binary header definitions and construction.
 *
 * Defines packed binary layout for standard 8-byte UDP headers (RFC 768)
 * and declares header assembly and checksum routines.
 */

#ifndef UDP_HEADER_H
#define UDP_HEADER_H

#include <stdint.h>

#pragma pack(push, 1)
/* UDP Header layout (RFC 768, 8 bytes) */
typedef struct {
    uint16_t src_port;      /* PID-derived source port */
    uint16_t dst_port;      /* Probe destination port (33434+) */
    uint16_t length;        /* UDP header + payload length */
    uint16_t checksum;      /* UDP checksum (RFC 768) */
} udp_header_t;
#pragma pack(pop)

#define UDP_HEADER_LEN            ((int)sizeof(udp_header_t))
#define UDP_CKSUM_ZERO_SUBSTITUTE 0xFFFF

/* Builds UDP header, calculates checksum with pseudo-header, applies RFC 768 zero-rule */
void build_udp_header(udp_header_t *udph, uint32_t src_addr, uint32_t dst_addr,
                      uint16_t src_port, uint16_t dst_port,
                      const void *payload, uint16_t payload_len);

#endif /* UDP_HEADER_H */
