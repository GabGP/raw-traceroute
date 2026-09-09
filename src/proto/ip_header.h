/*
 * ip_header.h - IPv4 binary packet header definitions and construction.
 *
 * Defines packed binary layout for standard 20-byte IPv4 headers (RFC 791)
 * and declares header assembly routines.
 */

#ifndef IP_HEADER_H
#define IP_HEADER_H

#include <stdint.h>

#define IPV4_VERSION            4
#define IPV4_IHL_MIN_WORDS      5
#define IPV4_IHL_MASK           0x0F
#define IPV4_WORD_BYTES         4
#define IPV4_VERSION_SHIFT      4

#pragma pack(push, 1)
/* IPv4 Header layout (RFC 791, 20 bytes minimum without options) */
typedef struct {
    uint8_t  ihl_version;   /* 4 bits version + 4 bits IHL */
    uint8_t  tos;           /* Type of Service / DSCP + ECN */
    uint16_t total_length;  /* Total length (IP header + payload) in network byte order */
    uint16_t id;            /* Identification */
    uint16_t flags_fo;      /* Flags and fragment offset */
    uint8_t  ttl;           /* Time To Live */
    uint8_t  protocol;      /* IPPROTO_UDP (17) */
    uint16_t checksum;      /* Header checksum */
    uint32_t src_addr;      /* Source IP (network byte order) */
    uint32_t dst_addr;      /* Destination IP (network byte order) */
} ip_header_t;
#pragma pack(pop)

#define IP_HEADER_LEN           ((int)sizeof(ip_header_t))

/* Explicitly populates all RFC 791 fields and calculates IP header checksum */
void build_ip_header(ip_header_t *iph, uint32_t src_addr, uint32_t dst_addr,
                     uint8_t ttl, uint16_t ip_id, uint16_t payload_len);

#endif /* IP_HEADER_H */
