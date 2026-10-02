/*
 * ip_header.h - IPv4 packet header structure and utilities (RFC 791).
 *
 * Defines the packed 20-byte structure and header construction routine
 * adapted for traceroute probes (variable TTL and UDP protocol).
 */

#ifndef IP_HEADER_H
#define IP_HEADER_H

#include <stdint.h>

#define IPV4_VERSION            4
#define IPV4_IHL_MIN_WORDS      5
#define IPV4_IHL_MASK           0x0F
#define IPV4_WORD_BYTES         4
#define IPV4_VERSION_SHIFT      4
#define IPV4_DEFAULT_TOS        0
#define IPV4_DEFAULT_FLAGS_FO   0
#define IPV4_INITIAL_CHECKSUM   0
#define IPV4_IHL_VERSION_DEFAULT ((IPV4_VERSION << IPV4_VERSION_SHIFT) | IPV4_IHL_MIN_WORDS)

/*
 * IPv4 header structure (RFC 791), 20 bytes without options.
 * #pragma pack prevents compiler padding between fields.
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t  ihl_version;   /* 4 bits version + 4 bits IHL (length in 32-bit words) */
    uint8_t  tos;           /* Type of Service */
    uint16_t total_length;  /* Total packet length (IP header + payload) in network byte order */
    uint16_t id;            /* Identification field used for fragmentation */
    uint16_t flags_fo;      /* 3 bits flags + 13 bits fragment offset */
    uint8_t  ttl;           /* Time To Live: traceroute hop counter */
    uint8_t  protocol;      /* Transport protocol (17 = UDP) */
    uint16_t checksum;      /* IP header checksum */
    uint32_t src_addr;      /* Source IP address in network byte order */
    uint32_t dst_addr;      /* Destination IP address in network byte order */
} ip_header_t;
#pragma pack(pop)

#define IP_HEADER_LEN           ((int)sizeof(ip_header_t))

/*
 * Populates iph with standard IPv4 header fields for traceroute.
 * payload_len = length of all data following the IP header (UDP header + data).
 * Checksum is calculated automatically via calculate_checksum().
 */
void build_ip_header(ip_header_t *iph, uint32_t src_addr, uint32_t dst_addr,
                     uint8_t ttl, uint16_t ip_id, uint16_t payload_len);

#endif /* IP_HEADER_H */

