/*
 * ip_header.c - IPv4 header assembly according to RFC 791.
 *
 * Populates each standard IPv4 header field explicitly and calculates
 * the 16-bit header checksum using calculate_checksum().
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "ip_header.h"
#include "checksum.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

void build_ip_header(ip_header_t *iph, uint32_t src_addr, uint32_t dst_addr,
                     uint8_t ttl, uint16_t ip_id, uint16_t payload_len)
{
    memset(iph, 0, sizeof(ip_header_t));

    iph->ihl_version  = (IPV4_VERSION << IPV4_VERSION_SHIFT) | IPV4_IHL_MIN_WORDS;
    iph->tos          = 0;
    iph->total_length = htons((uint16_t)(IP_HEADER_LEN + payload_len));
    iph->id           = htons(ip_id);
    iph->flags_fo     = 0;
    iph->ttl          = ttl;
    iph->protocol     = IPPROTO_UDP;  // 17
    iph->checksum     = 0;
    iph->src_addr     = src_addr;
    iph->dst_addr     = dst_addr;

    iph->checksum     = calculate_checksum(iph, IP_HEADER_LEN);
}
