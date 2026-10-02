/*
 * ip_header.c - IPv4 header construction according to RFC 791.
 *
 * Populates IPv4 binary header fields (network byte order, as Linux raw
 * sockets with IP_HDRINCL expect) and calculates the IP header checksum.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "ip_header.h"
#include "checksum.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

void build_ip_header(ip_header_t *iph, uint32_t src_addr, uint32_t dst_addr,
                     uint8_t ttl, uint16_t ip_id, uint16_t payload_len) {
    memset(iph, 0, sizeof(ip_header_t));

    iph->ihl_version   = IPV4_IHL_VERSION_DEFAULT;
    iph->tos           = IPV4_DEFAULT_TOS;

    iph->total_length  = htons((uint16_t)(sizeof(ip_header_t) + payload_len));
    iph->flags_fo      = IPV4_DEFAULT_FLAGS_FO;

    iph->id            = htons(ip_id);
    iph->ttl           = ttl;
    iph->protocol      = IPPROTO_UDP;
    iph->checksum      = IPV4_INITIAL_CHECKSUM;
    iph->src_addr      = src_addr;
    iph->dst_addr      = dst_addr;

    iph->checksum      = calculate_checksum(iph, sizeof(ip_header_t));
}

