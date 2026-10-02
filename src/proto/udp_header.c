/*
 * udp_header.c - UDP header construction according to RFC 768.
 *
 * Populates UDP header fields, computes transport checksum using IPv4
 * pseudo-header, and applies RFC 768 zero-checksum substitution (0x0000 -> 0xFFFF).
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "udp_header.h"
#include "checksum.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

void build_udp_header(udp_header_t *udph, uint32_t src_addr, uint32_t dst_addr,
                      uint16_t src_port, uint16_t dst_port,
                      const void *payload, uint16_t payload_len)
{
    uint16_t cksum;

    memset(udph, 0, sizeof(udp_header_t)); /* checksum field must be 0 while summing */
    udph->src_port = htons(src_port);
    udph->dst_port = htons(dst_port);
    udph->length   = htons((uint16_t)(UDP_HEADER_LEN + payload_len));

    cksum = calculate_udp_checksum(src_addr, dst_addr, udph, payload, payload_len);
    /* RFC 768: If computed checksum is 0, it is transmitted as all ones (0xFFFF) */
    if (cksum == 0) {
        cksum = UDP_CKSUM_ZERO_SUBSTITUTE;
    }
    udph->checksum = cksum;
}
