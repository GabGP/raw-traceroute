/*
 * packet.c - Datagram facade for 60-byte UDP probe packet construction.
 *
 * Coordinates IPv4 and UDP header builders to assemble the complete
 * on-the-wire probe datagram (IP header + UDP header + 32 zero-bytes).
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "packet.h"

#include <string.h>

void build_probe_packet(uint8_t *buf, uint32_t src_addr, uint32_t dst_addr,
                        uint8_t ttl, uint16_t src_port, uint16_t dst_port,
                        uint16_t ip_id)
{
    ip_header_t iph;
    udp_header_t udph;
    uint8_t payload[UDP_PAYLOAD_LEN];

    memset(buf, 0, PROBE_LEN);
    memset(payload, 0, sizeof(payload));

    build_udp_header(&udph, src_addr, dst_addr, src_port, dst_port,
                     payload, sizeof(payload));
    build_ip_header(&iph, src_addr, dst_addr, ttl, ip_id, UDP_SEGMENT_LEN);

    memcpy(buf, &iph, sizeof(iph));
    memcpy(buf + IP_HEADER_LEN, &udph, sizeof(udph));
    memcpy(buf + IP_HEADER_LEN + UDP_HEADER_LEN, payload, sizeof(payload));
}
