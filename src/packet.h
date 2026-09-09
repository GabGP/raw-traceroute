/*
 * packet.h - Datagram facade for probe packet assembly.
 *
 * Exposes protocol header definitions (IPv4, UDP, ICMP, Checksums) and
 * coordinates probe datagram assembly.
 */

#ifndef PACKET_H
#define PACKET_H

#include "checksum.h"
#include "ip_header.h"
#include "udp_header.h"
#include "icmp_header.h"

#define PROBE_LEN        60
#define UDP_SEGMENT_LEN  (PROBE_LEN - IP_HEADER_LEN)        /* 40 */
#define UDP_PAYLOAD_LEN  (UDP_SEGMENT_LEN - UDP_HEADER_LEN) /* 32 */

/* Assembles complete 60-byte UDP probe: IP header + UDP header + 32-byte zeros */
void build_probe_packet(uint8_t *buf, uint32_t src_addr, uint32_t dst_addr,
                        uint8_t ttl, uint16_t src_port, uint16_t dst_port,
                        uint16_t ip_id);

#endif /* PACKET_H */
