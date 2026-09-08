/*
 * packet.h - Handcrafted packet crafting and ICMP parsing structures.
 *
 * Structures and utilities to manually assemble probe datagrams (IPv4 + UDP)
 * and parse returned ICMP error replies. Uses byte-packed structures
 * (#pragma pack(push, 1)) and custom RFC 1071 checksum calculations.
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#define IPV4_VERSION            4
#define IPV4_IHL_MIN_WORDS      5
#define IPV4_IHL_MASK           0x0F
#define IPV4_WORD_BYTES         4
#define IPV4_VERSION_SHIFT      4

#define CKSUM_SHIFT             16
#define CKSUM_MASK              0xFFFF

#pragma pack(push, 1)
/* IPv4 Header layout (RFC 791, 20 bytes minimum without options) */
typedef struct {
    uint8_t  ihl_version;   /* 4 bits version + 4 bits IHL (32-bit words) */
    uint8_t  tos;           /* Type of Service / DSCP + ECN */
    uint16_t total_length;  /* Total IP packet length in network byte order */
    uint16_t id;            /* Identification */
    uint16_t flags_fo;      /* 3 bits flags + 13 bits fragment offset */
    uint8_t  ttl;           /* Time To Live: the core mechanism of traceroute */
    uint8_t  protocol;      /* Encapsulated transport protocol (17 = UDP) */
    uint16_t checksum;      /* 16-bit one's complement IP header checksum */
    uint32_t src_addr;      /* Source IPv4 address (network byte order) */
    uint32_t dst_addr;      /* Destination IPv4 address (network byte order) */
} ip_header_t;

/* UDP Header layout (RFC 768, 8 bytes) */
typedef struct {
    uint16_t src_port;      /* Fixed PID-derived port during the run */
    uint16_t dst_port;      /* 33434 + probe sequence number: identifies probe */
    uint16_t length;        /* UDP header + payload length (bytes) */
    uint16_t checksum;      /* Checksum computed over pseudo-header + segment */
} udp_header_t;

/* ICMP Header layout (RFC 792, 8 bytes) */
typedef struct {
    uint8_t  type;          /* ICMP type: 11 = Time Exceeded, 3 = Dest Unreach */
    uint8_t  code;          /* Subcode: 0 = TTL in transit, 3 = Port Unreach */
    uint16_t checksum;      /* ICMP header and payload checksum */
    uint32_t rest;          /* Unused 4 bytes in Type 11 and Type 3 messages */
} icmp_header_t;

/* IPv4 Pseudo-Header for UDP Checksum (RFC 768, 12 bytes) */
typedef struct {
    uint32_t src_addr;      /* Source IP address */
    uint32_t dst_addr;      /* Destination IP address */
    uint8_t  zero;          /* Reserved field, always 0 */
    uint8_t  protocol;      /* IPPROTO_UDP (17) */
    uint16_t udp_length;    /* Length of UDP header + payload */
} pseudo_header_t;
#pragma pack(pop)

#define IP_HEADER_LEN           ((int)sizeof(ip_header_t))    /* 20 */
#define UDP_HEADER_LEN          ((int)sizeof(udp_header_t))   /*  8 */
#define ICMP_HEADER_LEN         ((int)sizeof(icmp_header_t))  /*  8 */
#define PSEUDO_HEADER_LEN       ((int)sizeof(pseudo_header_t)) /* 12 */

/* Total probe datagram size: 20 bytes IP + 8 bytes UDP + 32 zero-padding */
#define PROBE_LEN               60
#define UDP_SEGMENT_LEN         (PROBE_LEN - IP_HEADER_LEN)   /* 40 */
#define UDP_PAYLOAD_LEN         (UDP_SEGMENT_LEN - UDP_HEADER_LEN) /* 32 */

#define UDP_CKSUM_ZERO_SUBSTITUTE 0xFFFF

#define ICMP_TIME_EXCEEDED      11
#define ICMP_DEST_UNREACH        3
#define ICMP_PORT_UNREACH_CODE   3
#define ICMP_TYPE_OFFSET         0
#define ICMP_CODE_OFFSET         1

/*
 * Internet Checksum (RFC 1071), standard algorithm from Lab #05.
 * Reads 16-bit words via memcpy to safely avoid unaligned memory access.
 */
uint16_t calculate_checksum(const void *buffer, int size);

/*
 * Computes UDP checksum over the 12-byte IPv4 pseudo-header (src_addr,
 * dst_addr, zero, protocol, length) followed by the UDP header and payload.
 */
uint16_t calculate_udp_checksum(uint32_t src_addr, uint32_t dst_addr,
                                const void *udp_segment, int udp_segment_len);

/*
 * Assembles a complete 60-byte UDP probe datagram into buf:
 * IP header with current hop TTL, UDP header with destination probe port,
 * 32 bytes of zero padding, and valid precomputed checksums.
 */
void build_probe_packet(uint8_t *buf, uint32_t src_addr, uint32_t dst_addr,
                        uint8_t ttl, uint16_t src_port, uint16_t dst_port,
                        uint16_t ip_id);

/* Relevant fields extracted from an accepted ICMP reply */
typedef struct {
    uint8_t  type;          /* ICMP type (11 or 3) */
    uint8_t  code;          /* ICMP code */
    uint16_t probe_port;    /* Quoted destination port: identifies the probe */
} icmp_reply_t;

/*
 * Dissects an incoming packet received on the raw ICMP socket:
 * skips the outer IP header (using IHL), validates ICMP type/code,
 * and inspects the quoted inner IP and first 8 bytes of the inner UDP header.
 * Returns 1 if the reply matches our source port (demultiplexing), 0 otherwise.
 */
int parse_icmp_reply(const uint8_t *packet, int len, uint16_t src_port,
                     icmp_reply_t *reply);

#endif /* PACKET_H */
