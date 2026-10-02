/*
 * icmp_header.h - ICMP response parsing and structures (RFC 792).
 *
 * Defines the packed binary layout for ICMP headers and the routine
 * to demultiplex Time Exceeded (Type 11) and Destination Unreachable (Type 3)
 * responses by verifying the quoted UDP probe datagram ports.
 */

#ifndef ICMP_HEADER_H
#define ICMP_HEADER_H

#include <stdint.h>

#define ICMP_TIME_EXCEEDED      11
#define ICMP_DEST_UNREACH        3
#define ICMP_NET_UNREACH_CODE        0
#define ICMP_HOST_UNREACH_CODE       1
#define ICMP_PROTO_UNREACH_CODE      2
#define ICMP_PORT_UNREACH_CODE       3
#define ICMP_FRAG_NEEDED_CODE        4
#define ICMP_SRC_ROUTE_FAILED_CODE   5
#define ICMP_NET_UNKNOWN_CODE        6
#define ICMP_HOST_UNKNOWN_CODE       7
#define ICMP_HOST_ISOLATED_CODE      8
#define ICMP_NET_PROHIBITED_CODE     9
#define ICMP_HOST_PROHIBITED_CODE   10
#define ICMP_NET_TOS_CODE           11
#define ICMP_HOST_TOS_CODE          12
#define ICMP_ADMIN_PROHIBITED_CODE  13
#define ICMP_PREC_VIOLATION_CODE    14
#define ICMP_PREC_CUTOFF_CODE       15

/*
 * ICMP header structure (RFC 792), 8 bytes.
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t  type;          /* ICMP message type */
    uint8_t  code;          /* Subtype code */
    uint16_t checksum;      /* ICMP checksum */
    uint32_t rest;          /* Additional data / unused in types 11 and 3 */
} icmp_header_t;
#pragma pack(pop)

#define ICMP_HEADER_LEN         ((int)sizeof(icmp_header_t))

/* Data extracted from a validated ICMP reply */
typedef struct {
    uint8_t  type;          /* ICMP type (11 or 3) */
    uint8_t  code;          /* ICMP code */
    uint16_t probe_port;    /* Quoted destination port identifying the probe */
} icmp_reply_t;

/*
 * Parses a received ICMP packet and verifies if it matches our probe.
 * Returns 1 if valid and matches src_port, 0 otherwise.
 */
int parse_icmp_reply(const uint8_t *packet, int len, uint16_t src_port,
                     icmp_reply_t *reply);

#endif /* ICMP_HEADER_H */

