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
#define ICMP_PORT_UNREACH_CODE   3
#define ICMP_TYPE_OFFSET         0
#define ICMP_CODE_OFFSET         1
#define IPV4_FIRST_BYTE_OFFSET   0
#define ICMP_PARSE_VALID         1
#define ICMP_PARSE_INVALID       0

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

