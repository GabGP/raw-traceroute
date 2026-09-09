/*
 * icmp_header.h - ICMP binary header definitions and reply parser.
 *
 * Defines packed binary layout for standard 8-byte ICMP headers (RFC 792)
 * and declares dissection and probe correlation parsing routines.
 */

#ifndef ICMP_HEADER_H
#define ICMP_HEADER_H

#include <stdint.h>

#define ICMP_TIME_EXCEEDED      11
#define ICMP_DEST_UNREACH        3
#define ICMP_PORT_UNREACH_CODE   3
#define ICMP_TYPE_OFFSET         0
#define ICMP_CODE_OFFSET         1

#pragma pack(push, 1)
/* ICMP Header layout (RFC 792, 8 bytes) */
typedef struct {
    uint8_t  type;          /* ICMP message type */
    uint8_t  code;          /* Subtype code */
    uint16_t checksum;      /* Checksum */
    uint32_t rest;          /* Unused / Gateway header data */
} icmp_header_t;
#pragma pack(pop)

#define ICMP_HEADER_LEN         ((int)sizeof(icmp_header_t))

/* Relevant fields extracted from an accepted ICMP reply */
typedef struct {
    uint8_t  type;          /* ICMP type (11 or 3) */
    uint8_t  code;          /* ICMP code */
    uint16_t probe_port;    /* Quoted destination port: identifies the probe */
} icmp_reply_t;

/* Dissects incoming ICMP packet and matches inner UDP probe port */
int parse_icmp_reply(const uint8_t *packet, int len, uint16_t src_port,
                     icmp_reply_t *reply);

#endif /* ICMP_HEADER_H */
