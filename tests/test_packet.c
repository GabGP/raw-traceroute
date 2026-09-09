/*
 * test_packet.c - Tier A non-root unit test suite for modular packet engine.
 *
 * Validates RFC 1071 checksum calculations, IPv4 header assembly, UDP header
 * assembly with RFC 768 zero substitution, 60-byte probe construction,
 * and ICMP error reply dissection and defenses.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "../src/checksum.h"
#include "../src/ip_header.h"
#include "../src/udp_header.h"
#include "../src/icmp_header.h"
#include "../src/packet.h"

#define TEST_SAMPLE_TTL          12
#define TEST_SAMPLE_SRC_PORT     45678
#define TEST_SAMPLE_DST_PORT     33434
#define TEST_SAMPLE_IP_ID        999
#define TEST_ICMP_PACKET_LEN     56
#define TEST_TRUNC_OUTER_IP      19
#define TEST_TRUNC_ICMP_HDR      27
#define TEST_TRUNC_INNER_IP      47
#define TEST_TRUNC_INNER_UDP     55

static void test_rfc1071_checksum(void)
{
    /* 1. All zeros yields 0xFFFF */
    uint16_t zeroes[4] = {0, 0, 0, 0};
    assert(calculate_checksum(zeroes, sizeof(zeroes)) == CKSUM_MASK);

    /* 2. Known carry fold: 0xFFFF + 0x0001 -> 0x10000 -> 0x0001 -> ~0x0001 = 0xFFFE */
    uint16_t carry_buf[2] = {0xFFFF, 0x0001};
    assert(calculate_checksum(carry_buf, sizeof(carry_buf)) == 0xFFFE);

    /* 3. Known RFC 1071 Section 3 vector: 0001 f203 f4f5 f6f7 -> 0x220d */
    uint8_t rfc_test[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    assert(calculate_checksum(rfc_test, sizeof(rfc_test)) == htons(0x220d));

    /* 4. Even length vs odd length with trailing zero padding */
    uint8_t even_data[] = {0x12, 0x34, 0x56, 0x00};
    uint8_t odd_data[]  = {0x12, 0x34, 0x56};
    assert(calculate_checksum(even_data, sizeof(even_data)) ==
           calculate_checksum(odd_data, sizeof(odd_data)));
}

static void test_ip_header_builder(void)
{
    ip_header_t iph;
    uint32_t src = inet_addr("192.168.1.50");
    uint32_t dst = inet_addr("8.8.8.8");

    build_ip_header(&iph, src, dst, 64, 1234, UDP_SEGMENT_LEN);

    assert(iph.ihl_version == ((IPV4_VERSION << IPV4_VERSION_SHIFT) | IPV4_IHL_MIN_WORDS));
    assert(iph.tos == 0);
    assert(iph.total_length == htons(PROBE_LEN));
    assert(iph.id == htons(1234));
    assert(iph.flags_fo == 0);
    assert(iph.ttl == 64);
    assert(iph.protocol == IPPROTO_UDP);
    assert(iph.src_addr == src);
    assert(iph.dst_addr == dst);
    assert(iph.checksum != 0);

    /* Verifying checksum over completed header results in zero */
    assert(calculate_checksum(&iph, sizeof(iph)) == 0);
}

static void test_udp_header_builder(void)
{
    udp_header_t udph;
    uint32_t src = inet_addr("10.0.0.1");
    uint32_t dst = inet_addr("10.0.0.2");
    uint8_t payload[32];

    memset(payload, 0xAA, sizeof(payload));
    build_udp_header(&udph, src, dst, 40000, 33434, payload, sizeof(payload));

    assert(udph.src_port == htons(40000));
    assert(udph.dst_port == htons(33434));
    assert(udph.length == htons(UDP_HEADER_LEN + sizeof(payload)));
    assert(udph.checksum != 0);
}

static void test_udp_pseudo_header_checksum(void)
{
    uint8_t buf[PROBE_LEN];
    uint32_t src = inet_addr("192.168.0.1");
    uint32_t dst = inet_addr("8.8.4.4");
    udp_header_t udph;
    uint16_t computed_cksum;

    /* Verify exact 12-byte layout according to RFC 768 / RFC 793 */
    assert(sizeof(pseudo_header_t) == 12);
    assert(offsetof(pseudo_header_t, src_addr) == 0);
    assert(offsetof(pseudo_header_t, dst_addr) == 4);
    assert(offsetof(pseudo_header_t, zero) == 8);
    assert(offsetof(pseudo_header_t, protocol) == 9);
    assert(offsetof(pseudo_header_t, udp_length) == 10);

    build_probe_packet(buf, src, dst, 1, 35000, 33440, 10);
    memcpy(&udph, buf + IP_HEADER_LEN, sizeof(udph));
    assert(udph.checksum != 0);

    /* Recalculating directly with calculate_udp_checksum should match */
    computed_cksum = calculate_udp_checksum(src, dst, buf + IP_HEADER_LEN,
                                            UDP_SEGMENT_LEN);
    assert(computed_cksum == 0);

    /* Negative or oversized length guards */
    assert(calculate_udp_checksum(src, dst, buf, -1) == 0);
    assert(calculate_udp_checksum(src, dst, buf, 2000) == 0);
}

static void test_probe_packet_crafting(void)
{
    uint8_t buf[PROBE_LEN];
    uint32_t src = inet_addr("10.0.0.2");
    uint32_t dst = inet_addr("1.1.1.1");
    uint8_t ttl = TEST_SAMPLE_TTL;
    uint16_t src_port = TEST_SAMPLE_SRC_PORT;
    uint16_t dst_port = TEST_SAMPLE_DST_PORT;
    uint16_t ip_id = TEST_SAMPLE_IP_ID;
    ip_header_t iph;
    udp_header_t udph;
    int i;

    build_probe_packet(buf, src, dst, ttl, src_port, dst_port, ip_id);

    /* Verify IPv4 header */
    memcpy(&iph, buf, sizeof(iph));
    assert(iph.ihl_version == ((IPV4_VERSION << IPV4_VERSION_SHIFT) | IPV4_IHL_MIN_WORDS));
    assert(iph.tos == 0);
    assert(iph.total_length == htons(PROBE_LEN));
    assert(iph.id == htons(ip_id));
    assert(iph.flags_fo == 0);
    assert(iph.ttl == ttl);
    assert(iph.protocol == IPPROTO_UDP);
    assert(iph.src_addr == src);
    assert(iph.dst_addr == dst);
    assert(calculate_checksum(&iph, sizeof(iph)) == 0);

    /* Verify UDP header */
    memcpy(&udph, buf + IP_HEADER_LEN, sizeof(udph));
    assert(udph.src_port == htons(src_port));
    assert(udph.dst_port == htons(dst_port));
    assert(udph.length == htons(UDP_SEGMENT_LEN));
    assert(udph.checksum != 0);

    /* Verify payload zero padding */
    for (i = IP_HEADER_LEN + UDP_HEADER_LEN; i < PROBE_LEN; i++) {
        assert(buf[i] == 0x00);
    }
}

static void test_icmp_reply_parsing(void)
{
    uint8_t packet[128];
    ip_header_t outer_ip, inner_ip;
    icmp_header_t icmp;
    udp_header_t inner_udp;
    icmp_reply_t reply;
    uint16_t my_src_port = 38000;
    uint16_t probe_dst_port = 33450;
    int pkt_len;

    /* Build outer IP */
    memset(&outer_ip, 0, sizeof(outer_ip));
    outer_ip.ihl_version = (IPV4_VERSION << IPV4_VERSION_SHIFT) | IPV4_IHL_MIN_WORDS;
    outer_ip.protocol = IPPROTO_ICMP;
    outer_ip.total_length = htons(TEST_ICMP_PACKET_LEN);
    outer_ip.src_addr = inet_addr("10.0.0.1");
    outer_ip.dst_addr = inet_addr("192.168.1.100");

    /* Build ICMP Time Exceeded */
    memset(&icmp, 0, sizeof(icmp));
    icmp.type = ICMP_TIME_EXCEEDED;
    icmp.code = 0;

    /* Build inner quoted IP */
    memset(&inner_ip, 0, sizeof(inner_ip));
    inner_ip.ihl_version = (IPV4_VERSION << IPV4_VERSION_SHIFT) | IPV4_IHL_MIN_WORDS;
    inner_ip.protocol = IPPROTO_UDP;
    inner_ip.src_addr = inet_addr("192.168.1.100");
    inner_ip.dst_addr = inet_addr("8.8.8.8");

    /* Build inner quoted UDP */
    memset(&inner_udp, 0, sizeof(inner_udp));
    inner_udp.src_port = htons(my_src_port);
    inner_udp.dst_port = htons(probe_dst_port);
    inner_udp.length = htons(UDP_SEGMENT_LEN);

    /* Assemble synthetic packet */
    memcpy(packet, &outer_ip, sizeof(outer_ip));
    memcpy(packet + IP_HEADER_LEN, &icmp, sizeof(icmp));
    memcpy(packet + IP_HEADER_LEN + ICMP_HEADER_LEN, &inner_ip, sizeof(inner_ip));
    memcpy(packet + IP_HEADER_LEN + ICMP_HEADER_LEN + IP_HEADER_LEN, &inner_udp, sizeof(inner_udp));
    pkt_len = TEST_ICMP_PACKET_LEN;

    /* 1. Valid Time Exceeded reply */
    memset(&reply, 0, sizeof(reply));
    assert(parse_icmp_reply(packet, pkt_len, my_src_port, &reply) == 1);
    assert(reply.type == ICMP_TIME_EXCEEDED);
    assert(reply.code == 0);
    assert(reply.probe_port == probe_dst_port);

    /* 2. Valid Destination Unreachable reply */
    packet[IP_HEADER_LEN] = ICMP_DEST_UNREACH;
    packet[IP_HEADER_LEN + 1] = ICMP_PORT_UNREACH_CODE;
    memset(&reply, 0, sizeof(reply));
    assert(parse_icmp_reply(packet, pkt_len, my_src_port, &reply) == 1);
    assert(reply.type == ICMP_DEST_UNREACH);
    assert(reply.code == ICMP_PORT_UNREACH_CODE);
    assert(reply.probe_port == probe_dst_port);

    /* 3. Foreign traffic rejection (different source port) */
    inner_udp.src_port = htons(my_src_port + 1);
    memcpy(packet + IP_HEADER_LEN + ICMP_HEADER_LEN + IP_HEADER_LEN, &inner_udp, sizeof(inner_udp));
    assert(parse_icmp_reply(packet, pkt_len, my_src_port, &reply) == 0);

    /* Restore source port */
    inner_udp.src_port = htons(my_src_port);
    memcpy(packet + IP_HEADER_LEN + ICMP_HEADER_LEN + IP_HEADER_LEN, &inner_udp, sizeof(inner_udp));

    /* 4. Foreign ICMP type rejection (e.g. ICMP Echo Reply Type 0) */
    packet[IP_HEADER_LEN] = 0;
    assert(parse_icmp_reply(packet, pkt_len, my_src_port, &reply) == 0);
    packet[IP_HEADER_LEN] = ICMP_TIME_EXCEEDED;

    /* 5. Non-UDP inner protocol rejection (e.g. TCP inner) */
    inner_ip.protocol = IPPROTO_TCP;
    memcpy(packet + IP_HEADER_LEN + ICMP_HEADER_LEN, &inner_ip, sizeof(inner_ip));
    assert(parse_icmp_reply(packet, pkt_len, my_src_port, &reply) == 0);
    inner_ip.protocol = IPPROTO_UDP;
    memcpy(packet + IP_HEADER_LEN + ICMP_HEADER_LEN, &inner_ip, sizeof(inner_ip));

    /* 6. Truncated packet defenses */
    assert(parse_icmp_reply(packet, TEST_TRUNC_OUTER_IP, my_src_port, &reply) == 0);
    assert(parse_icmp_reply(packet, TEST_TRUNC_ICMP_HDR, my_src_port, &reply) == 0);
    assert(parse_icmp_reply(packet, TEST_TRUNC_INNER_IP, my_src_port, &reply) == 0);
    assert(parse_icmp_reply(packet, TEST_TRUNC_INNER_UDP, my_src_port, &reply) == 0);
}

int main(void)
{
    printf("=== Running Tier A Unit Tests (Modular Protocol Engine) ===\n");

    test_rfc1071_checksum();
    printf("  [PASS] RFC 1071 checksum & carry wraparound\n");

    test_ip_header_builder();
    printf("  [PASS] IPv4 header builder & RFC 791 validation\n");

    test_udp_header_builder();
    printf("  [PASS] UDP header builder & RFC 768 validation\n");

    test_udp_pseudo_header_checksum();
    printf("  [PASS] UDP pseudo-header checksum calculation\n");

    test_probe_packet_crafting();
    printf("  [PASS] Handcrafted 60-byte probe facade assembly\n");

    test_icmp_reply_parsing();
    printf("  [PASS] ICMP reply parsing, demuxing & bounds defense\n");

    printf("OK: All Tier A unit tests passed successfully!\n");
    return 0;
}
