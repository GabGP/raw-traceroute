/*
 * network.h - Network resolution and address formatting interface.
 *
 * Declares functions for IPv4 DNS resolution via getaddrinfo(), local egress
 * IP discovery via kernel routing table, and formatted address labeling.
 */

#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* Room for "hostname (ip)": name + IPv4 text + " (" + ")" + NUL */
#define LABEL_BUFFER_SIZE    (NI_MAXHOST + INET_ADDRSTRLEN + 4)

/* Resolves destination host string to an IPv4 in_addr. Returns 0 on success, -1 on error. */
int network_resolve_target(const char *host, struct in_addr *dst_addr);

/* Determines local source IP address using the kernel routing table. Returns 0 on success, -1 on error. */
int network_get_source_addr(struct in_addr dst_addr, struct in_addr *src_addr);

/* Formats output label: "hostname (ip)" or bare "ip" if numeric. */
void network_format_addr(struct in_addr addr, int numeric, char *buf, size_t buflen);

#endif /* NETWORK_H */
