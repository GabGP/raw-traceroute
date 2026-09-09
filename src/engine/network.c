/*
 * network.c - Network resolution and routing table address discovery.
 *
 * Resolves destination hostnames to IPv4, discovers the local egress source
 * address by connecting a dummy UDP socket, and formats hop address labels.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "network.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int network_resolve_target(const char *host, struct in_addr *dst_addr)
{
    struct addrinfo hints, *res;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != GETADDRINFO_SUCCESS) {
        fprintf(stderr, "traceroute: unknown host %s (%s)\n", host, gai_strerror(rc));
        return NETWORK_ERROR;
    }
    *dst_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return NETWORK_SUCCESS;
}

int network_get_source_addr(struct in_addr dst_addr, struct in_addr *src_addr)
{
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, SOCKET_DEFAULT_PROTOCOL);
    if (fd < 0) {
        return NETWORK_ERROR;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr   = dst_addr;
    sa.sin_port   = htons(ROUTE_DISCOVERY_PORT);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &len) < 0) {
        close(fd);
        return NETWORK_ERROR;
    }
    close(fd);
    *src_addr = sa.sin_addr;
    return NETWORK_SUCCESS;
}

void network_format_addr(struct in_addr addr, int numeric, char *buf, size_t buflen)
{
    char ip[INET_ADDRSTRLEN];
    char host[NI_MAXHOST];
    struct sockaddr_in sa;

    inet_ntop(AF_INET, &addr, ip, sizeof(ip));
    if (numeric) {
        snprintf(buf, buflen, "%s", ip);
        return;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr   = addr;
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host),
                    NULL, GETNAMEINFO_FLAGS_NONE, NI_NAMEREQD) == GETNAMEINFO_SUCCESS) {
        snprintf(buf, buflen, "%s (%s)", host, ip);
    } else {
        snprintf(buf, buflen, "%s (%s)", ip, ip);
    }
}
