/*
 * raw_socket.c - Low-level raw socket lifecycle and I/O.
 *
 * Implements raw socket allocation, IP_HDRINCL option configuration,
 * unread input queue draining, and datagram transmission via sendto.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "raw_socket.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int raw_socket_create_send(void)
{
    int fd, on = 1;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        perror("[raw_socket] Error creating raw send socket (are you running as root?)");
        return -1;
    }
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("[raw_socket] Error setting setsockopt(IP_HDRINCL)");
        close(fd);
        return -1;
    }
    return fd;
}

int raw_socket_create_recv(void)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        perror("[raw_socket] Error creating raw ICMP receive socket (are you running as root?)");
        return -1;
    }
    return fd;
}

void raw_socket_drain(int recv_fd)
{
    uint8_t dummy[RECV_BUFFER_SIZE];
    while (recvfrom(recv_fd, dummy, sizeof(dummy), MSG_DONTWAIT, NULL, NULL) > 0) {
    }
}

int raw_socket_send(int send_fd, const void *packet, size_t packet_len,
                    struct in_addr dst_ip)
{
    struct sockaddr_in to;

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr   = dst_ip;

    if (sendto(send_fd, packet, packet_len, 0,
               (struct sockaddr *)&to, sizeof(to)) != (ssize_t)packet_len) {
        return -1;
    }
    return 0;
}

void raw_socket_close(int *fd)
{
    if (fd && *fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

