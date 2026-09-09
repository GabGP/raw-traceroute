/*
 * raw_socket.h - Low-level raw socket operations (Lab 05 pattern).
 *
 * Encapsulates raw socket creation, IP_HDRINCL options, non-blocking queue
 * drainage, datagram transmission, and descriptor lifecycle management.
 */

#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

#include <stddef.h>
#include <netinet/in.h>

#define RECV_BUFFER_SIZE 2048

/* Creates raw send socket with IP_HDRINCL */
int raw_socket_create_send(void);

/* Creates raw receive socket for ICMP */
int raw_socket_create_recv(void);

/* Drains any queued stale packets from the receive socket */
void raw_socket_drain(int recv_fd);

/* Sends raw IPv4 datagram to target destination */
int raw_socket_send(int send_fd, const void *packet, size_t packet_len,
                    struct in_addr dst_ip);

/* Safely closes socket descriptor */
void raw_socket_close(int *fd);

#endif /* RAW_SOCKET_H */
