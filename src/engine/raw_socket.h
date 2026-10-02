/*
 * raw_socket.h - Low-level operations for raw sockets.
 *
 * Encapsulates raw socket creation with IP_HDRINCL for sending,
 * raw ICMP socket creation for receiving, queue draining, and transmission.
 */

#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H

#include <stddef.h>
#include <netinet/in.h>

#define RECV_BUFFER_SIZE        2048

/*
 * Creates the raw sending socket with IP_HDRINCL enabled.
 * Requires root/sudo privileges.
 * Returns the socket descriptor or -1 on error.
 */
int raw_socket_create_send(void);

/*
 * Creates the raw receiving socket for ICMP datagrams.
 * Requires root/sudo privileges.
 * Returns the socket descriptor or -1 on error.
 */
int raw_socket_create_recv(void);

/*
 * Drains unread incoming packets accumulated in the receive socket buffer.
 */
void raw_socket_drain(int recv_fd);

/*
 * Transmits a complete datagram (IP header + payload) to the destination address.
 * Returns 0 on success, or -1 on error.
 */
int raw_socket_send(int send_fd, const void *packet, size_t packet_len,
                    struct in_addr dst_ip);

/*
 * Safely closes the socket and resets the descriptor to -1.
 */
void raw_socket_close(int *fd);

#endif /* RAW_SOCKET_H */

