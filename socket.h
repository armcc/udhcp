/* socket.h */
#ifndef _SOCKET_H
#define _SOCKET_H

int serverSocket(short listen_port);
int send_packet(struct dhcpMessage *payload, int force_broadcast);

#endif