/* socket.h */
#ifndef _SOCKET_H
#define _SOCKET_H

int read_interface(char *interface, int *ifindex, unsigned long *addr, char *arp);
int listen_socket(unsigned int ip, int port, char *inf);
int raw_socket(int ifindex);

#endif
