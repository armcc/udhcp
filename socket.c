/* socket.c -- DHCP server client/server socket creation */

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
/*
#ifndef EMBED
#include <sys/ioctl.h>
#endif
*/

int serverSocket(short listen_port) {
        int server_socket;
        struct sockaddr_in server;
        int n = 1;

        server_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(server_socket == -1)
                return -1;

        bzero(&server, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons(listen_port);
        server.sin_addr.s_addr = INADDR_ANY;

        if(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char *) &n, sizeof(n)) == -1)
		return -1;
        if(bind(server_socket, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
                return -1;

        return server_socket;
}


int clientSocket(short send_from_port, short send_to_port) {
        int n = 1;
        int client_socket;
        struct sockaddr_in client;

        client_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(client_socket == -1)
                return -1;

        if (setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, (char *) &n, sizeof(n)) == -1)
		return -1;

        setsockopt(client_socket, SOL_SOCKET, SO_BROADCAST, (char *) &n, sizeof(n));
        bzero(&client, sizeof(client));
        client.sin_family = AF_INET;
        client.sin_port = htons(send_from_port);
        client.sin_addr.s_addr = INADDR_ANY;

        if(bind(client_socket,(struct sockaddr *)&client, sizeof(struct sockaddr))==-1)
                return -1;

        bzero(&client, sizeof(client));
        client.sin_family = AF_INET;
        client.sin_port = htons(send_to_port);
        client.sin_addr.s_addr = INADDR_BROADCAST;

        if(connect(client_socket, (struct sockaddr *)&client, sizeof(struct sockaddr)) == -1)
                return -1;

        return client_socket;
}
