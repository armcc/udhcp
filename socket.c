/*
 * socket.c -- DHCP server client/server socket creation
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 */

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
#include <net/if.h>
#include <sys/socket.h>
#if __GLIBC__ >=2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif
#include <errno.h>
#include "debug.h"
#include "dhcpd.h"
#include "files.h"
#include "options.h"
#include "leases.h"

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


static u_int16_t checksum(void *addr, int count)
{
	/* Compute Internet Checksum for "count" bytes
	 *         beginning at location "addr".
	 */
	register int32_t sum = 0;
	u_int16_t *source = (u_int16_t *) addr;

	while( count > 1 )  {
		/*  This is the inner loop */
		sum += *source++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if( count > 0 )
		sum += * (unsigned char *) source;

	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}


/* send a packet to giaddr using the kernel ip stack */
static int send_packet_to_relay(struct dhcpMessage *payload, int payload_length)
{
	int n = 1;
	int fd, result;
	struct sockaddr_in client;
	
	DEBUG(LOG_INFO, "Forwarding packet to relay");

	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return -1;
	
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &n, sizeof(n)) == -1)
		return -1;

	memset(&client, 0, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_port = htons(SERVER_PORT);
	client.sin_addr.s_addr = config.server;

	if (bind(fd, (struct sockaddr *)&client, sizeof(struct sockaddr)) == -1)
		return -1;

	memset(&client, 0, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_port = htons(SERVER_PORT);
	client.sin_addr.s_addr = payload->giaddr; 

	if (connect(fd, (struct sockaddr *)&client, sizeof(struct sockaddr)) == -1)
		return -1;

	result = write(fd, payload, payload_length);
	close(fd);
	return result;
}


/* send a packet to a specific arp address and ip address by creating our own ip packet */
static int send_packet_to_client(struct dhcpMessage *payload, int payload_length, int force_broadcast)
{
	int fd;
	int result;
	struct sockaddr_ll dest;
	struct udp_dhcp_packet packet;
	u_int32_t ciaddr;
	char chaddr[6];
	
	if (force_broadcast) {
		DEBUG(LOG_INFO, "broadcasting packet to client (NAK)");
		ciaddr = INADDR_BROADCAST;
		memcpy(chaddr, MAC_BCAST_ADDR, 6);		
	} else if (payload->ciaddr) {
		DEBUG(LOG_INFO, "unicasting packet to client ciaddr");
		ciaddr = payload->ciaddr;
		memcpy(chaddr, payload->chaddr, 6);
	} else if (ntohs(payload->flags) & BROADCAST_FLAG) {
		DEBUG(LOG_INFO, "broadcasting packet to client (requested)");
		ciaddr = INADDR_BROADCAST;
		memcpy(chaddr, MAC_BCAST_ADDR, 6);		
	} else {
		DEBUG(LOG_INFO, "unicasting packet to client yiaddr");
		ciaddr = payload->yiaddr;
		memcpy(chaddr, payload->chaddr, 6);
	}
		
	
	if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
		DEBUG(LOG_ERR, "socket call failed: %s", sys_errlist[errno]);
		return -1;
	}
	
	memset(&dest, 0, sizeof(dest));
	memset(&packet, 0, sizeof(packet));
	
	dest.sll_family = AF_PACKET;
	dest.sll_protocol = htons(ETH_P_IP);
	dest.sll_ifindex = config.ifindex;
	dest.sll_halen = 6;
	memcpy(dest.sll_addr, chaddr, 6);
	if (bind(fd, (struct sockaddr *)&dest, sizeof(struct sockaddr_ll)) < 0) {
		DEBUG(LOG_ERR, "bind call failed: %s", sys_errlist[errno]);
		close(fd);
		return -1;
	}

	packet.ip.protocol = IPPROTO_UDP;
	packet.ip.saddr = config.server;
	packet.ip.daddr = ciaddr;
	packet.ip.tot_len = htons(sizeof(packet.udp) + payload_length); /* cheat on the psuedo-header */
	packet.udp.source = htons(SERVER_PORT);
	packet.udp.dest = htons(CLIENT_PORT);
	packet.udp.len = htons(sizeof(packet.udp) + payload_length);
	memcpy(&(packet.data), payload, payload_length);
	packet.udp.check = checksum(&packet, sizeof(packet.ip) + sizeof(packet.udp) + payload_length);
	
	packet.ip.tot_len = htons(sizeof(packet.ip) + sizeof(packet.udp) + payload_length);
	packet.ip.ihl = sizeof(packet.ip) >> 2;
	packet.ip.version = IPVERSION;
	packet.ip.ttl = IPDEFTTL;
	packet.ip.check = checksum(&(packet.ip), sizeof(packet.ip));

	result = sendto(fd, &packet, ntohs(packet.ip.tot_len), 0, (struct sockaddr *) &dest, sizeof(dest));
	if (result <= 0) {
		DEBUG(LOG_ERR, "write on socket failed: %s", sys_errlist[errno]);
	}
	close(fd);
	return result;
}


/* send a dhcp packet, if force broadcast is set, the packet will be broadcast to the client */
int send_packet(struct dhcpMessage *payload, int force_broadcast)
{
	int ret, payload_length;

	payload_length = sizeof(struct dhcpMessage) - 308;
	payload_length += end_option(payload->options) + 1;
	if (payload_length % 2) {
		payload_length++;
		*((char *) payload + payload_length - 1) = '\0';
	}

	DEBUG(LOG_INFO, "payload length is %d bytes", payload_length);

	if (payload->giaddr)
		ret = send_packet_to_relay(payload, payload_length);
	else ret = send_packet_to_client(payload, payload_length, force_broadcast);
	return ret;
}
