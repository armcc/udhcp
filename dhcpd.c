/* dhcpd.c
 *
 * Moreton Bay DHCP Server
 * Copyright (C) 1999 Matthew Ramsay <matthewr@moreton.com.au>
 *			Chris Trew <ctrew@moreton.com.au>
 *
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef SYSLOG
#include <syslog.h>
#endif
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <time.h>

#include "debug.h"
#include "dhcpd.h"
#include "arpping.h"
#include "socket.h"
#include "options.h"
#include "files.h"
#include "leases.h"

/* prototypes */
int log_pid(void);
int getPacket(struct dhcpMessage *packet, int server_socket);
int sendOffer(struct dhcpMessage *oldpacket);
int sendNAK(struct dhcpMessage *oldpacket);
int sendACK(struct dhcpMessage *oldpacket, u_int32_t yiaddr);
int send_inform(struct dhcpMessage *oldpacket);
u_int32_t find_address(int check_expired);
int check_ip(u_int32_t ipaddr);


/* globals */
struct dhcpOfferedAddr *leases;
struct server_config config;

void udhcpd_killed(int pid)
{
	pid = 0;
	if (config.pid_file) unlink(config.pid_file);
	LOG(LOG_INFO, "Received SIGTERM");
#ifdef SYSLOG
	closelog();
#endif
	exit(0);
}	
	
int main(void) {
	fd_set rfds;
	struct timeval tv;
	int server_socket;
	int bytes, retval;
	struct dhcpMessage packet;
	unsigned char *state;
	char *server_id, *requested;
	u_int32_t server_id_align, requested_align;
	unsigned long timeout_end;
	struct option_set *option;
	struct dhcpOfferedAddr *lease;
	struct sockaddr_in *sin;
			
	/* server ip addr */
	int fd = -1;
	struct ifreq ifr;

#ifdef SYSLOG
	openlog("udhcpd", 0, 0);
#endif
	LOG(LOG_INFO, "Moreton Bay DHCP Server (v%s) started", VERSION);
	
	memset(&config, 0, sizeof(struct server_config));
	
	read_config(DHCPD_CONF_FILE);
	if ((option = find_option(config.options, DHCP_LEASE_TIME)))
		config.lease = ntohl((u_int32_t) option->data[2]);
	else config.lease = LEASE_TIME;
	
	leases = malloc(sizeof(struct dhcpOfferedAddr) * config.max_leases);
	memset(leases, 0, sizeof(struct dhcpOfferedAddr) * config.max_leases);
	read_leases(config.lease_file);

	log_pid();
	
	/* by default 10.10.10.10 -- server id */
	config.server = htonl(0x0A0A0A0A);
	
	if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) {
		ifr.ifr_addr.sa_family = AF_INET;
		strcpy(ifr.ifr_name, config.interface);
		if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
			sin = (struct sockaddr_in *) &ifr.ifr_addr;
			config.server = sin->sin_addr.s_addr;
			DEBUG(LOG_INFO, "%s (server_ip) = %s", ifr.ifr_name, inet_ntoa(sin->sin_addr));
		} else {
			LOG(LOG_ERR, "SIOCGIFADDR failed!");
			return 1;
		}
		if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0) {
			DEBUG(LOG_INFO, "adapter index %d", ifr.ifr_ifindex);
			config.ifindex = ifr.ifr_ifindex;
		} else {
			LOG(LOG_ERR, "SIOCGIFINDEX failed!");
			return 1;
		}
		if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
			memcpy(config.arp, ifr.ifr_hwaddr.sa_data, 6);
			DEBUG(LOG_INFO, "adapter hardware address %02x:%02x:%02x:%02x:%02x:%02x",
				config.arp[0], config.arp[1], config.arp[2], 
				config.arp[3], config.arp[4], config.arp[5]);
		} else {
			LOG(LOG_ERR, "SIOCGIFHWADDR failed!");
			return 1;
		}
	} else {
		LOG(LOG_ERR, "socket failed!");
		return 1;
	}

#ifndef DEBUGGING
	if (fork()) return 0;
	else {
		close(0);
		setsid();
	}
#endif


	signal(SIGUSR1, write_leases);
	signal(SIGTERM, udhcpd_killed);

	timeout_end = time(0) + config.auto_time;
	while(1) { /* loop until universe collapses */

		server_socket = serverSocket(SERVER_PORT);
		if(server_socket == -1) {
			LOG(LOG_ERR, "couldn't create server socket -- au revoir");
			exit(0);
		}			

		FD_ZERO(&rfds);
		FD_SET(server_socket, &rfds);
		if (config.auto_time) {
			tv.tv_sec = timeout_end - time(0);
			if (tv.tv_sec <= 0) {
				tv.tv_sec = config.auto_time;
				timeout_end = time(0) + config.auto_time;
				write_leases(0);
			}
			tv.tv_usec = 0;
		}
		retval = select(server_socket + 1, &rfds, NULL, NULL, config.auto_time ? &tv : NULL);
		if (retval == 0) {
			write_leases(0);
			timeout_end = time(0) + config.auto_time;
			continue;
		} else if (retval < 0) {
			DEBUG(LOG_INFO, "error on select");
			continue;
		}
		
		bytes = getPacket(&packet, server_socket); /* this waits for a packet - idle */
		close(server_socket);
		if(bytes < 0)
			continue;

		if((state = get_option(&packet, DHCP_MESSAGE_TYPE)) == NULL) {
			DEBUG(LOG_ERR, "couldnt get option from packet -- ignoring");
			continue;
		}
		
		lease = find_lease_by_chaddr(packet.chaddr);
		switch (state[0]) {
		case DHCPDISCOVER:
			DEBUG(LOG_INFO,"received DISCOVER");
			
			if (sendOffer(&packet) < 0) {
				LOG(LOG_ERR, "send OFFER failed -- ignoring");
			}
			break;			
 		case DHCPREQUEST:
			DEBUG(LOG_INFO,"received REQUEST");

			requested = get_option(&packet, DHCP_REQUESTED_IP);
			server_id = get_option(&packet, DHCP_SERVER_ID);

			if (requested) memcpy(&requested_align, requested, 4);
			if (server_id) memcpy(&server_id_align, server_id, 4);
		
			if (lease) {
				if (server_id) {
					/* SELECTING State */
					DEBUG(LOG_INFO, "server_id = %08x", ntohl(*server_id));
					if (server_id_align == config.server && requested && 
					    requested_align == lease->yiaddr) {
						sendACK(&packet, lease->yiaddr);
					}
				} else {
					if (requested) {
						/* INIT-REBOOT State */
						if (lease->yiaddr == requested_align)
							sendACK(&packet, lease->yiaddr);
						else sendNAK(&packet);
					} else {
						/* RENEWING or REBINDING State */
						if (lease->yiaddr == packet.ciaddr)
							sendACK(&packet, lease->yiaddr);
						else {
							/* don't know what to do!!!! */
							sendNAK(&packet);
						}
					}						
				}
			} /* else remain silent */				
			break;
		case DHCPDECLINE:
			DEBUG(LOG_INFO,"received DECLINE");
			if (lease) {
				memset(lease->chaddr, 0, 16);
				lease->expires = time(0) + config.decline_time;
			}			
			break;
		case DHCPRELEASE:
			DEBUG(LOG_INFO,"received RELEASE");
			if (lease) lease->expires = time(0);
			break;
		case DHCPINFORM:
			DEBUG(LOG_INFO,"received INFORM");
			send_inform(&packet);
			break;	
		default:
			LOG(LOG_WARNING, "unsupported DHCP message (%02x) -- ignoring", state[0]);
		}
	}

	return 0;
}


int log_pid(void) 
{
	int fd;
	pid_t pid;
	char *pidfile = config.pid_file;

	pid = getpid();
	if((fd = open(pidfile, O_WRONLY | O_CREAT, 0660)) < 0)
		return -1;
	write(fd, (void *) &pid, sizeof(pid));
	close(fd);
	return 0;
}


int getPacket(struct dhcpMessage *packet, int server_socket) {
	int bytes;

	DEBUG(LOG_INFO, "listening for any DHCP messages on network...");

	memset(packet, 0, sizeof(struct dhcpMessage));
	bytes = read(server_socket, packet, sizeof(struct dhcpMessage));
	if (bytes < 0) {
		DEBUG(LOG_INFO, "couldn't read on server socket -- ignoring");
		return -1;
	}

	if (ntohl(packet->cookie) != DHCP_MAGIC) {
		LOG(LOG_ERR, "client sent bogus message -- ignoring");
		return -1;
	}
	DEBUG(LOG_INFO, "oooooh!!! got some!");
	return bytes;
}

void init_packet(struct dhcpMessage *packet, struct dhcpMessage *oldpacket, char type)
{
	memset(packet, 0, sizeof(struct dhcpMessage));
	
	packet->op = BOOTREPLY;
	packet->htype = ETH_10MB;
	packet->hlen = ETH_10MB_LEN;
	packet->xid = oldpacket->xid;
	memcpy(packet->chaddr, oldpacket->chaddr, 16);
	packet->cookie = htonl(DHCP_MAGIC);
	packet->options[0] = DHCP_END;
	packet->flags = oldpacket->flags;
	packet->giaddr = oldpacket->giaddr;
	packet->ciaddr = oldpacket->ciaddr;
	add_simple_option(packet->options, DHCP_MESSAGE_TYPE, type);
	add_simple_option(packet->options, DHCP_SERVER_ID, ntohl(config.server)); /* expects host order */
}

/* send a DHCP OFFER to a DHCP DISCOVER */
int sendOffer(struct dhcpMessage *oldpacket) {

	struct dhcpMessage packet;
	struct dhcpOfferedAddr *lease = NULL;
	u_int32_t req_align, lease_time_align = config.lease;
	char *req, *lease_time;
	struct option_set *curr;
	struct in_addr addr;

	init_packet(&packet, oldpacket, DHCPOFFER);

	/* the client is in our lease/offered table */
	if ((lease = find_lease_by_chaddr(oldpacket->chaddr))) {
		if (!lease_expired(lease)) 
			lease_time_align = lease->expires - time(0);
		packet.yiaddr = lease->yiaddr;
		
	/* Or the client has a requested ip */
	} else if ((req = get_option(oldpacket, DHCP_REQUESTED_IP)) &&

		   /* Don't look here (ugly hackish thing to do) */
		   memcpy(&req_align, req, 4) &&

		   /* and the ip is in the lease range */
		   ntohl(req_align) >= ntohl(config.start) &&
		   ntohl(req_align) <= ntohl(config.end) &&
		   
		   /* and its not already taken/offered */
		   ((!(lease = find_lease_by_yiaddr(*req)) ||
		   
		   /* or its taken, but expired */
		   lease_expired(lease)))) {
		   
				packet.yiaddr = *req;

	/* otherwise, find a free IP */
	} else {
		packet.yiaddr = find_address(0);
		
		/* try for an expired lease */
		if (!packet.yiaddr) packet.yiaddr = find_address(1);
	}
	
	if(!packet.yiaddr) {
		LOG(LOG_WARNING, "no IP addresses to give -- OFFER abandoned");
		return -1;
	}
	
	if (!add_lease(packet.chaddr, packet.yiaddr, config.offer_time)) {
		LOG(LOG_WARNING, "lease pool is full -- OFFER abandoned");
		return -1;
	}		

	if ((lease_time = get_option(oldpacket, DHCP_LEASE_TIME))) {
		memcpy(&lease_time_align, lease_time, 4);
		lease_time_align = ntohl(lease_time_align);
		if (lease_time_align > config.lease) 
			lease_time_align = config.lease;
	}
		
	add_simple_option(packet.options, DHCP_LEASE_TIME, lease_time_align);

	curr = config.options;
	while (curr) {
		if (curr->data[OPT_CODE] == DHCP_LEASE_TIME) continue;
		add_option_string(packet.options, curr->data);
		curr = curr->next;
	}
	
	addr.s_addr = packet.yiaddr;
	LOG(LOG_INFO, "sending OFFER of %s", inet_ntoa(addr));
	return send_packet(&packet, 0);
}


int sendNAK(struct dhcpMessage *oldpacket) {
	struct dhcpMessage packet;

	init_packet(&packet, oldpacket, DHCPNAK);
	
	DEBUG(LOG_INFO, "sending NAK");
	return send_packet(&packet, 1);
}


int sendACK(struct dhcpMessage *oldpacket, u_int32_t yiaddr) {
	struct dhcpMessage packet;
	struct option_set *curr;
	char *lease_time;
	u_int32_t lease_time_align = config.lease;
	struct in_addr addr;

	init_packet(&packet, oldpacket, DHCPACK);
	packet.yiaddr = yiaddr;
	
	if ((lease_time = get_option(oldpacket, DHCP_LEASE_TIME))) {
		memcpy(&lease_time_align, lease_time, 4);
		lease_time_align = ntohl(lease_time_align);
		if (lease_time_align > config.lease) 
			lease_time_align = config.lease;
		else if (lease_time_align < config.min_lease) 
			lease_time_align = config.lease;
	}
	
	add_simple_option(packet.options, DHCP_LEASE_TIME, lease_time_align);
	
	curr = config.options;
	while (curr) {
		if (curr->data[OPT_CODE] == DHCP_LEASE_TIME) continue;
		add_option_string(packet.options, curr->data);
		curr = curr->next;
	}
	
	addr.s_addr = packet.yiaddr;
	LOG(LOG_INFO, "sending ACK to %s", inet_ntoa(addr));

	if (send_packet(&packet, 0) < 0) 
		return -1;

	add_lease(packet.chaddr, packet.yiaddr, lease_time_align);

	return 0;
}

int send_inform(struct dhcpMessage *oldpacket) {
	struct dhcpMessage packet;
	struct option_set *curr;

	init_packet(&packet, oldpacket, DHCPACK);
	
	curr = config.options;
	while (curr) {
		if (curr->data[OPT_CODE] == DHCP_LEASE_TIME) continue;
		add_option_string(packet.options, curr->data);
		curr = curr->next;
	}

	return send_packet(&packet, 0);
}

/* find an assignable address, it check_expired is true, we check all the expired leases as well.
 * Maybe this should try expired leases by age... */
u_int32_t find_address(int check_expired) 
{
	u_int32_t addr, ret = 0;
	struct dhcpOfferedAddr *lease = NULL;		

	addr = config.start;
	for (;ntohl(addr) < ntohl(config.end) ;addr = htonl(ntohl(addr) + 1)) {

		/* ie, 192.168.55.0 */
		if (!(ntohl(addr) & 0xFF)) continue;

		/* ie, 192.168.55.255 */
		if ((ntohl(addr) & 0xFF) == 0xFF) continue;

		/* lease is not taken */
		if ((!(lease = find_lease_by_yiaddr(addr)) ||

		     /* or it expired and we are checking for expired leases */
		     (check_expired  && lease_expired(lease))) &&

		     /* and it isn't on the network */
	    	     !check_ip(addr)) {
			ret = addr;
			break;
		}
	}
	return ret;
}

/* check is an IP is taken, if it is, add it to the lease table */
int check_ip(u_int32_t addr)
{
	char blank_chaddr[] = {[0 ... 15] = 0};
	struct in_addr temp;
	
	if (!arpping(addr)) {
		temp.s_addr = addr;
	 	LOG(LOG_INFO, "%s belongs to someone, reserving it for %ld seconds", 
	 		inet_ntoa(temp), config.conflict_time);
		add_lease(blank_chaddr, addr, config.conflict_time);
		return 1;
	} else return 0;
}
