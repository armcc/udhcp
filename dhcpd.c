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
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/time.h>

#include "debug.h"
#include "dhcpd.h"
#include "arpping.h"
#include "socket.h"
#include "options.h"
#include "files.h"
#include "leases.h"
#include "packet.h"
#include "serverpacket.h"

/* prototypes */
static int log_pid(void);


/* globals */
struct dhcpOfferedAddr *leases;
struct server_config_t server_config;

static void udhcpd_killed(int pid)
{
	pid = 0;
	if (server_config.pid_file) unlink(server_config.pid_file);
	LOG(LOG_INFO, "Received SIGTERM");
	CLOSE_LOG();
	exit(0);
}	

#ifdef COMBINED_BINARY	
int udhcpd(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{	
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

	argc = argv[0][0]; /* get rid of some warnings */
	
	OPEN_LOG("udhcpd");
	LOG(LOG_INFO, "Moreton Bay DHCP Server (v%s) started", VERSION);
	
	memset(&server_config, 0, sizeof(struct server_config_t));
	
	read_config(DHCPD_CONF_FILE);
	if ((option = find_option(server_config.options, DHCP_LEASE_TIME))) {
		memcpy(&server_config.lease, option->data + 2, 4);
		server_config.lease = ntohl(server_config.lease);
	}
	else server_config.lease = LEASE_TIME;
	
	leases = malloc(sizeof(struct dhcpOfferedAddr) * server_config.max_leases);
	memset(leases, 0, sizeof(struct dhcpOfferedAddr) * server_config.max_leases);
	read_leases(server_config.lease_file);

	log_pid();
	
	if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) {
		ifr.ifr_addr.sa_family = AF_INET;
		strcpy(ifr.ifr_name, server_config.interface);
		if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
			sin = (struct sockaddr_in *) &ifr.ifr_addr;
			server_config.server = sin->sin_addr.s_addr;
			DEBUG(LOG_INFO, "%s (server_ip) = %s", ifr.ifr_name, inet_ntoa(sin->sin_addr));
		} else {
			LOG(LOG_ERR, "SIOCGIFADDR failed!");
			return 1;
		}
		if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0) {
			DEBUG(LOG_INFO, "adapter index %d", ifr.ifr_ifindex);
			server_config.ifindex = ifr.ifr_ifindex;
		} else {
			LOG(LOG_ERR, "SIOCGIFINDEX failed!");
			return 1;
		}
		if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
			memcpy(server_config.arp, ifr.ifr_hwaddr.sa_data, 6);
			DEBUG(LOG_INFO, "adapter hardware address %02x:%02x:%02x:%02x:%02x:%02x",
				server_config.arp[0], server_config.arp[1], server_config.arp[2], 
				server_config.arp[3], server_config.arp[4], server_config.arp[5]);
		} else {
			LOG(LOG_ERR, "SIOCGIFHWADDR failed!");
			return 1;
		}
	} else {
		LOG(LOG_ERR, "socket failed!");
		return 1;
	}
	close(fd);

#ifndef DEBUGGING
	if (fork()) return 0;
	else {
		close(0);
		setsid();
	}
#endif


	signal(SIGUSR1, write_leases);
	signal(SIGTERM, udhcpd_killed);

	timeout_end = time(0) + server_config.auto_time;
	while(1) { /* loop until universe collapses */

		server_socket = listen_socket(INADDR_ANY, SERVER_PORT, server_config.interface);
		if(server_socket == -1) {
			LOG(LOG_ERR, "couldn't create server socket -- au revoir");
			exit(0);
		}			

		FD_ZERO(&rfds);
		FD_SET(server_socket, &rfds);
		if (server_config.auto_time) {
			tv.tv_sec = timeout_end - time(0);
			if (tv.tv_sec <= 0) {
				tv.tv_sec = server_config.auto_time;
				timeout_end = time(0) + server_config.auto_time;
				write_leases(0);
			}
			tv.tv_usec = 0;
		}
		retval = select(server_socket + 1, &rfds, NULL, NULL, server_config.auto_time ? &tv : NULL);
		if (retval == 0) {
			write_leases(0);
			timeout_end = time(0) + server_config.auto_time;
			close(server_socket);
			continue;
		} else if (retval < 0) {
			DEBUG(LOG_INFO, "error on select");
			close(server_socket);
			continue;
		}
		
		bytes = get_packet(&packet, server_socket); /* this waits for a packet - idle */
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
					DEBUG(LOG_INFO, "server_id = %08x", ntohl(server_id_align));
					if (server_id_align == server_config.server && requested && 
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
				lease->expires = time(0) + server_config.decline_time;
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
	char *pidfile = server_config.pid_file;

	pid = getpid();
	if((fd = open(pidfile, O_WRONLY | O_CREAT, 0660)) < 0)
		return -1;
	write(fd, (void *) &pid, sizeof(pid));
	close(fd);
	return 0;
}


