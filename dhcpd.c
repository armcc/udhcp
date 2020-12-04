/*-------------------------------------------------------------------------------------
// Copyright 2006, Texas Instruments Incorporated
//
// This program has been modified from its original operation by Texas Instruments
// to do the following:
//
//  1. The server_config structure is extended to an array to define dhcp server 
// configuration on a per interface basis. NSP supports multiple lan groups 
// and requires dhcp server configuration per lan groups. These configurations 
// are saved in the server_config array. udhcp server supports configuration for
//  upto 6 interfaces.
//  2. Modified the main() function accordingly to listen on upto 6 sockets. 
// lease_file is therefore defined on a per interface basis. auto_time variable 
// (timeout_end) is extended to an array to hold 6 entries. 
// 3. Added a new text file udhcpd.host to allow consistency in host IP. 
//
// THIS MODIFIED SOFTWARE AND DOCUMENTATION ARE PROVIDED
// "AS IS," AND TEXAS INSTRUMENTS MAKES NO REPRESENTATIONS
// OR WARRENTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO, WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY
// PARTICULAR PURPOSE OR THAT THE USE OF THE SOFTWARE OR
// DOCUMENTATION WILL NOT INFRINGE ANY THIRD PARTY PATENTS,
// COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.
//
// These changes are covered as per original license.
//-------------------------------------------------------------------------------------*/

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
/* Change Description:07112006
 * 1. Added handling of option 60/77. Based on configuration assign a 
 *    DHCP class(server_config[i][j])
 * 2. Added Option 43 flag(flag43), which is used in serverpacket.c
 *    routines
 * 3. Modified all the calls to serverpacket routines to include flag43 
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
#include "pidfile.h"
#include "dhcpd_plugin_internal.h"

#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <string.h>

/* globals */
struct dhcpOfferedAddr *leases;
struct server_config_t server_config[MAX_INTERFACES][MAX_CLASSES];
int no_of_ifaces = 0;
int interfaces[MAX_INTERFACES] = {0,0,0,0,0,0};
int flag43 = 0;

char *vendor125_OptionInfo;
char *vendor_option_file;
int vendor_option_flag;

#define LEASE_ADD	1
#define LEASE_DEL	2

extern void write_to_delta(uint8_t *chaddr, uint32_t yiaddr, uint8_t *hname,unsigned long leasetime,uint8_t action,int classindex);

static void write_all_leases(int sig)
{
    int i,j;

    LOG(LOG_INFO, "Received SIGUSR1 - writing all leases");
    for (i = 0; i < no_of_ifaces; i++)
    {
        for (j = 0; j < MAX_CLASSES; j++)
        {
            write_leases(i,j);
        }
    }
}

static void update_vendor_specific_option(int sig)
{
    LOG(LOG_INFO, "Received SIGUSR2 - update Vendor Specific option 125");

    vendor_option_flag = 1;
}
            
/* Exit and cleanup */
static void exit_server(int retval, int ifid)
{
	pidfile_delete(server_config[ifid][0].pidfile);
	CLOSE_LOG();
	exit(retval);
}


/* SIGTERM handler */
static void udhcpd_killed(int sig)
{
	sig = 0;
	LOG(LOG_INFO, "Received SIGTERM");
	exit_server(0, 0);
}

static int find_class(struct dhcpMessage *packet, int ifid, int *flag43)
{
	char *vendorid_temp;
	char *vendorid;
	int vendorlength = 0;
	char *userclass_temp;
	char *userclass;
	int userclasslength = 0;
	int classindex = 0, j= 0;

	int i = ifid;

	*flag43 = 0;

	vendorid_temp = get_option(packet, DHCP_VENDOR);
	vendorlength = get_option_length(packet,DHCP_VENDOR);
	userclass_temp = get_option(packet, DHCP_USER_CLASS);
	userclasslength = get_option_length(packet,DHCP_USER_CLASS);

	if( (vendorid_temp == NULL ) && (userclass_temp == NULL) )
		;
	else
	{
		if(vendorid_temp != NULL)
		{
			vendorid = (char *)strndup(vendorid_temp,vendorlength);
			for(j = 1; j < MAX_CLASSES; j++)
			{
				if(server_config[i][j].active == TRUE)
				{
					if(!strncmp(server_config[i][j].classifier.id,"vendorid",strlen("vendorid")))
					{
						if( strncmp(vendorid,server_config[i][j].classifier.value,vendorlength) == 0)
						{
							classindex = j;
							*flag43 = 2;
							break;
						}
					}
				}
			}
			free(vendorid);
		}
		if( (userclass_temp != NULL) && (classindex == 0) )
		{
			userclass = (char *)strndup(userclass_temp,userclasslength);
			for(j = 1; j < MAX_CLASSES; j++)
			{
				if(server_config[i][j].active == TRUE)
				{
					if(!strncmp(server_config[i][j].classifier.id,"userclass",strlen("userclass")))
					{
						if( strncmp(userclass,server_config[i][j].classifier.value,userclasslength) == 0)
						{
							classindex = j;
							break;
						}
					}
				}
			}
			free(userclass);
		}
	}
	return classindex;
}

#ifdef COMBINED_BINARY	
int udhcpd(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{	
	fd_set rfds;
	struct timeval tv;
	int server_socket[MAX_INTERFACES];
	int bytes, retval;
	struct dhcpMessage packet;
	unsigned char *state;
	unsigned char *server_id, *requested;
	uint32_t server_id_align, requested_align;
	unsigned long timeout_end[MAX_INTERFACES][MAX_CLASSES];
	struct option_set *option;
	struct dhcpOfferedAddr *lease;
	int pid_fd;
	
	int i,j,classindex,continue_flag = FALSE;
	struct stat configFileCurrStat = {0};
	char defConfigFileName[] = DHCPD_CONF_FILE;
	char *configFileName;

	OPEN_LOG("udhcpd");
	LOG(LOG_INFO, "udhcp server (v%s) started", VERSION);

#if 0
	memset(&server_config, 0, sizeof(server_config));
#else
	/* Initialise server_config to all zeros */ 
	for (i = 0; i < MAX_INTERFACES; i++)
	{
		for( j = 0 ; j < MAX_CLASSES ; j++)
			memset(&server_config[i][j], 0, sizeof(struct server_config_t));
	}
#endif
	
	/* Initialize Vendor Specific Option pointers */
	vendor125_OptionInfo = NULL;
	vendor_option_file = NULL;
	vendor_option_flag = 0;

	if (argc < 2)
		configFileName = defConfigFileName;
	else
		configFileName = argv[1];

	read_config(configFileName);

	stat(configFileName, &configFileCurrStat);

	/* No DHCP server configured yet */
	if (no_of_ifaces == 0)
		exit(0);

	for (i = 0; i < no_of_ifaces; i++)
	{
		pid_fd = pidfile_acquire(server_config[i][0].pidfile);
		pidfile_write_release(pid_fd);
	}

	for (i = 0; i < no_of_ifaces; i++)
	{
		for (j = 0; j < MAX_CLASSES; j++)
		{
			if ((option = find_option(server_config[i][j].options, DHCP_LEASE_TIME))) {
				memcpy(&server_config[i][j].lease, option->data + 2, 4);
				server_config[i][j].lease = ntohl(server_config[i][j].lease);
			}
			else server_config[i][j].lease = LEASE_TIME;

			server_config[i][j].leases = malloc(sizeof(struct dhcpOfferedAddr) * server_config[i][j].max_leases);
			memset(server_config[i][j].leases, 0, sizeof(struct dhcpOfferedAddr) * server_config[i][j].max_leases);
			/* Warning: original upstream code called read_leases() here, not read_hosts() ? */
			read_hosts(server_config[i][j].host_file, i, j);

			/* Initially all configured interfaces are active, and we change the actual status
			   here based on the interface state
			*/
			if (server_config[i][j].active)
			{
				if (read_interface(server_config[i][j].interface, &server_config[i][j].ifindex, &server_config[i][j].server, server_config[i][j].arp) < 0)
					server_config[i][j].active = FALSE;
			}
#ifndef DEBUGGING
			pid_fd = pidfile_acquire(server_config[i][j].pidfile); /* hold lock during fork. */
			/* cfgmr req: do not fork */
/*
			if (daemon(0, 0) == -1) {
				perror("fork");
				exit_server(1, i);
			}
*/
			pidfile_write_release(pid_fd);
#endif
		}
	}


	signal(SIGUSR1, write_all_leases);
	signal(SIGTERM, udhcpd_killed);
	signal(SIGUSR2, update_vendor_specific_option);

	for (i = 0; i < no_of_ifaces; i++) 
	{
		server_socket[i] = -1;
		for(j = 0; j < MAX_CLASSES; j++)
		{
			timeout_end[i][j] = time(0) + server_config[i][j].auto_time;
			if(server_config[i][j].active == TRUE)
			{
				LOG(LOG_INFO, "interface: %s, start : %x end : %x\n", 
					server_config[i][j].interface, server_config[i][j].start, 
					server_config[i][j].end);
			}
		}
	}

	while(1) { /* loop until universe collapses */

	int ipc_socket;
	int max_fd;
	int deferred_packet = 0;

	/* Occasionally maintain state for the plugin */
	dhcpd_plugin_maintenance();
	ipc_socket = dhcpd_plugin_socket();

	for (i = 0; i < no_of_ifaces; i++)
	{
		for(j = 0; j < MAX_CLASSES; j++)
		{
			continue_flag += server_config[i][j].active;
		}

		if(continue_flag == FALSE)
			continue;

		if (server_socket[i] < 0)
			if ((server_socket[i] = listen_socket(INADDR_ANY, SERVER_PORT, server_config[i][0].interface)) < 0) {
				LOG(LOG_ERR, "FATAL: couldn't create server socket, %s", strerror(errno));
				exit_server(0, i);
			}			

		FD_ZERO(&rfds);
		FD_SET(server_socket[i], &rfds);

		max_fd = server_socket[i];
		if (ipc_socket != -1) {
			FD_SET(ipc_socket, &rfds);
			if (ipc_socket > max_fd) {
				max_fd = ipc_socket;
			}
		}

		for(j = 0; j < MAX_CLASSES; j++)
		{
			if (server_config[i][j].auto_time) {
				tv.tv_sec = timeout_end[i][j] - time(0);
				if (tv.tv_sec <= 0) {
					write_leases(i,j);
					tv.tv_sec = server_config[i][j].auto_time;
					timeout_end[i][j] = time(0) + server_config[i][j].auto_time;
				}
				tv.tv_usec = 0;
			}
		}

		if (0 == dhcpd_plugin_pop_deferred_packet(i, &packet)) {
			retval = 1;
			deferred_packet = 1;
		} else {
			retval = select(max_fd + 1, &rfds, NULL, NULL, server_config[i][0].auto_time ? &tv : NULL);

			/* Check whether we really have data to read (could have been IPC) */
			if ((retval > 0) && !FD_ISSET(server_socket[i], &rfds)) {
				retval = 0;
			}
		}

		/* if vendor_option_flag is set - this means that SIGUSR2 has been received - update the vendor specific option */
		if (vendor_option_flag == 1)
		{
			vendor_option_flag = 0;
			read_vendor_options();
		}

		if (retval == 0) {
			for (j = 0; j < MAX_CLASSES; j++) {
				write_leases(i,j);
				timeout_end[i][j] = time(0) + server_config[i][j].auto_time;
			}
			continue;
		} else if (retval < 0) {
			LOG(LOG_ERR, "dhcpd.c Error on select: errno is %s", strerror(errno));
			continue;
		}
		
		/* If udhcp config file has changed - update DB options */
		if (file_updated(configFileName, &configFileCurrStat) == True)
		{
			DEBUG(LOG_INFO, "New udhcp config file(%s) - Reloading options.\n", configFileName);
			update_options(configFileName);
		}

		if (deferred_packet == 0) {
			if ((bytes = get_packet(&packet, server_socket[i])) < 0) { /* this waits for a packet - idle */
				if (bytes == -1 && errno != EINTR) {
					DEBUG(LOG_INFO, "error on read, %s, reopening socket", strerror(errno));
					close(server_socket[i]);
					server_socket[i] = -1;
				}
				continue;
			}
		}

		if ((state = get_option(&packet, DHCP_MESSAGE_TYPE)) == NULL) {
			DEBUG(LOG_ERR, "couldn't get option from packet, ignoring");
			continue;
		}
		
		/* Determine the class that client belongs to */
		flag43 = 0;
		classindex = find_class( &packet, i, &flag43 );

		/* ADDME: look for a static lease */
		lease = find_lease_by_chaddr(packet.chaddr, i, classindex);
		switch (state[0]) {

		dhcpd_dev_check_from_client_t cb_callee_args;
		bool use_ext_addr;
		bool skip_ack;

		case DHCPDISCOVER:
			DEBUG(LOG_INFO,"received DISCOVER");
			
			if (sendOffer(&packet, i, classindex, flag43) < 0) {
				LOG(LOG_ERR, "send OFFER failed");
			}
			break;			
 		case DHCPREQUEST:
			DEBUG(LOG_INFO, "received REQUEST");

			requested = get_option(&packet, DHCP_REQUESTED_IP);
			server_id = get_option(&packet, DHCP_SERVER_ID);

			if (requested) memcpy(&requested_align, requested, 4);
			if (server_id) memcpy(&server_id_align, server_id, 4);
		
			/* Call to notify on request if registered,
			 * get external address to ack */

			use_ext_addr = false;
			skip_ack = false;

			dhcpd_plugin_check_dev (i, classindex, &packet, &skip_ack, &use_ext_addr, &cb_callee_args);

			if (skip_ack) {
				/* Do nothing - ignore the packet */
			}
			else if (use_ext_addr) {
				/* Always treat like a new lease, erasing any prior info. sendACK will create a new lease */
				clear_lease(packet.chaddr, 0, i, classindex);
				sendACK(&packet, cb_callee_args.externally_assigned.ip_address, i, classindex, flag43, &cb_callee_args);
			}
			else if (lease) { /*ADDME: or static lease */
				if (server_id) {
					/* SELECTING State */
					DEBUG(LOG_INFO, "server_id = %08x", ntohl(server_id_align));
					if (server_id_align == server_config[i][classindex].server && requested && 
					    requested_align == lease->yiaddr) {
						sendACK(&packet, lease->yiaddr, i, classindex, flag43, NULL);
					}
				} else {
					if (requested) {
						/* INIT-REBOOT State */
						if (lease->yiaddr == requested_align)
							sendACK(&packet, lease->yiaddr, i, classindex, flag43, NULL);
						else sendNAK(&packet, i,classindex, flag43);
					} else {
						/* RENEWING or REBINDING State */
						if (lease->yiaddr == packet.ciaddr)
							sendACK(&packet, lease->yiaddr, i, classindex, flag43, NULL);
						else {
							/* don't know what to do!!!! */
							sendNAK(&packet, i, classindex, flag43);
						}
					}						
				}
			
			/* what to do if we have no record of the client */
			} else if (server_id) {
				/* SELECTING State */
				sendNAK(&packet, i, classindex, flag43);

			} else if (requested) {
				/* INIT-REBOOT State */
				if ((lease = find_lease_by_yiaddr(requested_align,i,classindex))) {
					if (lease_expired(lease,i,classindex)) {
						/* probably best if we drop this lease */
						memset(lease->chaddr, 0, 16);
					/* make some contention for this address */
					} else sendNAK(&packet, i, classindex, flag43);
				} else if (requested_align < server_config[i][classindex].start || 
					   requested_align > server_config[i][classindex].end) {
					sendNAK(&packet, i, classindex, flag43);
				} else sendNAK(&packet, i, classindex, flag43);
			} else {
				 /* RENEWING or REBINDING State */
				sendNAK(&packet, i, classindex, flag43);
			}
			break;
		case DHCPDECLINE:
			DEBUG(LOG_INFO,"received DECLINE");
			if (lease) {
				memset(lease->chaddr, 0, 16);
				lease->expires = time(0) + server_config[i][classindex].decline_time;
			}			
			break;
		case DHCPRELEASE:
			DEBUG(LOG_INFO,"received RELEASE");
			dhcpd_plugin_release_dev(&packet);
			if (lease) {
				if( lease->expires != server_config[i][classindex].inflease_time) {
					lease->expires = time(0);
					write_to_delta(lease->chaddr, lease->yiaddr, lease->hostname, 0, LEASE_DEL, classindex);
				}
			}
			break;
		case DHCPINFORM:
			DEBUG(LOG_INFO,"received INFORM");
			send_inform(&packet, i, classindex, flag43);
			break;	
		default:
			LOG(LOG_WARNING, "unsupported DHCP message (%02x) -- ignoring", state[0]);
		}
	}
	}

	return 0;
}

