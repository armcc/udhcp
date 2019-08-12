/* serverpacket.c
 *
 * Constuct and send DHCP server packets
 *
 * Russ Dill <Russ.Dill@asu.edu> July 2001
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

/*-------------------------------------------------------------------------------------
// Copyright 2006, Texas Instruments Incorporated
//
// This program has been modified from its original operation by Texas Instruments
// to do the following:
//
// 1. Added utility function copy_till() to copy a string till the delimiter 
//	  specified
// 2. Changes to support multiple interfaces sendOffer() and sendAck() functions 
//	  modified to extract DHCP_HOST_NAME option field from the request and copy the 
//	  same to the offer message in the received dhcp packet. This is used in serverpacket.c.
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <malloc.h>

#include "packet.h"
#include "debug.h"
#include "dhcpd.h"
#include "options.h"
#include "leases.h"
#include "files.h"
#include "dhcpd_plugin.h"
#include "dhcpd_plugin_internal.h"

/* Change Description:07112006
 * 1. Option 43 handling added in init_packet
 * 2. Modified functions to include classindex to indicate correct server_config
 */

static int copy_till(char *inp, char *dest, char sep, unsigned int length)
{
	unsigned int i = 0;

	while( (inp[i] != 0x00) && (inp[i] != sep) && (i < length ))
	{
		*(dest + i) = inp[i];
		i++;
	}
	*(dest + i) = 0x00;
	return i;		
}

/* send a packet to giaddr using the kernel ip stack */
static int send_packet_to_relay(struct dhcpMessage *payload, int ifid,int classindex)
{
	DEBUG(LOG_INFO, "Forwarding packet to relay");

	return kernel_packet(payload, server_config[ifid][classindex].server, SERVER_PORT,
			payload->giaddr, SERVER_PORT);
}

/* This function analyses the Vendor Specific Option 125, received from the Client                   */
/* Currently it looks for the Enterprise code 4491 - Cable labs                                      */
/* Inside the Enterprise code the function looks for the Suboption 1 -	DHCPv4 Option Request Option */
/* Inside Suboption 1 it looks for the Value 3 - eRouter Container                                   */
static int checkIfOption125IsRequested(char *receivedOption125)
{

//#define GW_OPT_ENTERPRISE_NUMBER 4491
//#define GW_OPT_SUB_OPTION_3 3

	int ret = 0;
	int enterpriseCodeFound;
	uint8_t *vendorOption125 = receivedOption125;
	int i,j;
	uint8_t *optionPtr = receivedOption125;  /* pointer to the received from client Option 125 */
	uint8_t optionLen = vendorOption125[1];  /* length of the received from client Option 125 */

	/* look for CableLabs enterprise code 4491 */
	/* skip opcode and oplength - point to the enterprise code */
	vendorOption125 += OPT_SUBOPTION_LEN + OPT_SUBOPTION_CODE;

	/* look for enterprise number of cable labs 4491 */
	/* optionLen-5 is the length of the rest of the message without Enterprise code and Enterprise block length */
	/* *(vendorOption125 + i + 4) + 5 is the length of the Enterprise block plus 5 bytes of enterprise and length */
	for (i=0; i < (optionLen - (OPT_SUBOPTION_LEN + OPT_ENTERPRISE_NUMBER_LEN)); i += *(vendorOption125 + i + OPT_ENTERPRISE_NUMBER_LEN) + OPT_SUBOPTION_LEN + OPT_ENTERPRISE_NUMBER_LEN )
	{
		if (((uint32_t *)vendorOption125)[i] == OPT_ENTERPRISE_NUMBER)
		{
			enterpriseCodeFound = 1;
			vendorOption125 += i;		  /* points to the enterprise number */
			break;
		}
	}

	if (enterpriseCodeFound == 0)  /* no CableLabs enterprise code found */
		return ret;

	vendorOption125 += OPT_ENTERPRISE_NUMBER_LEN; /* points to the length of enterprise block */

	/* get length of enterprise block of options */
	int enterpriseBlockLen = *vendorOption125;

	/* point to the suboption code */
	vendorOption125 += OPT_SUBOPTION_LEN;

	/* go through the block and look for the requested sub-options */
	/* enterpriseBlockLen - 2 is the length of the suboption without its type and length */
	/* *(vendorOption125 + i + 1) + 2 is the length of subooption plus its type and length */
	for (i=0; i < (enterpriseBlockLen - (OPT_SUBOPTION_LEN + OPT_SUBOPTION_CODE)); i += *(vendorOption125 + i + OPT_SUBOPTION_LEN) + OPT_SUBOPTION_LEN + OPT_SUBOPTION_CODE)
	{
		/* switch on sub-option */
		switch (*(vendorOption125 + i))
		{
		case 1: /* Suboption - Requested options */
			for (j=0; j < (*(vendorOption125 + i + OPT_SUBOPTION_LEN) ); j++)
			{
				if ( *(vendorOption125 + i + OPT_SUBOPTION_LEN + OPT_SUBOPTION_CODE + j) == CL_V4EROUTER_CONTAINER_OPTION)
				{
					return 1;
				}
			}
			break;
		}

		return ret;
	}
}

/* Check whether the Vendor Specific Option 125 received and contains the Requested Options suboption 1 */
/* with the eRouter Container suboption code - 3. Only in this case the Container suboption in the */
/* option 125 will be added to the Server message */
static int check_and_send_vendor_specific_option(struct dhcpMessage *oldpacket, uint8_t *packetOptions)
{
	uint8_t *vendorSpecific;

	int occurance = 0;
	int done = 0;	 

	/* check if option 125 vendor specific is requested - get multiple occurancies */
	while(!done)
	{
		vendorSpecific = get_option_multiple(oldpacket, DHCP_VENDOR_SPECIFIC, occurance);
		if (vendorSpecific)
		{
			/* check if Container suboption is requested in the Client message */
			if (checkIfOption125IsRequested(vendorSpecific - 2) == 1)
			{
				done = 1;

				/* check if vendor specific option value is already read from file */
				if (vendor125_OptionInfo == NULL)
				{
					/* if not read - read from file */
					read_vendor_options();
				}

				/* vendor specific option value exists */
				if (vendor125_OptionInfo != NULL)
				{
					add_option_string(packetOptions, vendor125_OptionInfo);
					return 1;
				}
			}
			else
			{
				occurance++;
			}
		}
		else
		{
			done = 1;
			return 0;
		}
	}

	return 0;
}

/* send a packet to a specific arp address and ip address by creating our own ip packet */
static int send_packet_to_client(struct dhcpMessage *payload, int force_broadcast, int ifid,int classindex)
{
	unsigned char *chaddr;
	uint32_t ciaddr;
	
	if (force_broadcast) {
		DEBUG(LOG_INFO, "broadcasting packet to client (NAK)");
		ciaddr = INADDR_BROADCAST;
		chaddr = MAC_BCAST_ADDR;
	} else if (payload->ciaddr) {
		DEBUG(LOG_INFO, "unicasting packet to client ciaddr");
		ciaddr = payload->ciaddr;
		chaddr = payload->chaddr;
	} else if (ntohs(payload->flags) & BROADCAST_FLAG) {
		DEBUG(LOG_INFO, "broadcasting packet to client (requested)");
		ciaddr = INADDR_BROADCAST;
		chaddr = MAC_BCAST_ADDR;
	} else {
		DEBUG(LOG_INFO, "unicasting packet to client yiaddr");
		ciaddr = payload->yiaddr;
		chaddr = payload->chaddr;
	}
	return raw_packet(payload, server_config[ifid][classindex].server, SERVER_PORT, 
			ciaddr, CLIENT_PORT, chaddr, server_config[ifid][classindex].ifindex);
}


/* send a dhcp packet, if force broadcast is set, the packet will be broadcast to the client */
static int send_packet(struct dhcpMessage *payload, int force_broadcast, int ifid,int classindex)
{
	int ret;

	if (payload->giaddr)
		ret = send_packet_to_relay(payload, ifid,classindex);
	else ret = send_packet_to_client(payload, force_broadcast, ifid,classindex);
	return ret;
}


static void init_packet(struct dhcpMessage *packet, struct dhcpMessage *oldpacket, char type, int ifid,int classindex,int flag43)
{
	init_header(packet, type);
	packet->xid = oldpacket->xid;
	memcpy(packet->chaddr, oldpacket->chaddr, 16);
	packet->flags = oldpacket->flags;
	packet->giaddr = oldpacket->giaddr;
	packet->ciaddr = oldpacket->ciaddr;
	add_simple_option(packet->options, DHCP_SERVER_ID, server_config[ifid][classindex].server);

	if(flag43 == 2)
	{
		if( server_config[ifid][classindex].vendorinfo != NULL ) 
		{
			struct option_set *new;
			int length;

			length = strlen(server_config[ifid][classindex].vendorinfo);
			new = malloc(sizeof(struct option_set));
			if(new)
			{
				new->data = malloc(length + 2);
				if(new->data)
				{
					new->data[OPT_CODE] = DHCP_VENDOR_INFO;
					new->data[OPT_LEN] = length;
					memcpy(new->data + 2, server_config[ifid][classindex].vendorinfo, length);
					add_option_string(packet->options, new->data);

					free(new->data);
				}
				free(new);
			}
		}
		else
			add_simple_option(packet->options, DHCP_VENDOR_INFO, (int)NULL);
	} 

	if(flag43 == 1)
	{
		add_simple_option(packet->options, DHCP_VENDOR_INFO, (int)NULL);
	} 
}


/* add in the bootp options */
static void add_bootp_options(struct dhcpMessage *packet, int ifid,int classindex)
{
	packet->siaddr = server_config[ifid][classindex].siaddr;
	if (server_config[ifid][classindex].sname)
		strncpy(packet->sname, server_config[ifid][classindex].sname, sizeof(packet->sname) - 1);
	if (server_config[ifid][classindex].boot_file)
		strncpy(packet->file, server_config[ifid][classindex].boot_file, sizeof(packet->file) - 1);
}
	

static void add_ext_assigned_options(struct dhcpMessage *packet, dhcpd_dev_check_from_client_t *cb_callee_args)
{
	uint32_t option_val_nbo;
	unsigned char *option_data_ptr;
	uint8_t dns_server_option[OPT_DATA+sizeof(cb_callee_args->externally_assigned.dns_servers)];
	int dns_server_index;
	int dns_server_count = cb_callee_args->externally_assigned.dns_server_count;

	/* Subnet mask and default gateway are easy because they're just 32-bit values */
	if (0 != cb_callee_args->externally_assigned.subnet_mask) {
		option_val_nbo = htonl(cb_callee_args->externally_assigned.subnet_mask);
		option_data_ptr = get_option(packet, DHCP_SUBNET);
		if (NULL != option_data_ptr) {
			memcpy(option_data_ptr, &option_val_nbo, sizeof(option_val_nbo));
		} else if (0 == add_simple_option(packet->options, DHCP_SUBNET, option_val_nbo)) {
		   LOG(LOG_ERR, "Couldn't add externally assigned subnet mask option\n");
		}
	}

	if (0 != cb_callee_args->externally_assigned.default_gateway) {
		option_val_nbo = htonl(cb_callee_args->externally_assigned.default_gateway);
		option_data_ptr = get_option(packet, DHCP_ROUTER);
		if (NULL != option_data_ptr) {
			memcpy(option_data_ptr, &option_val_nbo, sizeof(option_val_nbo));
		} else if (0 == add_simple_option(packet->options, DHCP_ROUTER, option_val_nbo)) {
		   LOG(LOG_ERR, "Couldn't add externally assigned default gateway option\n");
		}
	}
   
	/* DNS server can be a list and can therefore be a different size.	
	 * Erase old option and add a new one */
	if (0 != dns_server_count) {
		erase_option(packet, DHCP_DNS_SERVER);
		dns_server_option[OPT_CODE] = DHCP_DNS_SERVER;
		dns_server_option[OPT_LEN] = sizeof(option_val_nbo) * dns_server_count;
		for (dns_server_index = 0; dns_server_index < dns_server_count; dns_server_index++) {
			unsigned option_offset = OPT_DATA+(dns_server_index*sizeof(option_val_nbo));
			option_val_nbo = htonl(cb_callee_args->externally_assigned.dns_servers[dns_server_index]);
			memcpy(dns_server_option+option_offset, &option_val_nbo, sizeof(option_val_nbo));
		}
		if ((dns_server_option[OPT_LEN]+OPT_DATA) != add_option_string(packet->options, dns_server_option)) {
			LOG(LOG_ERR, "Couldn't add externally assigned DNS servers option\n");
		}
	}
}

/* Read hostname from packet and copy to temporary storage string */
int getHostnameFromPacket(struct dhcpMessage *oldpacket, struct dhcpMessage *packet,
	uint8_t *hostname)
{
	uint8_t *hname;
	int length = 0;

	hname = get_option(oldpacket,DHCP_HOST_NAME);
	if(hname)
	{
		length = get_option_length(oldpacket,DHCP_HOST_NAME);
		if(length <= HOST_NAME_MAX){
			memset(hostname,0x00,HOST_NAME_MAX);
			copy_till(hname , hostname, '.',(length < HOST_NAME_MAX ? length : HOST_NAME_MAX));
			add_option_string(packet->options, hname - 2 );			
		}
		else{
			LOG(LOG_WARNING, "Hostname too long, supported length %d\n", HOST_NAME_MAX);
			return -1;
		}
	}
	else{
		return -1;
	}
	return 0;
}

/* send a DHCP OFFER to a DHCP DISCOVER */
int sendOffer(struct dhcpMessage *oldpacket, int ifid, int classindex, int flag43)
{
	struct dhcpMessage packet;
	struct dhcpOfferedAddr *lease = NULL;
	uint32_t req_align, lease_time_align = server_config[ifid][classindex].lease,leasetime = 0;
	unsigned char *req, *lease_time;
	struct option_set *curr;
	struct in_addr addr;
	uint8_t hostname[HOST_NAME_MAX + 1] = "unknown";
	dhcpd_dev_check_from_client_t cb_callee_args;
	bool use_ext_addr = false;
	bool skip_offer = false;

	/* Call to notify on discover if registered, 
	 * get external address to offer */
	dhcpd_plugin_check_dev(ifid, 
						   classindex, 
						   oldpacket, 
						   &skip_offer, 
						   &use_ext_addr, 
						   &cb_callee_args);
	if (skip_offer) {
		return 0;
	}

	init_packet(&packet, oldpacket, DHCPOFFER, ifid, classindex, flag43);
	
	/* If externally controlled address assignment, remove any lease for this device
	 * and start from scratch */
	if (use_ext_addr) {
		clear_lease(oldpacket->chaddr, 0, ifid, classindex);
		packet.yiaddr = cb_callee_args.externally_assigned.ip_address;
	}
	else

	/* ADDME: if static, short circuit */
	/* the client is in our lease/offered table */
	if ((lease = find_lease_by_chaddr(oldpacket->chaddr, ifid, classindex))) {
		if (!lease_expired(lease, ifid, classindex)) {
			if(lease->expires == server_config[ifid][classindex].inflease_time) {
				lease_time_align = server_config[ifid][classindex].inflease_time;
			} else {
				lease_time_align = lease->expires - time(0);
			}
		}
		packet.yiaddr = lease->yiaddr;
		
	/* Or the client has a requested ip */
	} else if ((req = get_option(oldpacket, DHCP_REQUESTED_IP)) &&

		   /* Don't look here (ugly hackish thing to do) */
		   memcpy(&req_align, req, 4) &&

		   /* and the ip is in the lease range */
		   ntohl(req_align) >= ntohl(server_config[ifid][classindex].start) &&
		   ntohl(req_align) <= ntohl(server_config[ifid][classindex].end) &&
		   
		   /* and its not already taken/offered */ /* ADDME: check that its not a static lease */
		   ((!(lease = find_lease_by_yiaddr(req_align, ifid, classindex)) ||
		   
		   /* or its taken, but expired */ /* ADDME: or maybe in here */
		   lease_expired(lease,ifid,classindex)))) {
				/* check id addr is not taken by a static ip */
				if(!check_ip(req_align, ifid, classindex)) {
					packet.yiaddr = req_align; /* FIXME: oh my, is there a host using this IP? */
				} else { 
					packet.yiaddr = find_address(0, ifid, classindex);

					/* try for an expired lease */
					if (!packet.yiaddr) packet.yiaddr = find_address(1, ifid, classindex);
				}

	/* otherwise, find a free IP */ /*ADDME: is it a static lease? */
	} else {
		packet.yiaddr = find_address(0, ifid,classindex);
		
		/* try for an expired lease */
		if (!packet.yiaddr) packet.yiaddr = find_address(1, ifid,classindex);
	}
	
	if(!packet.yiaddr) {
		LOG(LOG_WARNING, "no IP addresses to give -- OFFER abandoned");
		return -1;
	}
	
	if (!getHostnameFromPacket(oldpacket, &packet, hostname)) {
		LOG(LOG_INFO, "SENDING OFFER to %s\n",hostname);
	}

	/* check if option 125 vendor specific is requested - get multiple occurancies */  
	if (check_and_send_vendor_specific_option(oldpacket, packet.options) == 1) {
		LOG(LOG_INFO, "SENDING OFFER with option 125\n");
	}

	/*Check for infinite lease */
	if ((lease = find_lease_by_chaddr(oldpacket->chaddr, ifid, classindex)))
	{
		if(lease->expires == server_config[ifid][classindex].inflease_time) {
			leasetime = server_config[ifid][classindex].inflease_time;
		} else {
			leasetime = server_config[ifid][classindex].offer_time;
		}
	}
	else {
		leasetime = server_config[ifid][classindex].offer_time;
	}

	if (!add_lease(packet.chaddr, packet.yiaddr, leasetime /*server_config[ifid].offer_time*/, ifid, classindex, hostname)) {
		LOG(LOG_WARNING, "lease pool is full -- OFFER abandoned");
		return -1;
	}		

	if ((lease_time = get_option(oldpacket, DHCP_LEASE_TIME))) {
		memcpy(&lease_time_align, lease_time, 4);
		lease_time_align = ntohl(lease_time_align);
		if (lease_time_align > server_config[ifid][classindex].lease) 
			lease_time_align = server_config[ifid][classindex].lease;
	}

	/* Make sure we aren't just using the lease time from the previous offer */
	if (lease_time_align < server_config[ifid][classindex].min_lease) 
		lease_time_align = server_config[ifid][classindex].lease;

	/* For inifinite leases change the lease time */
	if( leasetime == server_config[ifid][classindex].inflease_time) {
		lease_time_align = leasetime;
	}

	/* ADDME: end of short circuit */		
	add_simple_option(packet.options, DHCP_LEASE_TIME, htonl(lease_time_align));

	curr = server_config[ifid][classindex].options;
	while (curr) {
		if (curr->data[OPT_CODE] != DHCP_LEASE_TIME)
			add_option_string(packet.options, curr->data);
		curr = curr->next;
	}

	add_bootp_options(&packet, ifid, classindex);
	
	if (use_ext_addr) {
		add_ext_assigned_options(&packet, &cb_callee_args);
	}

	addr.s_addr = packet.yiaddr;
	LOG(LOG_INFO, "sending OFFER of %s", inet_ntoa(addr));
	return send_packet(&packet, 0, ifid,classindex);
}


int sendNAK(struct dhcpMessage *oldpacket, int ifid,int classindex,int flag43)
{
	struct dhcpMessage packet;

	init_packet(&packet, oldpacket, DHCPNAK, ifid,classindex,flag43);
	
	DEBUG(LOG_INFO, "sending NAK");
	return send_packet(&packet, 1, ifid,classindex);
}


int sendACK(struct dhcpMessage *oldpacket, uint32_t yiaddr, int ifid,int classindex,int flag43, dhcpd_dev_check_from_client_t *ext_addr)
{
	struct dhcpMessage packet;
	struct option_set *curr;
	unsigned char *lease_time;
	uint32_t lease_time_align = server_config[ifid][classindex].lease;
	struct in_addr addr;
	uint8_t hostname[HOST_NAME_MAX + 1]="unknown";
	struct dhcpOfferedAddr *lease = NULL;
	uint8_t *vendorSpecific;

	init_packet(&packet, oldpacket, DHCPACK, ifid,classindex,flag43);
	packet.yiaddr = yiaddr;
	
	if ((lease_time = get_option(oldpacket, DHCP_LEASE_TIME))) {
		memcpy(&lease_time_align, lease_time, 4);
		lease_time_align = ntohl(lease_time_align);
		if (lease_time_align > server_config[ifid][classindex].lease) 
			lease_time_align = server_config[ifid][classindex].lease;
		else if (lease_time_align < server_config[ifid][classindex].min_lease) 
			lease_time_align = server_config[ifid][classindex].lease;
	}
	
	/* If the existing lease entry has infinite entry give it infinite time */
	if ( (lease = find_lease_by_chaddr(oldpacket->chaddr, ifid,classindex)) )
	{
		if(lease->expires == server_config[ifid][classindex].inflease_time)
			lease_time_align = server_config[ifid][classindex].inflease_time;
	}

	add_simple_option(packet.options, DHCP_LEASE_TIME, htonl(lease_time_align));

	if(!getHostnameFromPacket(oldpacket, &packet, hostname))
	{
		LOG(LOG_INFO, "SENDING ACK to %s\n",hostname);
	}
	
	/* check if option 125 vendor specific is requested - get multiple occurancies */
	if (check_and_send_vendor_specific_option(oldpacket, packet.options) == 1)
	{
		LOG(LOG_INFO, "SENDING ACK with option 125\n");
	}

	curr = server_config[ifid][classindex].options;
	while (curr) {
		if (curr->data[OPT_CODE] != DHCP_LEASE_TIME)
			add_option_string(packet.options, curr->data);
		curr = curr->next;
	}

	add_bootp_options(&packet, ifid, classindex);

	if (ext_addr) {
		add_ext_assigned_options(&packet, ext_addr);
	}

	addr.s_addr = packet.yiaddr;
	LOG(LOG_INFO, "sending ACK to %s", inet_ntoa(addr));

	if (send_packet(&packet, 0, ifid, classindex) < 0) 
		return -1;

	add_lease(packet.chaddr, packet.yiaddr, lease_time_align, ifid, classindex, hostname);

	return 0;
}


int send_inform(struct dhcpMessage *oldpacket, int ifid, int classindex, int flag43)
{
	struct dhcpMessage packet;
	struct option_set *curr;

	init_packet(&packet, oldpacket, DHCPACK, ifid, classindex, flag43);
	
	curr = server_config[ifid][classindex].options;
	while (curr) {
		if (curr->data[OPT_CODE] != DHCP_LEASE_TIME)
			add_option_string(packet.options, curr->data);
		curr = curr->next;
	}

	add_bootp_options(&packet, ifid,classindex);

	return send_packet(&packet, 0, ifid,classindex);
}



