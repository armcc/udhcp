/*-------------------------------------------------------------------------------------
// Copyright 2006, Texas Instruments Incorporated
//
// This program has been modified from its original operation by Texas Instruments
// to do the following:
//
// 1. Added changes to define server_config on a per interface basis
// 2. Added a new text file udhcpd.host to allow consistency in host IP. 
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

/* dhcpd.h */
#ifndef _DHCPD_H
#define _DHCPD_H

#include <netinet/ip.h>
#include <netinet/udp.h>

#include "leases.h"
#include "files.h"

/* Change Description:07112006
 * 1. Options added to support DHCPD_VENDOR_INFO, DHCP_USER_CLASS
 * 2. Added classifier information and vendor encapsulated options
 */

/************************************/
/* Defaults _you_ may want to tweak */
/************************************/

/* the period of time the client is allowed to use that address */
#define LEASE_TIME              (60*60*24*10) /* 10 days of seconds */

/* where to find the DHCP server configuration file */
#define DHCPD_CONF_FILE         "/etc/udhcpd.conf"

/*****************************************************************/
/* Do not modify below here unless you know what you are doing!! */
/*****************************************************************/

/* DHCP protocol -- see RFC 2131 */
#define SERVER_PORT		67
#define CLIENT_PORT		68

#define DHCP_MAGIC		0x63825363

/* DHCP option codes (partial list) */
#define DHCP_PADDING		0x00
#define DHCP_SUBNET		0x01
#define DHCP_TIME_OFFSET	0x02
#define DHCP_ROUTER		0x03
#define DHCP_TIME_SERVER	0x04
#define DHCP_NAME_SERVER	0x05
#define DHCP_DNS_SERVER		0x06
#define DHCP_LOG_SERVER		0x07
#define DHCP_COOKIE_SERVER	0x08
#define DHCP_LPR_SERVER		0x09
#define DHCP_HOST_NAME		0x0c
#define DHCP_BOOT_SIZE		0x0d
#define DHCP_DOMAIN_NAME	0x0f
#define DHCP_SWAP_SERVER	0x10
#define DHCP_ROOT_PATH		0x11
#define DHCP_IP_TTL		0x17
#define DHCP_MTU		0x1a
#define DHCP_BROADCAST		0x1c
#define DHCP_NTP_SERVER		0x2a
#define DHCP_VENDOR_INFO	0x2b
#define DHCP_WINS_SERVER	0x2c
#define DHCP_REQUESTED_IP	0x32
#define DHCP_LEASE_TIME		0x33
#define DHCP_OPTION_OVER	0x34
#define DHCP_MESSAGE_TYPE	0x35
#define DHCP_SERVER_ID		0x36
#define DHCP_PARAM_REQ		0x37
#define DHCP_MESSAGE		0x38
#define DHCP_MAX_SIZE		0x39
#define DHCP_T1			0x3a
#define DHCP_T2			0x3b
#define DHCP_VENDOR		0x3c
#define DHCP_CLIENT_ID		0x3d
#define DHCP_USER_CLASS		0x4d
#define DHCP_VENDOR_SPECIFIC 0x7d

#define DHCP_END		0xFF


#define BOOTREQUEST		1
#define BOOTREPLY		2

#define ETH_10MB		1
#define ETH_10MB_LEN		6

#define DHCPDISCOVER		1
#define DHCPOFFER		2
#define DHCPREQUEST		3
#define DHCPDECLINE		4
#define DHCPACK			5
#define DHCPNAK			6
#define DHCPRELEASE		7
#define DHCPINFORM		8

#define BROADCAST_FLAG		0x8000

#define OPTION_FIELD		0
#define FILE_FIELD		1
#define SNAME_FIELD		2

/* miscellaneous defines */
#define TRUE			1
#define FALSE			0
#define MAC_BCAST_ADDR		(unsigned char *) "\xff\xff\xff\xff\xff\xff"
#define OPT_CODE 0
#define OPT_LEN 1
#define OPT_DATA 2


/* handling of vendor specific option 125 */
#define OPT_ENTERPRISE_NUMBER_LEN 4
#define OPT_ENTERPRISE_NUMBER 4491
#define CL_V4EROUTER_CONTAINER_OPTION 3
#define OPT_SUBOPTION_LEN 1
#define OPT_SUBOPTION_CODE 1
#define OPT_VENDOR_SPECIFIC 125
#define OPT_MAX_LEN 256

struct option_set {
	unsigned char *data;
	struct option_set *next;
};
/* 
 * This is the classifier type. The id is be the option based on which 
 * the server defines classes of configuration and value indicates the
 * value of options indicated by id. e.g. id = "vendorid" and value=
 * "udhcp 0.9.7"
 */
typedef struct classifier_type {
	char *id;
	char *value;
}classifier_t;

struct server_config_t {
	uint32_t server;		/* Our IP, in network order */
	uint32_t start;		/* Start address of leases, network order */
	uint32_t end;			/* End of leases, network order */
	struct option_set *options;	/* List of DHCP options loaded from the config file */
	char *interface;		/* The name of the interface to use */
	int ifindex;			/* Index number of the interface to use */
	unsigned char arp[6];		/* Our arp address */
	unsigned long lease;		/* lease time in seconds (host order) */
	unsigned long max_leases; 	/* maximum number of leases (including reserved address) */
	char remaining; 		/* should the lease file be interpreted as lease time remaining, or
			 		 * as the time the lease expires */
	unsigned long auto_time; 	/* how long should udhcpd wait before writing a config file.
					 * if this is zero, it will only write one on SIGUSR1 */
	unsigned long decline_time; 	/* how long an address is reserved if a client returns a
				    	 * decline message */
	unsigned long conflict_time; 	/* how long an arp conflict offender is leased for */
	unsigned long offer_time; 	/* how long an offered address is reserved */
	unsigned long min_lease; 	/* minimum lease a client can request*/
	char *lease_file;
	char *host_file;
	// char *vendor_option_file;	/* file that keeps option 125 received from DHCP Client */
	char *pidfile;
	char *notify_file;		/* What to run whenever leases are written */
	uint32_t siaddr;		/* next server bootp option */
	char *sname;			/* bootp server name */
	char *boot_file;		/* bootp boot file option */
	int  active;
	unsigned long inflease_time;	/* how long is infinite leasetime */
	struct dhcpOfferedAddr *leases;  
	classifier_t classifier; /**/
	char *vendorinfo;
	// char *vendor125_OptionInfo;	/* option 125 from the vendor_option_file */
};	

extern struct server_config_t server_config[MAX_INTERFACES][MAX_CLASSES];
extern struct dhcpOfferedAddr *leases;
		
extern int no_of_ifaces;
extern int interfaces[];
extern int flag43;

extern char *vendor125_OptionInfo;	/* option 125 from the vendor_option_file */
extern char *vendor_option_file;	/* file that keeps option 125 received from DHCP Client */
extern int vendor_option_flag;		/* indicates that the Vendor Specific information shall be updated */

char *vendor125_OptionInfo;
char *vendor_option_file;
int vendor_option_flag;

#endif
