/* dhcpd.h */
#ifndef _DHCPC_H
#define _DHCPC_H


#define INIT_SELECTING	0
#define REQUESTING	1
#define BOUND		2
#define RENEWING	3
#define REBINDING	4
#define INIT_REBOOT	5
#define RENEW_REQUESTED 6
#define RELEASED	7


/* Paramaters the client should request from the server */
#define PARM_REQUESTS \
	DHCP_SUBNET, \
	DHCP_ROUTER, \
	DHCP_DNS_SERVER, \
	DHCP_HOST_NAME, \
	DHCP_DOMAIN_NAME, \
	DHCP_BROADCAST


struct client_config_t {
	char *dir;			/* Path containing DHCP client scripts */
	char *prefix;			/* Prefix to add to scripts */
	char interface[10];		/* The name of the interface to use */
	char *clientid;			/* Optional client id to use */
	char *hostname;			/* Optional hostname to use */
	int ifindex;			/* Index number of the interface to use */
	unsigned char arp[6];		/* Our arp address */
};

extern struct client_config_t client_config;


#endif
