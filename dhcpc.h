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




struct client_config_t {
	char *dir;
	char *prefix;
	char interface[10];
	char *clientid;
	int ifindex;
	unsigned char arp[6];
};

extern struct client_config_t client_config;


#endif