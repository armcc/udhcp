/*
 * arpping.c
 *
 * Mostly stolen from: dhcpcd - DHCP client daemon
 * by Yoichi Hariguchi <yoichi@fore.com>
 */


#include "arpping.h"

#define DEBUG		0


/* local prototypes */
int arpCheck(u_long inaddr, struct ifinfo *ifbuf, long timeout);
void mkArpMsg(int opcode, u_long tInaddr, u_char *tHaddr, u_long sInaddr, u_char *sHaddr, struct arpMsg *msg);
int openRawSocket (int *s, u_short type);


/* args:	yiaddr - what IP to ping (eg. on the NETtel cb189701)
 * retn: 	1 addr free
 *		0 addr used
 *		-1 error 
 */  
int arpping(u_int32_t yiaddr) {
	int rv;
	struct ifinfo ifbuf;
	int n;
	static int nr = 0;
	unsigned char *ep;
	/*unsigned char ep[6] = {0x00,0xd0,0xcf,0x00,0x01,0x0f};*/
	
	/*
	u_int32_t yiaddr = 0xcb189701;
	u_int32_t yiaddr = 0xcb189778;
	*/
	
	strcpy(ifbuf.ifname, "eth0");
	ifbuf.addr = 0xcb1897aa; /* this addr appears to be irrelevant */
/*	ifbuf.mask = 0xffffff00;
	ifbuf.bcast = 0xcb1897ff; */
	ifbuf.mask = 0x0;
	ifbuf.bcast = 0x0;

#if CONFIG_NETtel
	/* rip the HW addr out of the flash :-) 
	 * points to the memory where hwaddr is located */
	ep = (unsigned char *) (0xf0006000);/* + (nr++ * 6));*/
#if 0
	if ((ep[0] == 0xff) && (ep[1] == 0xff) && (ep[2] == 0xff) &&
	    (ep[3] == 0xff) && (ep[4] == 0xff) && (ep[5] == 0xff)) {
#if DEBUG
		syslog(LOG_INFO, "DHCPD - oops! bad hwaddr (0xff)");
#endif
		return -1;
	} else if ((ep[0] == 0) && (ep[1] == 0) && (ep[2] == 0) &&
	    (ep[3] == 0) && (ep[4] == 0) && (ep[5] == 0)) {
#if DEBUG
		syslog(LOG_INFO, "DHCPD - oops! bad hwaddr (0x00)");
#endif
		return -1;
	}
#endif
#endif
	
#if 0
	printf("arpping hwaddr: ");
#endif
	for(n=0;n<6;n++) {
#if 0
		printf("%02x", ep[n]);
#endif
		ifbuf.haddr[n] = ep[n];
	}
#if 0
	printf("\n");
#endif
	ifbuf.flags = 0;
	
	rv = arpCheck(yiaddr, &ifbuf, 3);
#if 0
	printf("rv = %d (1=free, 0=used)\n", rv);
#endif
	
	return rv;
}


int arpCheck(u_long inaddr, struct ifinfo *ifbuf, long timeout)  {
	int				s;			/* socket */
	int				rv;			/* return value */
	struct sockaddr addr;		/* for interface name */
	struct arpMsg	arp;
	fd_set			fdset;
	struct timeval	tm;
	time_t			prevTime;

	rv = 1;
	openRawSocket(&s, ETH_P_ARP);

	/* send arp request */
	mkArpMsg(ARPOP_REQUEST, inaddr, NULL, ifbuf->addr, ifbuf->haddr, &arp);
	bzero(&addr, sizeof(addr));
	strcpy(addr.sa_data, ifbuf->ifname);
	if ( sendto(s, &arp, sizeof(arp), 0, &addr, sizeof(addr)) < 0 ) {
#if 0
		printf("sendto (arpCheck)");
#endif
		rv = 0;
	}
	
	/* wait arp reply, and check it */
	tm.tv_usec = 0;
	time(&prevTime);
	while ( timeout > 0 ) {
		FD_ZERO(&fdset);
		FD_SET(s, &fdset);
		tm.tv_sec  = timeout;
		if ( select(s+1, &fdset, (fd_set *)NULL, (fd_set *)NULL, &tm) < 0 ) {
#if 0
			printf("select (arpCheck)");
#endif
			rv = 0;
		}
		if ( FD_ISSET(s, &fdset) ) {
			if (recv(s, &arp, sizeof(arp), 0) < 0 ) {
#if 0
				printf("recv (arpCheck)");
#endif
				rv = 0;
			}
			if(arp.operation == htons(ARPOP_REPLY) && bcmp(arp.tHaddr, ifbuf->haddr, 6) == 0 && *((u_int *)arp.sInaddr) == inaddr ) {
				rv = 0;
				break;
			}
		}
		timeout -= time(NULL) - prevTime;
		time(&prevTime);
	}
	close(s);
	return rv;
}

void mkArpMsg(int opcode, u_long tInaddr, u_char *tHaddr,
		 u_long sInaddr, u_char *sHaddr, struct arpMsg *msg) {
	bzero(msg, sizeof(*msg));
	bcopy(MAC_BCAST_ADDR, msg->ethhdr.h_dest, 6); /* MAC DA */
	bcopy(sHaddr, msg->ethhdr.h_source, 6);	/* MAC SA */
	msg->ethhdr.h_proto = htons(ETH_P_ARP);	/* protocol type (Ethernet) */
	msg->htype = htons(ARPHRD_ETHER);		/* hardware type */
	msg->ptype = htons(ETH_P_IP);			/* protocol type (ARP message) */
	msg->hlen = 6;							/* hardware address length */
	msg->plen = 4;							/* protocol address length */
	msg->operation = htons(opcode);			/* ARP op code */
	*((u_int *)msg->sInaddr) = sInaddr;		/* source IP address */
	bcopy(sHaddr, msg->sHaddr, 6);			/* source hardware address */
	*((u_int *)msg->tInaddr) = tInaddr;		/* target IP address */
	if ( opcode == ARPOP_REPLY ) {
		bcopy(tHaddr, msg->tHaddr, 6);		/* target hardware address */
	}
}


int openRawSocket (int *s, u_short type) {
	int optval = 1;

	if((*s = socket (AF_INET, SOCK_PACKET, htons (type))) == -1) {
#if 0
		perror("socket");
		printf("socket err\n");
#endif	
		return -1;
	}
	
	if(setsockopt (*s, SOL_SOCKET, SO_BROADCAST, &optval, sizeof (optval)) == -1) {
#if 0
		perror("setsockopt");
		printf("setsockopt err\n");
#endif	
		return -1;
    }
}

