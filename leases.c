/* 
 * leases.c -- tools to manage DHCP leases 
 * Russ Dill <Russ.Dill@asu.edu> July 2001
 */

/*-------------------------------------------------------------------------------------
// Copyright 2006, Texas Instruments Incorporated
//
// This program has been modified from its original operation by Texas Instruments
// to do the following:
//
// 1. Modification related support for per interface server_config
// 2. Added a new function write_to_delta() to update a text file (udhcpd.delta) 
//    when ever an IP is allocated or de-allocated to a client device. This allows 
//    udhcpd configuration application to monitor and save the IPs in use. Following 
//    key words are defined for this purpose : LEASE_ADD and LEASE_DEL.
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


#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "debug.h"
#include "dhcpd.h"
#include "files.h"
#include "options.h"
#include "leases.h"
#include "arpping.h"

#define LEASE_DELTA_FILE "/var/tmp/udhcpd.delta"
#define LEASE_ADD	1
#define LEASE_DEL	2

/* Change Description:07112006
 * 1. Modified functions to include classindex to indicate correct server_config
 */

unsigned char blank_chaddr[] = {[0 ... 15] = 0};

/* clear every lease out that chaddr OR yiaddr matches and is nonzero */
void clear_lease(uint8_t *chaddr, uint32_t yiaddr, int ifid, int classindex)
{
	unsigned int i, j;
	
	for (j = 0; j < 16 && !chaddr[j]; j++);
	
	for (i = 0; i < server_config[ifid][classindex].max_leases; i++)
		if ((j != 16 && !memcmp(server_config[ifid][classindex].leases[i].chaddr, chaddr, 16)) ||
		    (yiaddr && server_config[ifid][classindex].leases[i].yiaddr == yiaddr)) {
			memset(&(server_config[ifid][classindex].leases[i]), 0, sizeof(struct dhcpOfferedAddr));
		}
}

void write_to_delta(uint8_t *chaddr, uint32_t yiaddr, uint8_t *hname,unsigned long leasetime,uint8_t action,int classindex)
{
  FILE  *fp;
  char line[HOST_NAME_MAX + 64];
  int count = 0 ;
  char *ip;
  //unsigned long leasetime = 86400;
  struct in_addr addr;

	if (!(fp = fopen(LEASE_DELTA_FILE, "w"))) {
		LOG(LOG_ERR, "Unable to open %s for writing", LEASE_DELTA_FILE);
		return;
	}
	memset(line , 0x00 , sizeof(line) );
  addr.s_addr = yiaddr;
  ip = inet_ntoa(addr);

  if(action == LEASE_ADD){
		count = sprintf(line,"%s %02x:%02x:%02x:%02x:%02x:%02x %s %ld %s %d",
              "ADD",chaddr[0],chaddr[1],chaddr[2],chaddr[3],chaddr[4],chaddr[5],
			ip,leasetime,hname,classindex);
  	}
  else{
		count = sprintf(line,"%s %02x:%02x:%02x:%02x:%02x:%02x %s %ld %s %d",
              "DEL",chaddr[0],chaddr[1],chaddr[2],chaddr[3],chaddr[4],chaddr[5],
			ip,leasetime,hname,classindex);
  	}
	LOG(LOG_INFO, "%s",line); 

  fwrite(line, sizeof(char), count, fp); 
  fclose(fp); 
  return;
}

static int zerohwaddr( uint8_t *chaddr )
{
	int i;
  for(i=0;i<6;i++)
	{
		if( chaddr[i] != 0x00)
			return 0;
	}
	return 1;
}

/*add host parameters to host file*/
static void write_to_host(uint8_t *chaddr, uint32_t yiaddr, int ifid, int classindex, uint8_t *hname)
{
    FILE  *fp;
    char line[HOST_NAME_MAX + 64];
	char macAddrStr[20];
    int count = 0 ;
    char *ip;
    struct in_addr addr;

    memset(line , 0x00 , sizeof(line) );
    addr.s_addr = yiaddr;
    ip = inet_ntoa(addr);
	
    if(server_config[ifid][classindex].host_file)
    { 
        count = sprintf(line,"%02x:%02x:%02x:%02x:%02x:%02x %s %ld %s\n",
                        chaddr[0],chaddr[1],chaddr[2],chaddr[3],chaddr[4],chaddr[5],ip,(unsigned long)0,hname); 

        sprintf(macAddrStr,"%02x:%02x:%02x:%02x:%02x:%02x",
                        chaddr[0],chaddr[1],chaddr[2],chaddr[3],chaddr[4],chaddr[5]);

        if ((fp = fopen(server_config[ifid][classindex].host_file, "a+")))
        {
            char fileline[256];

            while (fgets(fileline, 256, fp) != NULL)
            {                    
                if (strstr(fileline, macAddrStr))
                {                        
                    fclose(fp);
                    return;
                }
            }                
            fwrite(line, sizeof(char), count, fp);
            fclose(fp);
        }
    }
    return;
}

/* add a lease into the table, clearing out any old ones */
struct dhcpOfferedAddr *add_lease(uint8_t *chaddr, uint32_t yiaddr, unsigned long lease, int ifid,int classindex, uint8_t *hname)
{
	struct dhcpOfferedAddr *oldest;
	
	/* clean out any old ones */
	if( !zerohwaddr(chaddr ))
		clear_lease(chaddr, yiaddr, ifid, classindex);
		
	oldest = oldest_expired_lease(ifid,classindex);
	
	if (oldest) {
		memcpy(oldest->chaddr, chaddr, 16);
		strcpy(oldest->hostname, hname);
		oldest->yiaddr = yiaddr;
		if( lease != server_config[ifid][classindex].inflease_time )
			oldest->expires = time(0) + lease;
		else
			oldest->expires = server_config[ifid][classindex].inflease_time; 
		write_to_delta(chaddr,yiaddr,hname,lease,LEASE_ADD,classindex); 
        write_to_host(chaddr, yiaddr, ifid, classindex, hname); 
	}
	
	return oldest;
}


/* true if a lease has expired */
int lease_expired(struct dhcpOfferedAddr *lease, int ifid, int classindex)
{
	if( lease->expires != server_config[ifid][classindex].inflease_time)
		return (lease->expires < (unsigned long) time(0));
	else
		return 0;
}	


/* Find the oldest expired lease, NULL if there are no expired leases */
struct dhcpOfferedAddr *oldest_expired_lease(int ifid,int classindex)
{
	struct dhcpOfferedAddr *oldest = NULL;
	unsigned long oldest_lease = time(0);
	unsigned int i;

	
	for (i = 0; i < server_config[ifid][classindex].max_leases; i++)
	{
		if( server_config[ifid][classindex].leases[i].expires == server_config[ifid][classindex].inflease_time)
			continue;

        if ((server_config[ifid][classindex].leases[i].expires == 0) &&
            (server_config[ifid][classindex].leases[i].yiaddr == 0))
        {
            oldest = &(server_config[ifid][classindex].leases[i]);
            return oldest;
        }
		else if (oldest_lease > server_config[ifid][classindex].leases[i].expires) {
			oldest_lease = server_config[ifid][classindex].leases[i].expires;
			oldest = &(server_config[ifid][classindex].leases[i]);
		}
	}
	return oldest;
		
}


/* Find the first lease that matches chaddr, NULL if no match */
struct dhcpOfferedAddr *find_lease_by_chaddr(uint8_t *chaddr, int ifid, int classindex)
{
	unsigned int i;

	for (i = 0; i < server_config[ifid][classindex].max_leases; i++)
		if (!memcmp(server_config[ifid][classindex].leases[i].chaddr, chaddr, 16)) return &(server_config[ifid][classindex].leases[i]);
	
	return NULL;
}


/* Find the first lease that matches yiaddr, NULL is no match */
struct dhcpOfferedAddr *find_lease_by_yiaddr(uint32_t yiaddr, int ifid,int classindex)
{
	unsigned int i;

	for (i = 0; i < server_config[ifid][classindex].max_leases; i++)
		if (server_config[ifid][classindex].leases[i].yiaddr == yiaddr) return &(server_config[ifid][classindex].leases[i]);
	
	return NULL;
}


/* find an assignable address, it check_expired is true, we check all the expired leases as well.
 * Maybe this should try expired leases by age... */
uint32_t find_address(int check_expired, int ifid,int classindex) 
{
	uint32_t addr, ret;
	struct dhcpOfferedAddr *lease = NULL;		

	addr = ntohl(server_config[ifid][classindex].start); /* addr is in host order here */
	for (;addr <= ntohl(server_config[ifid][classindex].end); addr++) {

		/* ie, 192.168.55.0 */
		if (!(addr & 0xFF)) continue;

		/* ie, 192.168.55.255 */
		if ((addr & 0xFF) == 0xFF) continue;

		/* lease is not taken */
		ret = htonl(addr);
		if ((!(lease = find_lease_by_yiaddr(ret, ifid,classindex)) ||

		     /* or it expired and we are checking for expired leases */
		     (check_expired  && lease_expired(lease,ifid,classindex))) &&

		     /* and it isn't on the network */
	    	     !check_ip(ret, ifid, classindex)) {
			return ret;
			break;
		}
	}
	return 0;
}


/* check is an IP is taken, if it is, add it to the lease table */
int check_ip(uint32_t addr, int ifid,int classindex)
{
	struct in_addr temp;
	unsigned char hwaddr[6];
	
	if (arpping(addr, server_config[ifid][classindex].server, server_config[ifid][classindex].arp, server_config[ifid][classindex].interface,hwaddr) == 0) {
		temp.s_addr = addr;
	 	LOG(LOG_INFO, "%s belongs to someone, reserving it for %ld seconds", 
	 		inet_ntoa(temp), server_config[ifid][classindex].conflict_time);

		printf("%x:%x:%x:%x:%x:%x\n",hwaddr[0],hwaddr[1],hwaddr[2],hwaddr[3],hwaddr[4],hwaddr[5]);

		add_lease(hwaddr, addr, server_config[ifid][classindex].conflict_time, ifid, classindex, "unknown");
		return 1;
	} else return 0;
}

