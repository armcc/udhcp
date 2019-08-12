/* leases.h */
/*-------------------------------------------------------------------------------------
// Copyright 2006, Texas Instruments Incorporated
//
// This program has been modified from its original operation by Texas Instruments
// to do the following:
//
// 1. Added hostname to dhcpOfferedAddr
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

#ifndef _LEASES_H
#define _LEASES_H

#include <limits.h>

//#define INF_LEASETIME  	604800
/* Change Description:07112006
 * 1. Modified functions to include classindex to indicate correct server_config
 */

struct dhcpOfferedAddr {
    /* Make sure that the array start is word aligned - required for ARM. */
	uint8_t chaddr[16]; __attribute__ ((aligned));
	uint32_t yiaddr;	/* network order */
	uint32_t expires;	/* host order */
	uint8_t hostname[HOST_NAME_MAX + 1];
};

extern unsigned char blank_chaddr[];

void clear_lease(uint8_t *chaddr, uint32_t yiaddr, int ifid,int classindex);
struct dhcpOfferedAddr *add_lease(uint8_t *chaddr, uint32_t yiaddr, unsigned long lease, int ifid,int classindex,uint8_t *hname);
int lease_expired(struct dhcpOfferedAddr *lease,int ifid,int classindex);
struct dhcpOfferedAddr *oldest_expired_lease(int ifid,int classindex);
struct dhcpOfferedAddr *find_lease_by_chaddr(uint8_t *chaddr, int ifid,int classindex);
struct dhcpOfferedAddr *find_lease_by_yiaddr(uint32_t yiaddr, int ifid,int classindex);
uint32_t find_address(int check_expired, int ifid,int classindex);
int check_ip(uint32_t addr, int ifid, int classindex);

#endif
