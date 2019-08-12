#ifndef _SERVERPACKET_H
#define _SERVERPACKET_H

/* Change Description:07112006
 * 1. Option 43 handling added in init_packet
 * 2. Modified functions to include classindex to indicate correct server_config
 */

#include "dhcpd_plugin.h"

int sendOffer(struct dhcpMessage *oldpacket, int ifid,int classindex,int flag43);
int sendNAK(struct dhcpMessage *oldpacket, int ifid,int classindex,int flag43);
int sendACK(struct dhcpMessage *oldpacket, uint32_t yiaddr, int ifid,int classindex,int flag43, dhcpd_dev_check_from_client_t *ext_addr);
int send_inform(struct dhcpMessage *oldpacket, int ifid,int classindex,int flag43);


#endif
