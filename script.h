#ifndef _SCRIPT_H
#define _SCRIPT_H


void script_deconfig(void);
void script_renew(struct dhcpMessage *packet);
void script_bound(struct dhcpMessage *packet);


#endif
