/* options.h */
#ifndef _OPTIONS_H
#define _OPTIONS_H

#include "packet.h"

#define TYPE_MASK	0x0F
#define OPTION_IP	0x01
#define OPTION_IP_PAIR	0x02
#define OPTION_STRING	0x03
#define OPTION_BOOLEAN	0x04
#define OPTION_U8	0x05
#define OPTION_U16	0x06
#define OPTION_S16	0x07
#define OPTION_U32	0x08
#define OPTION_S32	0x09

#define OPTION_LIST	0x80

struct dhcp_option {
	char name[10];
	char flags;
	char code;
};

extern struct dhcp_option options[];
extern int option_lengths[];

unsigned char *get_option(struct dhcpMessage *packet, int code);
int end_option(unsigned char *optionptr);
int add_option_string(unsigned char *optionptr, unsigned char *string);
int add_simple_option(unsigned char *optionptr, unsigned char code, u_int32_t data);
struct option_set *find_option(struct option_set *opt_list, char code);
void attach_option(struct option_set **opt_list, struct dhcp_option *option, char *buffer, int length);

#endif