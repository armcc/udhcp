/* options.h */
/*-------------------------------------------------------------------------------------
// Copyright 2006, Texas Instruments Incorporated
//
// This program has been modified from its original operation by Texas Instruments
// to do the following:
//
// 1. Added a new function, get_option_length() to get the length of the option value 
//    in the received dhcp packet. This is used in serverpacket.c.
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
 

#ifndef _OPTIONS_H
#define _OPTIONS_H

#include "packet.h"

#define TYPE_MASK	0x0F
/* Change Description:07112006
 * 1. Added options vendorinfo, vendorid and userclass
 */

enum {
	OPTION_IP=1,
	OPTION_IP_PAIR,
	OPTION_STRING,
	OPTION_BOOLEAN,
	OPTION_U8,
	OPTION_U16,
	OPTION_S16,
	OPTION_U32,
	OPTION_S32,
	OPTION_VARIABLE
};

#define OPTION_REQ	0x10 /* have the client request this option */
#define OPTION_LIST	0x20 /* There can be a list of 1 or more of these */

struct dhcp_option {
	char name[10];
	char flags;
	unsigned char code;
};

extern struct dhcp_option options[];
extern int option_lengths[];

int get_option_length(struct dhcpMessage *packet, int code);
unsigned char *get_option(struct dhcpMessage *packet, int code);
unsigned char *get_option_multiple(struct dhcpMessage *packet, int code, int counter);

int end_option(unsigned char *optionptr);
int add_option_string(unsigned char *optionptr, unsigned char *string);
int add_simple_option(unsigned char *optionptr, unsigned char code, uint32_t data);
void erase_option(struct dhcpMessage *packet, unsigned char code);
struct option_set *find_option(struct option_set *opt_list, char code);
void attach_option(struct option_set **opt_list, struct dhcp_option *option, char *buffer, int length);
void delete_all_options(struct option_set **opt_list);

#endif
