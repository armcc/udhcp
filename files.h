/* files.h */
#ifndef _FILES_H
#define _FILES_H

struct config_keyword {
	char keyword[20];
	int (*handler)(char *line, void *var);
	void *var;
	char def[40];
};

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

int read_config(char *file);
void write_leases(int dummy);
void read_leases(char *file);

#endif