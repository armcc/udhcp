/* 
 * options.c -- DHCP server option packet tools 
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 */
 
#include <stdio.h>
#include <stdlib.h>

#include "debug.h"
#include "dhcpd.h"
#include "files.h"
#include "options.h"
#include "leases.h"


/* get an option with bounds checking. */
unsigned char *get_option(struct dhcpMessage *packet, int code)
{
	int i, length;
	static char err[] = "bogus packet, option fields too long."; /* save a few bytes */
	unsigned char *optionptr;
	int over = 0, done = 0, curr = OPTION_FIELD;
	
	optionptr = packet->options;
	i = 0;
	length = 308;
	while (!done) {
		if (i >= length) {
			LOG(LOG_WARNING, err);
			return NULL;
		}
		if (optionptr[i + OPT_CODE] == code) {
			if (i + 1 + optionptr[i + OPT_LEN] >= length) {
				LOG(LOG_WARNING, err);
				return NULL;
			}
			return optionptr + i + 2;
		}			
		switch (optionptr[i + OPT_CODE]) {
		case DHCP_PADDING:
			i++;
			break;
		case DHCP_OPTION_OVER:
			if (i + 1 + optionptr[i + OPT_LEN] >= length) {
				LOG(LOG_WARNING, err);
				return NULL;
			}
			over = optionptr[i + 3];
			i += optionptr[OPT_LEN] + 2;
			break;
		case DHCP_END:
			if (curr == OPTION_FIELD && over & FILE_FIELD) {
				optionptr = packet->file;
				i = 0;
				length = 128;
				curr = FILE_FIELD;
			} else if (curr == FILE_FIELD && over & SNAME_FIELD) {
				optionptr = packet->sname;
				i = 0;
				length = 64;
				curr = SNAME_FIELD;
			} else done = 1;
			break;
		default:
			i += optionptr[OPT_LEN + i] + 2;
		}
	}
	return NULL;
}

/* return the position of the 'end' option (no bounds checking) */
int end_option(unsigned char *optionptr) 
{
	int i = 0;
	
	while (optionptr[i] != DHCP_END) {
		if (optionptr[i] == DHCP_PADDING) i++;
		else i += optionptr[i + OPT_LEN] + 2;
	}
	return i;
}

/* add an option string to the options (an option string contains an option code,
 * length, then data) */
int add_option_string(unsigned char *optionptr, unsigned char *string)
{
	int i, end = end_option(optionptr);
	
	/* end position + string length + option code/length + end option */
	if (end + string[OPT_LEN] + 2 + 1 >= 308) {
		for (i = 0; options[i].code && options[i].code != string[OPT_CODE]; i++);
		LOG(LOG_ERR, "Option %s (0x%02x) did not fit into the packet!", 
			options[i].code ? options[i].name : "unknown", string[OPT_CODE]);
		return 0;
	}
	DEBUG(LOG_INFO, "adding option %02x", string[OPT_CODE]);
	memcpy(optionptr + end, string, string[OPT_LEN] + 2);
	optionptr[end + string[OPT_LEN] + 2] = DHCP_END;
	return string[OPT_LEN] + 2;
}

/* add an option that was loaded from dhcpd.conf to a packet */
int add_stored_option(unsigned char *optionptr, unsigned char code)
{
	struct option_set *curr = config.options;
	
	while (curr && curr->data[OPT_CODE] > code)
		curr = curr->next;
		
	if (curr && curr->data[OPT_CODE] == code) {
		return add_option_string(optionptr, curr->data);
	} else return 0;
}

/* add a one to four byte option to a packet */
int add_simple_option(unsigned char *optionptr, unsigned char code, u_int32_t data)
{
	char length = 0;
	int i, end;

	for (i = 0; options[i].code; i++)
		if (options[i].code == code) {
			length = option_lengths[options[i].flags & TYPE_MASK];
			break;
		}
		
	if (!length) return 0;

	end = end_option(optionptr);
	optionptr[end + OPT_CODE] = code;
	optionptr[end + OPT_LEN] = length;
	switch (length) {
		case 1: optionptr[end + 2] = data; break;
		case 2: *((u_int16_t *) &optionptr[end + 2]) = htons(data); break;
		case 4: *((u_int32_t *) &optionptr[end + 2]) = htonl(data); break;
	}
	optionptr[end + length + 2] = DHCP_END;
	return length;
}

/* find option 'code' in opt_list */
struct option_set *find_option(struct option_set *opt_list, char code)
{
	while (opt_list && opt_list->data[OPT_CODE] < code)
		opt_list = opt_list->next;

	if (opt_list && opt_list->data[OPT_CODE] == code) return opt_list;
	else return NULL;
}

/* add an option to the opt_list */
void attach_option(struct option_set **opt_list, struct dhcp_option *option, char *buffer, int length)
{
	struct option_set *existing, *new, **curr;

	/* add it to an existing option */
	if ((existing = find_option(*opt_list, option->code))) {
		DEBUG(LOG_INFO, "Attaching option %s to existing member of list", option->name);
		if (option->flags & OPTION_LIST) {
			if (existing->data[OPT_LEN] + length <= 255) {
				existing->data = realloc(existing->data, 
						existing->data[OPT_LEN] + length + 2);
				memcpy(existing->data + existing->data[OPT_LEN] + 2, buffer, length);
				existing->data[OPT_LEN] += length;
			} /* else, ignore the data, we could put this in a second option in the future */
		} /* else, ignore the new data */
	} else {
		DEBUG(LOG_INFO, "Attaching option %s to list", option->name);
		
		/* make a new option */
		new = malloc(sizeof(struct option_set));
		new->data = malloc(length + 2);
		new->data[OPT_CODE] = option->code;
		new->data[OPT_LEN] = length;
		memcpy(new->data + 2, buffer, length);
		
		curr = opt_list;
		while (*curr && (*curr)->data[OPT_CODE] < option->code)
			curr = &(*curr)->next;
			
		new->next = *curr;
		*curr = new;		
	}
}
