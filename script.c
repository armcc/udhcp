/* script.c
 *
 * Functions to call the DHCP client notification scripts 
 *
 * Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "options.h"
#include "dhcpd.h"
#include "dhcpc.h"
#include "packet.h"
#include "options.h"
#include "debug.h"

/* get a rough idea of how long an option will be (rounding up...) */
static int max_option_length(char *option, struct dhcp_option *type)
{
	int size = 0;
	
	switch (type->flags & TYPE_MASK) {
	case OPTION_IP:
	case OPTION_IP_PAIR:
		size = (option[OPT_LEN - 2] / 4) * strlen("255.255.255.255 ");
		break;
	case OPTION_STRING:
		size = option[OPT_LEN - 2] + 1;
		break;
	case OPTION_BOOLEAN:
		size = option[OPT_LEN - 2] * strlen("yes ");
		break;
	case OPTION_U8:
		size = option[OPT_LEN - 2] * strlen("255 ");
		break;
	case OPTION_U16:
		size = (option[OPT_LEN - 2] / 2) * strlen("65535 ");
		break;
	case OPTION_S16:
		size = (option[OPT_LEN - 2] / 2) * strlen("-32768 ");
		break;
	case OPTION_U32:
		size = (option[OPT_LEN - 2] / 4) * strlen("4294967295 ");
		break;
	case OPTION_S32:
		size = (option[OPT_LEN - 2] / 4) * strlen("-2147483684 ");
		break;
	}
	
	return size;
}


/* Fill dest with the text of option 'option' */
static void fill_options(char *dest, char *option, struct dhcp_option *type)
{
	int pos;
	u_int16_t val_u16;
	int16_t val_s16;
	u_int32_t val_u32;
	int32_t val_s32;
	struct in_addr in;
	
	if ((type->flags & TYPE_MASK) == OPTION_STRING) {
		strncpy(dest, option, option[OPT_LEN]);
		dest[(int) option[OPT_LEN - 2]] = '\0';
		return;
	}
	
	dest[0] = '\0';
	
	for (pos = 0; pos < option[OPT_LEN - 2]; pos += option_lengths[type->flags & TYPE_MASK]) {
		if (pos) strcat(dest, " ");
		switch (type->flags & TYPE_MASK) {
		case OPTION_IP:
			memcpy(&in.s_addr, option + pos, 4);
			strcat(dest, inet_ntoa(in));
			break;
		case OPTION_IP_PAIR:
			memcpy(&in.s_addr, option + pos, 4);
			strcat(dest, inet_ntoa(in));
			memcpy(&in.s_addr, option + pos + 4, 4);
			strcat(dest, inet_ntoa(in));
			break;
		case OPTION_BOOLEAN:
			strcat(dest, option[pos] ? "yes" : "no");
			break;
		case OPTION_U8:
			sprintf(dest + strlen(dest), "%u", option[pos]);
			break;
		case OPTION_U16:
			memcpy(&val_u16, option + pos, 2);
			sprintf(dest + strlen(dest), "%u", ntohs(val_u16));
			break;
		case OPTION_S16:
			memcpy(&val_s16, option + pos, 2);
			sprintf(dest + strlen(dest), "%d", ntohs(val_s16));
			break;
		case OPTION_U32:
			memcpy(&val_u32, option + pos, 4);
			sprintf(dest + strlen(dest), "%lu", (unsigned long) ntohl(val_u32));
			break;
		case OPTION_S32:
			memcpy(&val_s32, option + pos, 4);
			sprintf(dest + strlen(dest), "%ld", (long) ntohl(val_s32));
			break;
		}
	}
}


/* write out the paramaters to a file */
static void write_pars(struct dhcpMessage *packet)
{
	char file[strlen(client_config.dir) + 
	(client_config.prefix ? strlen(client_config.prefix) : 0) +
	strlen("info") + 1];
		
	int i;
	char *temp, *buff;
	FILE *fp;
	struct in_addr addr;
	
	strcpy(file, client_config.dir);
	if (client_config.prefix) strcat(file, client_config.prefix);
	strcat(file, "info");

	if (!(fp = fopen(file, "w"))) {
		LOG(LOG_ERR, "Could not open %s for writing", file);
		return;
	}
	
	fprintf(fp, "interface %s\n", client_config.interface);
	addr.s_addr = packet->yiaddr;
	fprintf(fp, "ip %s\n", inet_ntoa(addr));
	for (i = 0; options[i].code; i++) {
		if ((temp = get_option(packet, options[i].code))) {
			buff = malloc(max_option_length(temp, &options[i]));
			fill_options(buff, temp, &options[i]);
			fprintf(fp, "%s %s\n", options[i].name, buff);
			free(buff);
		}
	}

	fclose(fp);	
}


/* put all the paramaters into an environment */
static char **fill_envp(struct dhcpMessage *packet)
{
	int num_options = 0;
	int i, j;
	struct in_addr addr;
	char **envp, *temp;

	for (i = 0; options[i].code; i++)
		if (get_option(packet, options[i].code))
			num_options++;
	
	envp = malloc((num_options + 3) * sizeof(char *));
	envp[0] = malloc(strlen("interface=") + strlen(client_config.interface) + 1);
	sprintf(envp[0], "interface=%s", client_config.interface);
	addr.s_addr = packet->yiaddr;
	envp[1] = malloc(strlen("ip=255.255.255.255"));
	sprintf(envp[1], "ip=%s", inet_ntoa(addr));
	for (i = 0, j = 2; options[i].code; i++) {
		if ((temp = get_option(packet, options[i].code))) {
			envp[j] = malloc(max_option_length(temp, &options[i]) + 
					strlen(options[i].name + 1));
			strcpy(envp[j], options[i].name);
			strcat(envp[j], "=");
			fill_options(envp[j] + strlen(envp[j]), temp, &options[i]);
			j++;
		}
	}		
	envp[j] = NULL;
	return envp;
}


/* Call the deconfic script */
void script_deconfig(void)
{
	char file[255 + 5];
	sprintf(file, "%s%sdeconfig", client_config.dir, client_config.prefix);
	if (system(file) < 0)
		LOG(LOG_ERR, "script %s failed: %s", file, sys_errlist[errno]);
}


/* Call a script with a par file and env vars */
static void par_script(struct dhcpMessage *packet, char *name)
{
	int pid;
	char **envp;
	char file[255 + 5];

	write_pars(packet);

	/* call script */
	pid = fork();	
	if (pid) {
		waitpid(pid, NULL, 0);
		return;
	} else if (pid == 0) {
		envp = fill_envp(packet);
		
		/* close fd's? */
		
		/* exec script */
		sprintf(file, "%s%s%s", client_config.dir, client_config.prefix, name);
		DEBUG(LOG_INFO, "execle'ing %s", file);
		execle(file, name, NULL, envp);
		LOG(LOG_ERR, "script %s failed: %s", file, sys_errlist[errno]);
		exit(0);
	}			
}


/* call the renew script */
void script_renew(struct dhcpMessage *packet)
{
	par_script(packet, "renew");
}


/* call the bound script */
void script_bound(struct dhcpMessage *packet)
{
	par_script(packet, "bound");	
}


