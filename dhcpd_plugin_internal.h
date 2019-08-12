/* dhcpd_plugin_internal.h
 *
 * Internal definisions for DHCP server plugin
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
#ifndef _DHCPD_PLUGIN_INTERNAL_H
#define _DHCPD_PLUGIN_INTERNAL_H

#include <stdbool.h>
#include "dhcpd_plugin.h"

/* Maintenance */
void dhcpd_plugin_maintenance(void);

/*
 * Asks the client what to do in response to a discover or request
 * skip_response, client_addr, client_args are all outputs.
 * Does nothing if no client is connected.
 */
void dhcpd_plugin_check_dev(int                            ifid,
                            int                            classindex,
                            struct dhcpMessage            *packet,
                            bool                          *skip_response,
                            bool                          *use_ext_addr,
                            dhcpd_dev_check_from_client_t *callee_args);

/* Gets a deferred packet that's ready to be handled and copies it to the 
 * caller's memory.  This removes the packet from the array - we won't store it 
 * anymore.
 * return 0 means we found one.  Other values mean we didn't find one and 
 * packet_dest is unchanged.
 */
int dhcpd_plugin_pop_deferred_packet(int    ifid, 
                                     struct dhcpMessage *packet_dest);

/* Gets the current socket used by the plugin, or -1 if none */
int dhcpd_plugin_socket(void);

/* Notification for DHCP release */
void dhcpd_plugin_release_dev(struct dhcpMessage *packet);


#endif /*_DHCPD_PLUGIN_INTERNAL_H */
