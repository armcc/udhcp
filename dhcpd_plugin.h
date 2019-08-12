/* dhcpd_plugin.h
 *
 * Interface for DHCP server plugin
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
#ifndef _DHCPD_PLUGIN_H
#define _DHCPD_PLUGIN_H

#include <stdbool.h>
#include <net/if.h>

#define DHCPD_MAC_LEN 6

/*
 * Path used when creating IPC socket
 */
#define IPC_SOCKET_PATH "/var/tmp/dhcpd_ipc"

/*
 * Specifies parameters sent to the plugin client when the server handles
 * a DHCP discover
 * Server to client.
 *
 * The server expects a response to this message, with the parameters from
 * dhcpd_dev_check_from_client_t
 */
typedef struct {
   int      ifid;                  /* Interface ID as seen by the DHCP server */
   char     ifname[IFNAMSIZ];      /* Name of the interface */
   uint8_t  chaddr[DHCPD_MAC_LEN]; /* Client hardware (MAC) address */
} dhcpd_dev_check_to_client_t;



/*
 * Specifies How the DHCP server should proceed with the discover.
 */
typedef enum {
   /* Proceed without using any externally assigned parameters */
   DHCPD_DEV_CHECK_OP_PROCEED_NORMALLY = 300,  
   
   /* Proceed, but use the externally assigned parameters */
   DHCPD_DEV_CHECK_OP_PROCEED_WITH_ARGS,
   
   /* Parameters not known yet, wait before offering an address */
   DHCPD_DEV_CHECK_OP_DEFER
} dhcpd_dev_check_op_t;


/*
 * maximum number of DNS servers the client can pass in
 */
#define DHCPD_MAX_DNS 8

/*
 * Parameters the client uses to control how the DHCP server responds to the 
 * discover.  Sent in response to the parameters in dhcpd_dev_check_to_client_t.
 */
typedef struct {
   /* What to do in response to this discover */
   dhcpd_dev_check_op_t operation;
   
   /* 
    * Parameters to use in case operation is DHCPD_DEV_CHECK_OP_PROCEED_WITH_ARGS 
    * Specifying 0 for a parameter means it won't be used, except for ip_address 
    * which is required.
    */
   struct {
       uint32_t ip_address;
       uint32_t default_gateway;
       uint32_t subnet_mask;
       unsigned dns_server_count;
       uint32_t dns_servers[DHCPD_MAX_DNS];
   } externally_assigned;
   
} dhcpd_dev_check_from_client_t;

/*
 * When the client decides that a previously deferred discover/request can now
 * be handled, it will use these parameters.
 *
 * This is an asynchronous message with no ack from the server.
 */
typedef struct {
   uint8_t  chaddr[DHCPD_MAC_LEN]; /* Client hardware (MAC) address */
} dhcpd_new_dev_from_client_t;

/*
 * Used by the server to notify the client that one of the DHCP clients has
 * released its lease.
 *
 * This is an asynchronous message with no ack from the client.
 */
typedef struct {
   uint8_t  chaddr[DHCPD_MAC_LEN]; /* Client hardware (MAC) address */
} dhcpd_release_to_client_t;

/*
 * Identifier in the plugin message that defines th epayload type 
 */
typedef enum {
    DHCPD_SERVER_CONNECTED = 100, /* No params, no response */
    DHCPD_DEV_CHECK_TO_CLIENT,
    DHCPD_DEV_CHECK_FROM_CLIENT,
    DHCPD_NEW_DEV_FROM_CLIENT,
    DHCPD_RELEASE_TO_CLIENT
} dhcpd_message_id_t;

typedef struct {
    dhcpd_message_id_t id;
    union {
        dhcpd_dev_check_to_client_t dev_check_to_client;
        dhcpd_dev_check_from_client_t dev_check_from_client;
        dhcpd_new_dev_from_client_t new_dev_from_client;
        dhcpd_release_to_client_t release_to_client;
    };
} dhcpd_message_t;


#endif /*_DHCPD_PLUGIN_H */
