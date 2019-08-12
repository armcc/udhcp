/* dhcpd_plugin_internal.c
 *
 * Implementation of DHCP server plugin
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
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include "debug.h"
#include "dhcpd.h"
#include "packet.h"
#include "dhcpd_plugin.h"
#include "dhcpd_plugin_internal.h"

/*
 * Number of DHCP discover/request packets we can have stored simultaneously
 * Arbitrarily chosen.
 */
#define DHCPD_PLUGIN_SAVED_PACKET_COUNT 16

/*
 * How long to keep the discover/request packets.  Arbitrarily chosen.
 */
#define DHCPD_PLUGIN_SAVED_PACKET_TIME 10

/*
 * How long to wait for synchronous IPC response.  Arbitrarily chosen.
 */
#define IPC_RESPONSE_WAIT_TIME_US 500000

/*
 * Stores a discover or request from a client that needs to be saved and
 * responded to at a later time.
 */
typedef struct {
    bool                in_use;           /* Is this context being used */
    bool                ready_to_respond; /* Are we able to respond to this */
    /* The actual packet.  Malloced when the packet is saved, 
     * so must be freed when this packet is no longer needed. */
    struct dhcpMessage *packet;
    int                 ifid;             /* ifid as seen by server */
    time_t              save_time;        /* System time when this was saved */
} dhcpd_plugin_deferred_packet_t;


/* Global saved (deferred) DHCP discover and request packets */
dhcpd_plugin_deferred_packet_t 
    stored_packet_table[DHCPD_PLUGIN_SAVED_PACKET_COUNT] = {{0}};

/* The ipc socket we create (server side) */
static int ipc_socket = -1;

/* The ipc socket we get when we accept the connection (client side) */
static int ipc_socket_c = -1;

/*
 * Subtracts the two supplied times and returns the number of microseconds 
 * apart they are.  0 is returned if the "end" time is less than the "start"
 * time.
 */
static unsigned long time_diff_usecs(struct timeval *start, 
                                     struct timeval *end) {
    unsigned long ret = 0;
    
    /* handle when tv_usec rolls over */
    if (start->tv_usec > end->tv_usec) {
        end->tv_usec += 1000000;
        end->tv_sec--;
    }
    
    /* 
     * If, after rollover checking, the start time seconds value is larger than
     * end time, just return 0
     */
    if (end->tv_sec >= start->tv_sec) {
        ret = (end->tv_sec - start->tv_sec) * 1000000;
        ret += end->tv_usec - start->tv_usec;
    }
    
    return ret;
}


/*
 * Creates a socket to use for IPC to the plugin client.
 * The socket is stored in the global var ipc_socket
 * Nothing is done if the socket already exists
 * The socket is left in the listening state and is non-blocking
 */
static void create_ipc_socket(void) {
    bool success = 0;

    if (-1 == ipc_socket) {
        struct sockaddr_un addr;
        int                flags;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strcpy(addr.sun_path, IPC_SOCKET_PATH);
        unlink(IPC_SOCKET_PATH);

        if (0 > (ipc_socket = socket(AF_UNIX, SOCK_STREAM, 0))) {
            LOG(LOG_ERR, "Error opening IPC server socket");
        } else if (0 > bind(ipc_socket, (struct sockaddr *) &addr, sizeof(addr))) {
            LOG(LOG_ERR, "Couldn't bind IPC server socket");
        } else if (0 > listen(ipc_socket, 1)) {
            LOG(LOG_ERR, "Couldn't listen on IPC server socket");
        } else if (-1 == (flags = fcntl(ipc_socket, F_GETFL))) {
            LOG(LOG_ERR, "Couldn't get flags on IPC server socket");
        } else {
            flags |= O_NONBLOCK;
            if (0 > fcntl(ipc_socket, F_SETFL, flags)) {
                LOG(LOG_ERR, "Couldn't set flags on IPC server socket");
            } else {
                success = 1;
            }
        }
        if (!success && (-1 != ipc_socket)) {
            close(ipc_socket);
            ipc_socket = -1;
        }
    }
}

/*
 * Accepts incoming connection, if any.
 * If we are already connected nothing is done.
 * The client socket is stored in ipc_socket_c and is made nonblocking
 */
static void check_for_ipc_connection(void) {
    int flags;

    if (-1 == ipc_socket_c) {
        if (0 > (ipc_socket_c = accept(ipc_socket, NULL, NULL))) {
            ipc_socket_c = -1;
        } else if (-1 == (flags = fcntl(ipc_socket, F_GETFL))) {
            LOG(LOG_ERR, "Couldn't get flags on IPC client socket");
            close(ipc_socket_c);
            ipc_socket_c= -1;
        } else {
            flags |= O_NONBLOCK;
            if (0 > fcntl(ipc_socket_c, F_SETFL, flags)) {
                LOG(LOG_ERR, "Couldn't set flags on IPC client socket");
                close(ipc_socket_c);
                ipc_socket_c= -1;
            } else {
                dhcpd_message_t message;
                int expected_size = sizeof(dhcpd_message_t);
                message.id = DHCPD_SERVER_CONNECTED;
                if (expected_size != send(ipc_socket_c, 
                                          &message, 
                                          expected_size, 
                                          MSG_NOSIGNAL)) {
                    LOG(LOG_ERR, "Failure sending connected message");
                    close(ipc_socket_c);
                    ipc_socket_c= -1;
                } else {
                    LOG(LOG_INFO, "IPC connected to plugin client");
                }
            }
        }
    } else {
        int temp;
        if (0 == recv(ipc_socket_c, &temp, sizeof(temp), MSG_PEEK)) {
            LOG(LOG_ERR, "It appears the client has closed the connection");
            close(ipc_socket_c);
            ipc_socket_c = -1;
        }
    }
}


/* Search for a deferred packet context by ifid and chaddr.  
 * NULL returned if none */
static dhcpd_plugin_deferred_packet_t *
dhcpd_plugin_find_pkt_cxt_by_chaddr(uint8_t *chaddr) {
    unsigned cxt_num = 0;
    dhcpd_plugin_deferred_packet_t *ret = NULL;
    
    for(;cxt_num < DHCPD_PLUGIN_SAVED_PACKET_COUNT; cxt_num++) {
        dhcpd_plugin_deferred_packet_t *cxt = &stored_packet_table[cxt_num];
        
        if (cxt->in_use && 
            (NULL != cxt->packet) &&
            (NULL != chaddr) &&
            (0 == memcmp(cxt->packet->chaddr, chaddr, 6))
           ) {
            ret = cxt;
            break;
        }
    }
    return ret;
}

/* If there's a deferred packet with this ifid and chaddr it is marked for replay 
 * The next time the server checks for pending packets */
static void dhcpd_plugin_mark_packet_for_replay(uint8_t *chaddr) {
    dhcpd_plugin_deferred_packet_t *cxt;
    cxt = dhcpd_plugin_find_pkt_cxt_by_chaddr(chaddr);
    if (NULL != cxt) {
        cxt->ready_to_respond = true;
    }
}

/*
 * Checks for any incoming messages from the plugin client.
 * Only asynchronous messages should arrive in this way
 */
static void check_for_ipc_messages(void) {
    dhcpd_message_t message;
    int             expected_size = sizeof(dhcpd_message_t);
    
    if (-1 != ipc_socket_c) {
        while (expected_size == read(ipc_socket_c, &message, expected_size)) {
            if (message.id == DHCPD_NEW_DEV_FROM_CLIENT) {
                dhcpd_plugin_mark_packet_for_replay(
                    message.new_dev_from_client.chaddr);
            } else {
                LOG(LOG_ERR, "Got unexpected asynch IPC");
            }
        }
    }
}

/* Sends the supplied message, waits for a response with the expected type.
 * Asynchronous messages received when waiting (which might have been in the 
 * socket before the message was sent) are handled as they come.
 * if the expected message is received it is copied to the message pointer.
 */
static int dhcpd_plugin_send_sync_msg(dhcpd_message_t    *message,
                                      dhcpd_message_id_t  expected_response) {
    int ret = -1;
    int expected_size = sizeof(dhcpd_message_t);
    if (expected_size != send(ipc_socket_c, 
                              message, 
                              expected_size, 
                              MSG_NOSIGNAL)) {
        LOG(LOG_ERR, "It appears the client has closed the connection");
    } else {
        struct timeval start_time;
        unsigned long  remaining_time = IPC_RESPONSE_WAIT_TIME_US;

        if (0 > gettimeofday(&start_time, NULL)) {
            LOG(LOG_ERR, "Error reading start time");
        } else {
            do {
                unsigned long  elapsed_time = 0;
                fd_set         rfds;
                struct timeval select_timeout;
                struct timeval curr_time;

                FD_ZERO(&rfds);
                FD_SET(ipc_socket_c, &rfds);
                select_timeout.tv_sec = 0;
                select_timeout.tv_usec = remaining_time;
                
                ret = select(ipc_socket_c+1, 
                             &rfds, 
                             NULL, 
                             NULL, 
                             &select_timeout);
                if (-1 == ret) {
                    LOG(LOG_ERR, "Error from select - IPC client socket");
                    break;
                } else if (0 == ret) {
                    LOG(LOG_ERR, "IPC client didn't respond in time");
                    ret = -1;
                    break;
                } else {
                    if (expected_size == read(ipc_socket_c, 
                                              message,
                                              expected_size)) {
                        if (message->id == DHCPD_NEW_DEV_FROM_CLIENT) {
                            dhcpd_plugin_mark_packet_for_replay(
                                message->new_dev_from_client.chaddr);
                        } else if (message->id == expected_response) {
                            ret = 0;
                            break;
                        } else {
                            LOG(LOG_ERR, "Got unexpected asynch IPC");
                        }
                    }
                }

                if (0 > gettimeofday(&curr_time, NULL)) {
                    LOG(LOG_ERR, "Error reading current time");
                    break;
                }
                elapsed_time = time_diff_usecs(&start_time, &curr_time);
                if (elapsed_time > remaining_time) {
                    remaining_time = 0;
                } else {
                    remaining_time -= elapsed_time;
                }
                
            } while (remaining_time > 0);
            
            if (0 == remaining_time) {
                LOG(LOG_ERR, "IPC client didn't respond in time");
            }
        } /* Got start time */
    } /* send succeeded */

    if (-1 == ret) {
        LOG(LOG_ERR, "Closing IPC connection");
        close(ipc_socket_c);
        ipc_socket_c = -1;
    }

    return ret;
}

/* Search for a. unused deferred packet context.  NULL returned if none */
static dhcpd_plugin_deferred_packet_t *
dhcpd_plugin_find_free_pkt_cxt(void) {
    unsigned cxt_num = 0;
    dhcpd_plugin_deferred_packet_t *ret = NULL;
    
    for(;cxt_num < DHCPD_PLUGIN_SAVED_PACKET_COUNT; cxt_num++) {
        dhcpd_plugin_deferred_packet_t *cxt = &stored_packet_table[cxt_num];
        
        if (!cxt->in_use) {
            ret = cxt;
            break;
        }
    }
    return ret;
}

/* Free any packet contexts that are too old */
void dhcpd_plugin_maintenance(void) {
    unsigned cxt_num = 0;
    time_t curr_time = time(NULL);

    create_ipc_socket();
    check_for_ipc_connection();
    check_for_ipc_messages();


    for(;cxt_num < DHCPD_PLUGIN_SAVED_PACKET_COUNT; cxt_num++) {
        dhcpd_plugin_deferred_packet_t *cxt = &stored_packet_table[cxt_num];
        if (cxt->in_use && 
            (curr_time-cxt->save_time > DHCPD_PLUGIN_SAVED_PACKET_TIME)) {
            if (NULL != cxt->packet) {
                free(cxt->packet);
                cxt->packet = NULL;
            }
            cxt->in_use = false;
        }
    }
}

/* Gets a deferred packet that's ready to be handled and copies it to the 
 * caller's memory.  This removes the packet from the array - we won't store it 
 * anymore.
 * return 0 means we found one.  Other values mean we didn't find one and 
 * packet_dest is unchanged.
 */
int dhcpd_plugin_pop_deferred_packet(int    ifid, 
                                     struct dhcpMessage *packet_dest) {
    unsigned cxt_num = 0;
    int ret = 1;

    for(;cxt_num < DHCPD_PLUGIN_SAVED_PACKET_COUNT; cxt_num++) {
        dhcpd_plugin_deferred_packet_t *cxt = &stored_packet_table[cxt_num];
        if (cxt->in_use && 
            cxt->ready_to_respond && 
            (cxt->ifid == ifid) &&
            (NULL != packet_dest) &&
            (NULL != cxt->packet)
           ) {
            memcpy((void*)packet_dest, 
                   (void*)cxt->packet, 
                   sizeof(struct dhcpMessage));
            free((void *)cxt->packet);
            cxt->packet = NULL;
            cxt->in_use = false;
            ret = 0;
            break;
        }
    }
    return ret;
}

/* Adds given packet into our list of deferred packets.
 * The packet is copied, so the caller can do whatever it wants to the packet
 * after we save it.
 * The packet will be stored until a timeout occurrs, at which time it gets 
 * freed.
 */
static void dhcpd_plugin_save_packet(int ifid,
                                     struct dhcpMessage *packet) {
    dhcpd_plugin_deferred_packet_t *cxt;
    if (NULL == packet) {
        return;
    }
    
    /* See whether we already have something for this HW address.  
     * If yes, use that context. */
    cxt = dhcpd_plugin_find_pkt_cxt_by_chaddr(packet->chaddr);

    /* If not, check for an unused context */
    if (NULL == cxt) {
        cxt = dhcpd_plugin_find_free_pkt_cxt();
    }

    /* If we found a context to store the packet into go ahead */
    if (NULL != cxt) {
        
        /* There's a corner case where the plugin marked this device ready to
         * respond, but before we offered anything another DHCP 
         * discover/request came in for the same HW address.
         * We don't want to clear the ready_to_respond flag in this case */
        if (cxt->in_use && cxt->ready_to_respond) {
             /* Don't clear ready_to_respond in this case */
        } else {
            cxt->ready_to_respond = false;
        }
        cxt->in_use = true;
        
        if (NULL == cxt->packet) {
            cxt->packet = malloc(sizeof(struct dhcpMessage));
            
            /* Check for malloc error case.  The result if failing like this 
             * will be no response to the DHCP message that we're trying
             * to save.
             */
            if (NULL == cxt->packet) {
                cxt->in_use = false;
                return;
            }
        }
        memcpy((void *)cxt->packet, (void *)packet, sizeof(struct dhcpMessage));
        cxt->ifid = ifid;
        cxt->save_time = time(NULL);
    }

    /* If we didn't find a context, the DHCP server will never respond to this 
     * discover/request and the client device will need to wait until it 
     * retransmits another.
     */
}

void dhcpd_plugin_check_dev(int                            ifid,
                            int                            classindex,
                            struct dhcpMessage            *packet,
                            bool                          *skip_response,
                            bool                          *use_ext_addr,
                            dhcpd_dev_check_from_client_t *client_args) {
    dhcpd_message_t   message = {0};

    if (NULL == packet        || 
        NULL == skip_response || 
        NULL == use_ext_addr  || 
        NULL == client_args   ||
        -1 == ipc_socket_c) {
        return;
    }
    *skip_response = false;
    *use_ext_addr = false;

    message.id = DHCPD_DEV_CHECK_TO_CLIENT;

    message.dev_check_to_client.ifid = ifid;
    strncpy(message.dev_check_to_client.ifname, 
            server_config[ifid][classindex].interface, 
            IFNAMSIZ);
    memcpy(message.dev_check_to_client.chaddr, packet->chaddr, DHCPD_MAC_LEN);

    if (0 != dhcpd_plugin_send_sync_msg(&message, DHCPD_DEV_CHECK_FROM_CLIENT)) {
        LOG(LOG_ERR, "Error getting discover response from client!");
    } else {
        switch(message.dev_check_from_client.operation) {
            case DHCPD_DEV_CHECK_OP_PROCEED_WITH_ARGS:
                *use_ext_addr = true;
                memcpy(client_args, 
                       &message.dev_check_from_client,
                       sizeof(dhcpd_dev_check_from_client_t));
                break;
            case DHCPD_DEV_CHECK_OP_DEFER:
                dhcpd_plugin_save_packet(ifid, packet);
                *skip_response = true;
                break;
            case DHCPD_DEV_CHECK_OP_PROCEED_NORMALLY:
                break;
            default:
                LOG(LOG_ERR, "Unknown discover operation%u", 
                    message.dev_check_from_client.operation);
                break;
        }
    }
}


int dhcpd_plugin_socket(void) {
    return ipc_socket_c;
}

void dhcpd_plugin_release_dev(struct dhcpMessage *packet) {
    int expected_size = sizeof(dhcpd_message_t);
    
    if (NULL == packet || -1 == ipc_socket_c) {
        return;
    }
    dhcpd_message_t   message = {0};
    message.id = DHCPD_RELEASE_TO_CLIENT;
    memcpy(message.release_to_client.chaddr, packet->chaddr, DHCPD_MAC_LEN);
    
    if (expected_size != send(ipc_socket_c, 
                              &message, 
                              expected_size,
                              MSG_NOSIGNAL)) {
        LOG(LOG_ERR, "It appears the client has closed the connection");
        close(ipc_socket_c);
        ipc_socket_c = -1;
    }
}

