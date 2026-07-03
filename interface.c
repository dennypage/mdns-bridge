
//
// Copyright (c) 2024-2026, Denny Page
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "common.h"


// The list of configured interfaces
interface_t *                   configured_interface_list = NULL;
unsigned int                    configured_interface_count = 0;

// The list of interfaces by IP type
interface_t **                  ip_interface_list[NUM_IP_TYPES]     = { NULL, NULL};
unsigned int                    ip_interface_count[NUM_IP_TYPES]    = { 0, 0 };



//
// Set the configured interface list
//
unsigned int set_interface_list(
    char **                     list,
    unsigned int                count)
{
    unsigned int                index;

    // Allocate the list
    configured_interface_list = calloc(count, sizeof(interface_t));
    if (configured_interface_list == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }

    // Copy the interface names
    for (index = 0; index < count; index++)
    {
        configured_interface_list[index].name = strdup(list[index]);
        if (configured_interface_list[index].name == NULL)
        {
            fatal("Cannot allocate memory: %s\n", strerror(errno));
        }
        configured_interface_list[index].index = index;
    }

    configured_interface_count = count;
    return 0;
}


//
// Get an interface by name
//
interface_t * get_interface_by_name(
    const char *                name)
{
    unsigned int                index;

    for (index = 0; index < configured_interface_count; index++)
    {
        if (strcmp(name, configured_interface_list[index].name) == 0)
        {
            return &configured_interface_list[index];
        }
    }
    return NULL;
}


//
// Get the outbound filter list an interface uses for a peer
//
filter_list_t * get_filter_list_for_peer(
    interface_t *               interface,
    interface_t *               peer)
{
    if (interface->peer_outbound_filter_list && interface->peer_outbound_filter_list[peer->index])
    {
        return interface->peer_outbound_filter_list[peer->index];
    }

    return interface->outbound_filter_list;
}


//
// Build and validate the list of interfaces for an ip type
//
static void build_interface_list(
    ip_type_t                   ip_type)
{
    interface_t *               interface;
    unsigned int                count;
    unsigned int                index;

    count = 0;

    // Build the list of interfaces
    if (ip_interface_count[ip_type] > 1)
    {
        ip_interface_list[ip_type] = calloc(ip_interface_count[ip_type], sizeof(interface_t *));
        if (ip_interface_list[ip_type] == NULL)
        {
            fatal("Cannot allocate memory: %s\n", strerror(errno));
        }

        for (index = 0; index < configured_interface_count; index++)
        {
            interface = &configured_interface_list[index];
            if (configured_interface_list[index].disable_ip[ip_type] == 0)
            {
                ip_interface_list[ip_type][count] = interface;
                count += 1;
            }
        }
    }

    // If there just the one interface, disable it
    if (count < 2)
    {
        for (index = 0; index < configured_interface_count; index++)
        {
            interface = &configured_interface_list[index];
            if (configured_interface_list[index].disable_ip[ip_type] == 0)
            {
                logger("Interface \"%s\" does not have any %s peers (disabled)\n", interface->name, ip_type == IPV4 ? "IPv4" : "IPv6");
                interface->disable_ip[ip_type] = 1;
                break;
            }
        }
        count = 0;
    }

    ip_interface_count[ip_type] = count;
}


//
// Build the interface peer lists
//
static void build_interface_dest_lists(
    ip_type_t                   ip_type)
{
    interface_t *               interface;
    interface_t *               peer;
    filter_list_t *             filter_list;
    dest_filter_list_t *        dest_filter_list;
    dest_filter_list_t **       work_list;
    dest_filter_list_t *        work_list_slot;
    unsigned int                work_list_used;
    unsigned int                interface_index;
    unsigned int                peer_index;
    unsigned int                index;

    // Allocate memory for the work list
    work_list = malloc(ip_interface_count[ip_type] * sizeof(dest_filter_list_t *));
    if (work_list == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }
    for (index = 0; index < ip_interface_count[ip_type]; index++)
    {
        work_list[index] = malloc(ip_interface_count[ip_type] * sizeof(dest_filter_list_t));
        if (work_list[index] == NULL)
        {
            fatal("Cannot allocate memory: %s\n", strerror(errno));
        }
    }

    for (interface_index = 0; interface_index < ip_interface_count[ip_type]; interface_index++)
    {
        interface = ip_interface_list[ip_type][interface_index];

        // Clear the work list
        work_list_used = 0;

        // Process the peers
        for (peer_index = 0; peer_index < ip_interface_count[ip_type]; peer_index++)
        {
            peer = ip_interface_list[ip_type][peer_index];
            if (peer == interface)
            {
                // Skip the current interface
                continue;
            }

            // Get the filter list used by the peer for this interface
            filter_list = get_filter_list_for_peer(peer, interface);

            // Is the filter already in the list?
            for (index = 0; index < work_list_used; index++)
            {
                if (work_list[index]->filter == filter_list)
                {
                    break;
                }
            }

            // Add the filter to the list if it's not already present
            if (index >= work_list_used)
            {
                work_list_slot = work_list[work_list_used];
                work_list_used++;

                // Add the filter to the list
                work_list_slot->filter = filter_list;
                work_list_slot->peer_list[0] = peer;
                work_list_slot->peer_count = 1;

                // Check for other peers
                for (index = peer_index + 1; index < ip_interface_count[ip_type]; index++)
                {
                    peer = ip_interface_list[ip_type][index];
                    if (peer == interface)
                    {
                        // Skip the current interface
                        continue;
                    }

                    // Check the filter list used by the peer for this interface
                    filter_list = get_filter_list_for_peer(peer, interface);
                    if (filter_list == work_list_slot->filter)
                    {
                        work_list_slot->peer_list[work_list_slot->peer_count] = peer;
                        work_list_slot->peer_count++;
                    }
                }
            }
        }

        // Create the the permanent peer filter list array
        interface->dest_filter_count[ip_type] = work_list_used;
        interface->dest_filter_list[ip_type] = malloc(work_list_used * sizeof(dest_filter_list_t *));
        if (work_list == NULL)
        {
            fatal("Cannot allocate memory: %s\n", strerror(errno));
        }

        // Save each peer filter list
        for (index = 0; index < work_list_used; index++)
        {
            // Allocate memory for the peer filter list
            dest_filter_list = malloc(sizeof(dest_filter_list_t) + work_list_slot->peer_count * sizeof(struct interface *));
            if (dest_filter_list == NULL)
            {
                fatal("Cannot allocate memory: %s\n", strerror(errno));
            }
            interface->dest_filter_list[ip_type][index] = dest_filter_list;

            // Copy the filter and peer list from the work list slot
            work_list_slot = work_list[index];
            dest_filter_list->filter = work_list_slot->filter;
            dest_filter_list->peer_count = work_list_slot->peer_count;
            for (peer_index = 0; peer_index < work_list_slot->peer_count; peer_index++)
            {
                dest_filter_list->peer_list[peer_index] = work_list_slot->peer_list[peer_index];
            }

        }
    }

    // Clean up the work list
    for (index = 0; index < ip_interface_count[ip_type]; index++)
    {
        free(work_list[index]);
    }
    free(work_list);
}


//
// Set the configured interface lists and associated peer lists
//
void set_ip_interface_lists(void)
{
    // Build the list of interfaces
    if (ip_interface_count[IPV4])
    {
        build_interface_list(IPV4);
    }
    if (ip_interface_count[IPV6])
    {
        build_interface_list(IPV6);
    }

    // If there are no active interfaces, exit
    if (ip_interface_count[IPV4] == 0 && ip_interface_count[IPV6] == 0)
    {
        fatal("No active IPv4 or IPv6 interfaces... exiting\n");
    }

    // Build the peer lists for each interface
    if (ip_interface_count[IPV4])
    {
        build_interface_dest_lists(IPV4);
    }
    if (ip_interface_count[IPV6])
    {
        build_interface_dest_lists(IPV6);
    }
}
