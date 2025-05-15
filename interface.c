
//
// Copyright (c) 2024-2025, Denny Page
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

    // If a list was previously defined, return error
    if (configured_interface_list != NULL)
    {
        return 1;
    }

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
// Build and validate a list of interfaces for an ip type
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
// Set the configured interface list
//
static void build_interface_peer_lists(
    ip_type_t                   ip_type)
{
    interface_t *               interface;
    interface_t *               peer;
    unsigned int                index;
    unsigned int                peer_index;
    unsigned int                filter_index;

    for (index = 0; index < ip_interface_count[ip_type]; index++)
    {
        interface = ip_interface_list[ip_type][index];

        // Allocate the peer list
        interface->peer_list[ip_type] = calloc(ip_interface_count[ip_type] - 1, sizeof(interface_t *));
        if (interface->peer_list[ip_type] == NULL)
        {
            fatal("Cannot allocate memory: %s\n", strerror(errno));
        }

        // Allocate the peer outbound filter list if used
        if (unique_outbound_filter_count)
        {
            interface->peer_filter_list[ip_type] = calloc(unique_outbound_filter_count, sizeof(filter_list_t *));
            if (interface->peer_filter_list[ip_type] == NULL)
            {
                fatal("Cannot allocate memory: %s\n", strerror(errno));
            }
        }

        // Process the peers
        for (peer_index = 0; peer_index < ip_interface_count[ip_type]; peer_index++)
        {
            peer = ip_interface_list[ip_type][peer_index];
            if (peer == interface)
            {
                // Skip the current interface
                continue;
            }

            // Add the peer to the list
            interface->peer_list[ip_type][interface->peer_count[ip_type]] = peer;
            interface->peer_count[ip_type] += 1;

            // Check if the peer has outbound filtering
            if (peer->outbound_filter_list)
            {
                // Is the filter already in the list?
                for (filter_index = 0; filter_index < interface->peer_filter_count[ip_type]; filter_index++)
                {
                    if (peer->outbound_filter_list == interface->peer_filter_list[ip_type][filter_index])
                    {
                        break;
                    }
                }

                // If the filter is not in the list, add it
                if (filter_index == interface->peer_filter_count[ip_type])
                {
                    interface->peer_filter_list[ip_type][filter_index] = peer->outbound_filter_list;
                    interface->peer_filter_count[ip_type] += 1;
                }
            }
            else
            {
                interface->peer_nofilter_count[ip_type] += 1;
            }
        }
    }
}


//
// Set the configured interface lists and assocated peer lists
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
        build_interface_peer_lists(IPV4);
    }
    if (ip_interface_count[IPV6])
    {
        build_interface_peer_lists(IPV6);
    }
}
