
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "common.h"


//
// Ensure we have epoll or kqueue
//
#if defined(__linux__)
# define HAVE_EPOLL
#elif defined(__FreeBSD__) || defined(__APPLE__)
# define HAVE_KQUEUE
#endif

#if defined(HAVE_EPOLL)
# include <sys/epoll.h>
#elif defined(HAVE_KQUEUE)
# include <sys/event.h>
#else
# error epoll or kqueue is required
#endif


//
// Thread local storage for bridge threads
//
typedef struct
{
    // IP type selector:IPV4 or IPV6
    ip_type_t                   ip_type;

    // Interfaces that are part of this bridge
    interface_t **              interface_list;
    unsigned int                interface_count;

    // Destination address for outgoing packets
    socket_address_t            dst_addr;
    socklen_t                   dst_addr_len;

    // DNS decode/encode internal state
    dns_state_t                 dns_state;

    // Receive and send packets
    packet_t                    recv_packet;
    packet_t                    send_packet;
} thread_local_storage_t;



//
// Process an incoming packet
//
static void receive(
    thread_local_storage_t *    local_storage,
    interface_t *               interface)
{
    packet_t *                  packet = &local_storage->recv_packet;
    ip_type_t                   ip_type = local_storage->ip_type;
    ssize_t                     bytes;
    socket_address_t *          dst_addr = &local_storage->dst_addr;
    socklen_t                   dst_addr_len = local_storage->dst_addr_len;
    interface_t *               peer;
    unsigned int                peer_index;
    unsigned int                filter_index;
    filter_list_t *             filter_list;
    unsigned int                r;

    // Receive the packet
    packet->src_addr_len = sizeof(packet->src_addr.storage);
    bytes = recvfrom(interface->sock[ip_type],
                            packet->buffer, sizeof(packet->buffer), 0,
                            &packet->src_addr.sa, &packet->src_addr_len);
    if (bytes == -1)
    {
        logger("recvfrom error on interface %s: %s\n", interface->name, strerror(errno));
        return;
    }
    packet->bytes = bytes;

    // If filter is enabled, decode the packet
    if (filtering_enabled)
    {
        r = dns_decode_packet(local_storage->dns_state, packet, interface);
        if (r == 0)
        {
            // If the decoder found a problem with the packet, or everything has been filtered, drop the packet
            return;
        }
    }

    // Forward the packet to peers that do not have outbound filters
    if (interface->peer_nofilter_count[ip_type])
    {
        if (global_filter_list || interface->inbound_filter_list)
        {
            dns_encode_packet(local_storage->dns_state, &local_storage->recv_packet, &local_storage->send_packet, NULL);
            packet = &local_storage->send_packet;
       }

        for (peer_index = 0; peer_index < interface->peer_count[ip_type]; peer_index++)
        {
            peer = interface->peer_list[ip_type][peer_index];
            if (peer->outbound_filter_list == NULL)
            {
                if (ip_type == IPV6)
                {
                    // Set the destination scope ID
                    dst_addr->sin6.sin6_scope_id = peer->if_index;
                }
                bytes = sendto(peer->sock[ip_type], packet->buffer, packet->bytes, 0, &dst_addr->sa, dst_addr_len);
                if (bytes == -1)
                {
                    logger("sendto error on interface %s: %s\n", peer->name, strerror(errno));
                }
            }
        }
    }

    // Forward the packet to peers that do have outbound filters
    if (interface->peer_filter_count[ip_type])
    {
        packet = &local_storage->send_packet;

        for (filter_index = 0; filter_index < interface->peer_filter_count[ip_type]; filter_index++)
        {
            filter_list = interface->peer_filter_list[ip_type][filter_index];

            r = dns_encode_packet(local_storage->dns_state, &local_storage->recv_packet, &local_storage->send_packet, filter_list);
            if (r == 0)
            {
                // If everything has been filtered, skip the packet
                continue;
            }

            for (peer_index = 0; peer_index < interface->peer_count[ip_type]; peer_index++)
            {
                peer = interface->peer_list[ip_type][peer_index];
                if (peer->outbound_filter_list == filter_list)
                {
                    if (ip_type == IPV6)
                    {
                        // Set the destination scope ID
                        dst_addr->sin6.sin6_scope_id = peer->if_index;
                    }
                    bytes = sendto(peer->sock[ip_type], packet->buffer, packet->bytes, 0, &dst_addr->sa, dst_addr_len);
                    if (bytes == -1)
                    {
                        logger("sendto error on interface %s: %s\n", peer->name, strerror(errno));
                    }
                }
            }
        }
    }
}


//
// Bridge thread
//
#if defined(HAVE_EPOLL)

__attribute__ ((noreturn))
static void * bridge_thread(
    void *                      arg)
{
    thread_local_storage_t *    local_storage = (thread_local_storage_t *) arg;
    ip_type_t                   ip_type = local_storage->ip_type;

    interface_t *               interface;
    unsigned int                index;
    int                         event_fd;
    struct epoll_event          event;
    struct epoll_event *        events;
    int                         num_events;

    // Create the kernel event notifier
    event_fd = epoll_create(ip_interface_count[ip_type]);
    if (event_fd < 0)
    {
        fatal("epoll_create: %s\n", strerror(errno));
    }
    event.events = EPOLLIN;

    // Add the sockets to the event notifier
    events = calloc(ip_interface_count[ip_type], sizeof(struct epoll_event));
    if (events == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }

    for (index = 0; index < ip_interface_count[ip_type]; index++)
    {
        interface = ip_interface_list[ip_type][index];

        event.data.ptr = interface;
        if (epoll_ctl(event_fd, EPOLL_CTL_ADD, interface->sock[ip_type], &event) < 0)
        {
            fatal("epoll_ctl (EPOLL_CTL_ADD): %s\n", strerror(errno));
        }
    }

    // Loop forever waiting for events
    while (1)
    {
        num_events = epoll_wait(event_fd, events, ip_interface_count[ip_type], -1);
        if (num_events < 0 && errno != EINTR)
        {
            logger("epoll_wait: %s\n", strerror(errno));
        }

        for (index = 0; index < (unsigned int) num_events; index++)
        {
            receive(local_storage, (interface_t *) events[index].data.ptr);
        }
    }
}

#elif defined(HAVE_KQUEUE)

__attribute__ ((noreturn))
static void * bridge_thread(
    void *                      arg)
{
    thread_local_storage_t *    local_storage = (thread_local_storage_t *) arg;
    ip_type_t                   ip_type = local_storage->ip_type;
    interface_t *               interface;
    unsigned int                index;
    int                         event_fd;
    struct kevent               event;
    struct kevent *             events;
    int                         num_events;
    int                         r;

    // Create the kernel event notifier
    event_fd = kqueue();
    if (event_fd < 0)
    {
        fatal("kqueue: %s\n", strerror(errno));
    }

    // Add the sockets to the event notifier
    events = calloc(ip_interface_count[ip_type], sizeof(struct kevent));
    if (events == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }

    for (index = 0; index < ip_interface_count[ip_type]; index++)
    {
        interface = ip_interface_list[ip_type][index];

        EV_SET(&event, interface->sock[ip_type], EVFILT_READ, EV_ADD, 0, 0, interface);
        r = kevent(event_fd, &event, 1, NULL, 0, NULL);
        if (r < 0)
        {
            fatal("kevent (EV_SET): %s\n", strerror(errno));
        }
    }

    // Loop forever waiting for events
    while (1)
    {
        num_events = kevent(event_fd, NULL, 0, events, ip_interface_count[ip_type], NULL);
        if (num_events < 0 && errno != EINTR)
        {
            logger("kevent: %s\n", strerror(errno));
        }

        for (index = 0; index < (unsigned int) num_events; index++)
        {
            receive(local_storage, (interface_t *) events[index].udata);
        }
    }
}

#endif


//
// Create the thread local storage structure for a bridge thread
//
static thread_local_storage_t * local_storage_create(
    ip_type_t                   ip_type)
{
    thread_local_storage_t *    local_storage;

    local_storage = calloc(1, sizeof(thread_local_storage_t));
    if (local_storage == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }

    // DNS state for the thread
    local_storage->dns_state = dns_state_create();

    // IP type and destination address for the thread
    local_storage->ip_type = ip_type;
    if (ip_type == IPV4)
    {
        local_storage->dst_addr.sin = ipv4_mcast_sockaddr;
        local_storage->dst_addr_len = sizeof(local_storage->dst_addr.sin);

        // Set send packet address family (principally for debugging purpose)
        local_storage->send_packet.src_addr.sin.sin_family = AF_INET;
        local_storage->send_packet.src_addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    else
    {
        local_storage->dst_addr.sin6 = ipv6_mcast_sockaddr;
        local_storage->dst_addr_len = sizeof(local_storage->dst_addr.sin6);

        // Set send packet address family (principallyfor debugging purpose)
        local_storage->send_packet.src_addr.sin6.sin6_family = AF_INET6;
        local_storage->send_packet.src_addr.sin6.sin6_addr = in6addr_loopback;
    }

    return (local_storage);
}


//
// Start the bridge threads
//
void start_bridges(void)
{
    thread_local_storage_t *    local_storage;

    pthread_t                   thread_id;
    int                         r;

    // NB: Currently, we just split based on IPv4 and IPv6. In the future we
    // may want to split further to limit the number of interfaces per thread.

    // Note that all but the last thread ID created is discarded/lost.

    // Start the IPv4 bridge thread
    if (ip_interface_count[IPV4])
    {
        // Create the thread local storage
        local_storage = local_storage_create(IPV4);

        // The the interface list and count
        local_storage->interface_list = ip_interface_list[IPV4];
        local_storage->interface_count = ip_interface_count[IPV4];

        // Start the thread
        r = pthread_create(&thread_id, NULL, &bridge_thread, local_storage);
        if (r != 0)
        {
            fatal("cannot create IPv4 bridge thread: %s\n", strerror(errno));
        }
    }

    // Start the IPv6 bridge thread
    if (ip_interface_count[IPV6])
    {
        // Create the thread local storage
        local_storage = local_storage_create(IPV6);

        // The the interface list and count
        local_storage->interface_list = ip_interface_list[IPV6];
        local_storage->interface_count = ip_interface_count[IPV6];

        // Start the thread
        r = pthread_create(&thread_id, NULL, &bridge_thread, local_storage);
        if (r != 0)
        {
            fatal("cannot create IPv6 bridge thread: %s\n", strerror(errno));
        }
    }
}
