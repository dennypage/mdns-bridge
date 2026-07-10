
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "common.h"
#include "socketp.h"


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

    // Structures for recvmsg
    struct msghdr               recv_msg;
    struct iovec                recv_iovec;
#if defined(HAVE_IP_RECVIF)
    char                        cmsg_buf[CMSG_SPACE(sizeof(socket_address_t))];
#endif
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
    dest_filter_list_t **       dest_filter_list;
    dest_filter_list_t *        dest_filter;
    interface_t *               peer;
    unsigned int                dest_filter_index;
    unsigned int                peer_index;
    unsigned int                r;

    // Receive the packet
    local_storage->recv_msg.msg_namelen = sizeof(packet->src_addr);
    bytes = recvmsg(interface->sock[ip_type], &local_storage->recv_msg, 0);
    if (bytes == -1)
    {
        logger("recvmsg error on interface %s: %s\n", interface->name, strerror(errno));
        return;
    }
    packet->bytes = bytes;
    packet->src_addr_len = local_storage->recv_msg.msg_namelen;

#if defined(HAVE_IP_RECVIF)
    {
        struct cmsghdr *        cmsg;
        struct sockaddr_dl *    sa_dl;
        interface_t *           new_interface = NULL;
        unsigned int            index;

        for (cmsg = CMSG_FIRSTHDR(&local_storage->recv_msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&local_storage->recv_msg, cmsg))
        {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVIF)
            {
                sa_dl = (struct sockaddr_dl *) CMSG_DATA(cmsg);
                if (interface->if_index != sa_dl->sdl_index)
                {
                    // Look for the correct interface by system interface index
                    for (index = 0; index < local_storage->interface_count; index++)
                    {
                        if (local_storage->interface_list[index]->if_index == sa_dl->sdl_index)
                        {
                            new_interface = local_storage->interface_list[index];
                            break;
                        }
                    }

                    // If no interface is found, skip this message
                    if (new_interface == NULL)
                    {
                        return;
                    }

                    // Assign the correct interface to the packet
                    interface = new_interface;
                }
            }
        }
    }
#endif

    // Decode the packet
    r = dns_decode_packet(local_storage->dns_state, packet, interface);
    if (r == 0)
    {
        // If the decoder found a problem with the packet, or everything has been filtered, drop the packet
        return;
    }

    dest_filter_list = interface->dest_filter_list[ip_type];
    for (dest_filter_index = 0; dest_filter_index < interface->dest_filter_count[ip_type]; dest_filter_index++)
    {
        dest_filter = dest_filter_list[dest_filter_index];

        // Does the packet need to be re-encoded?
        if (dest_filter->filter || dns_src_filter_active(local_storage->dns_state))
        {
            r = dns_encode_packet(local_storage->dns_state, &local_storage->recv_packet, &local_storage->send_packet, dest_filter->filter);
            if (r == 0)
            {
                // If everything has been filtered, skip the packet
                continue;
            }
            packet = &local_storage->send_packet;
        }
        else
        {
            packet = &local_storage->recv_packet;
        }

        // Send the packet to each of the peers
        for (peer_index = 0; peer_index < dest_filter->peer_count; peer_index++)
        {
            peer = dest_filter->peer_list[peer_index];

            if (ip_type == IPV6)
            {
                // Set the destination scope ID
                dst_addr->sin6.sin6_scope_id = peer->if_index;
            }

            bytes = sendto(peer->sock[ip_type], packet->buffer, packet->bytes, 0, &dst_addr->sa, dst_addr_len);
            if (bytes == -1 && errno != ENETDOWN)
            {
                logger("sendto error on interface %s: %s\n", peer->name, strerror(errno));
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
        if (num_events < 0)
        {
            if (errno != EINTR)
            {
                logger("epoll_wait: %s\n", strerror(errno));
            }
            continue;
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
        if (num_events < 0)
        {
            if (errno != EINTR)
            {
                logger("kevent: %s\n", strerror(errno));
            }
            continue;
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

    // Initialize recvmsg structures
    local_storage->recv_msg.msg_name = &local_storage->recv_packet.src_addr;
    local_storage->recv_msg.msg_namelen = sizeof(local_storage->recv_packet.src_addr);
    local_storage->recv_msg.msg_iov = &local_storage->recv_iovec;
    local_storage->recv_msg.msg_iovlen = 1;
    local_storage->recv_iovec.iov_base = local_storage->recv_packet.buffer;
    local_storage->recv_iovec.iov_len = sizeof(local_storage->recv_packet.buffer);
#if defined(HAVE_IP_RECVIF)
    local_storage->recv_msg.msg_control = local_storage->cmsg_buf;
    local_storage->recv_msg.msg_controllen = sizeof(local_storage->cmsg_buf);
#endif

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

        // Set send packet address family (principally for debugging purpose)
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

        // Set the interface list and count
        local_storage->interface_list = ip_interface_list[IPV4];
        local_storage->interface_count = ip_interface_count[IPV4];

        // Start the thread
        r = pthread_create(&thread_id, NULL, &bridge_thread, local_storage);
        if (r != 0)
        {
            fatal("cannot create IPv4 bridge thread: %s\n", strerror(r));
        }
    }

    // Start the IPv6 bridge thread
    if (ip_interface_count[IPV6])
    {
        // Create the thread local storage
        local_storage = local_storage_create(IPV6);

        // Set the interface list and count
        local_storage->interface_list = ip_interface_list[IPV6];
        local_storage->interface_count = ip_interface_count[IPV6];

        // Start the thread
        r = pthread_create(&thread_id, NULL, &bridge_thread, local_storage);
        if (r != 0)
        {
            fatal("cannot create IPv6 bridge thread: %s\n", strerror(r));
        }
    }
}
