
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
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "common.h"


// Multicast addresses (224.0.0.251 and ff02::fb) in hex
#define IPV4_HEX_MCAST_ADDRESS  0xe00000fb
#define IPV6_HEX_MCAST_ADDRESS  {{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb }}}

// Multicast addresses and port in binary, initialized at runtime in os_initialize_sockets()
static struct in_addr           ipv4_mcast_addr;
struct sockaddr_in              ipv4_any_sockaddr;
struct sockaddr_in              ipv4_mcast_sockaddr;

static struct in6_addr          ipv6_mcast_addr;
struct sockaddr_in6             ipv6_any_sockaddr;
struct sockaddr_in6             ipv6_mcast_sockaddr;


// Determine if an address is an IPv4 Link Local address (169.254/16)
#define MDB_ADDR_IS_IPV4_LL(addr) ((ntohl(addr) & 0xffff0000) == 0xa9fe0000)

// Determine if an address is an IPv6 Link Local address (FE80::/10)
#define MDB_ADDR_IS_IPV6_LL(addr) (addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80)

// Determine if an address is an IPv6 Unique Local address (FC00::/7)
#define MDB_ADDR_IS_IPV6_ULA(addr) ((addr[0] & 0xfe) == 0xfc)



//
// Validate configured interfaces against the system interface list
//
void os_validate_interfaces(void)
{
    interface_t *               interface;
    struct ifaddrs *            ifaddr_list;
    struct ifaddrs *            ifaddr_ptr;
    struct sockaddr_in *        sin;
    struct sockaddr_in6 *       sin6;
    struct sockaddr *           sa;
    unsigned int                index;
    unsigned int                i;
    int                         ipv4_found;
    int                         ipv6_found;

    if (configured_interface_list == NULL)
    {
        fatal("No interface list defined\n");
    }

    // Get interface indexes and validate interface names
    for (index = 0; index < configured_interface_count; index++)
    {
        interface = &configured_interface_list[index];

        interface->if_index = if_nametoindex(interface->name);
        if (interface->if_index == 0)
        {
            fatal("Interface \"%s\" does not exist\n", interface->name);
        }
        for (i = 0; i < index; i++)
        {
            if (interface->if_index == configured_interface_list[i].if_index)
            {
                fatal("Interface \"%s\" and \"%s\" are identical\n", interface->name, configured_interface_list[i].name);
            }
        }
    }

    // Search the system interface list for our selected interfaces and confirm flags and addresses
    if (getifaddrs(&ifaddr_list) == -1)
    {
        fatal("getifaddrs failed: %s\n", strerror(errno));
    }
    for (index = 0; index < configured_interface_count; index++)
    {
        interface = &configured_interface_list[index];
        ipv4_found = 0;
        ipv6_found = 0;

        for (ifaddr_ptr = ifaddr_list; ifaddr_ptr != NULL; ifaddr_ptr = ifaddr_ptr->ifa_next)
        {
            if (strcmp(ifaddr_ptr->ifa_name, interface->name) == 0)
            {
                sa = ifaddr_ptr->ifa_addr;
                if (sa)
                {
                    // Confirm the interface is up and supports multicast
                    if ((ifaddr_ptr->ifa_flags & IFF_UP) == 0)
                    {
                        logger("Interface \"%s\" is not up\n", interface->name);
                    }
                    if ((ifaddr_ptr->ifa_flags & IFF_MULTICAST) == 0)
                    {
                        logger("Interface \"%s\" does not support multicast\n", interface->name);
                    }

                    // Check the IPv4 and IPv6 addresses
                    if (sa->sa_family == AF_INET && interface->disable_ip[IPV4] == 0)
                    {
                        sin = (struct sockaddr_in *) sa;
                        if (ipv4_found)
                        {
                            // Favor global addresses over link-local ones
                            if (MDB_ADDR_IS_IPV4_LL(sin->sin_addr.s_addr))
                            {
                                continue;
                            }
                        }

                        ipv4_found = 1;
                        memcpy(&interface->ipv4_addr, &sin->sin_addr, sizeof(interface->ipv4_addr));
                        inet_ntop(AF_INET, &interface->ipv4_addr, interface->ipv4_addr_str, sizeof(interface->ipv4_addr_str));
                    }
                    else if (sa->sa_family == AF_INET6 && interface->disable_ip[IPV6] == 0)
                    {
                        sin6 = (struct sockaddr_in6 *) sa;
                        if (ipv6_found)
                        {
                            // Favor global addresses over link-local or unique-local
                            if (MDB_ADDR_IS_IPV6_LL(sin6->sin6_addr.s6_addr) || MDB_ADDR_IS_IPV6_ULA(sin6->sin6_addr.s6_addr))
                            {
                                continue;
                            }
                        }

                        ipv6_found = 1;
                        memcpy(&interface->ipv6_addr, &sin6->sin6_addr, sizeof(interface->ipv6_addr));
                        inet_ntop(AF_INET6, &interface->ipv6_addr, interface->ipv6_addr_str, sizeof(interface->ipv6_addr_str));
                    }
                }
            }
        }

        // Add the interface to the IPv4 list, or disable it if does have a valid IPv4 address
        if (ipv4_found)
        {
            ip_interface_count[IPV4] += 1;
        }
        else if (interface->disable_ip[IPV4] == 0)
        {
            logger("Interface \"%s\" does not have an IPv4 address (disabled)\n", interface->name);
            interface->disable_ip[IPV4] = 1;
        }

        // Add the interface to the IPv6 list, or disable it if does have a valid IPv6 address
        if (ipv6_found)
        {
            ip_interface_count[IPV6] += 1;
        }
        else if (interface->disable_ip[IPV6] == 0)
        {
            logger("Interface \"%s\" does not have an IPv6 address (disabled)\n", interface->name);
            interface->disable_ip[IPV6] = 1;
        }
    }

    freeifaddrs(ifaddr_list);
}


//
// Bind an IPv4 socket
//
static void os_bind_ipv4socket(
    interface_t *               interface)
{
    int                         sock;
    const int                   on = 1;
    const int                   off = 0;
    const int                   ttl = 255;
    int                         r;

    struct sockaddr_in          sin;
    struct ip_mreqn             mreq;

    // Create the socket
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1)
    {
        fatal("IPv4 socket creation failed: %s\n", strerror(errno));
    }

    // Set SO_REUSEADDR and SO_REUSEPORT
    r = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));
    if (r == -1)
    {
        fatal("setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
    }
    r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on));
    if (r == -1)
    {
        fatal("setsockopt(SO_REUSEPORT) failed: %s\n", strerror(errno));
    }

    // Set interface specific binding if available
#if defined(SO_BINDTODEVICE)
    r = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface->name, strlen(interface->name));
    if (r == -1)
    {
        fatal("setsockopt (SO_BINDTODEVICE) for IPv4 on %s failed: %s\n", interface->name, strerror(errno));
    }
#elif defined(IP_BOUND_IF)
    r = setsockopt(sock, IPPROTO_IP, IP_BOUND_IF, &interface->if_index, sizeof(interface->if_index));
    if (r == -1)
    {
        fatal("setsockopt (IP_BOUND_IF) for IPv4 on %s failed: %s\n", interface->name, strerror(errno));
    }
#endif

    // Set the ttl
    r = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if (r == -1)
    {
        fatal("setsockopt (IPV6_MULTICAST_IF) for IPv6 on %s failed: %s\n", interface->name, strerror(errno));
    }

    // Set the outbound interface
    r = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &interface->ipv4_addr, sizeof(interface->ipv4_addr));
    if (r == -1)
    {
        fatal("setsockopt (IP_MULTICAST_IF) for IPv4 on %s failed: %s\n", interface->name, strerror(errno));
    }

    // Disable multicast loopback
    r = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void *) &off, sizeof(off));
    if (r == -1)
    {
        fatal("setsockopt (IP_MULTICAST_LOOP) for IPv4 on %s failed: %s\n", interface->name, strerror(errno));
    }

    // Bind the socket
    sin = ipv4_any_sockaddr;
    r = bind(sock, (struct sockaddr *) &sin, sizeof(sin));
    if (r == -1)
    {
        fatal("IPv4 bind to %s on %s failed: %s\n", IPV4_MCAST_ADDRESS, interface->name, strerror(errno));
    }

    // Join the multicast group
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_ifindex = interface->if_index;
    mreq.imr_multiaddr = ipv4_mcast_addr;
    mreq.imr_address = interface->ipv4_addr;
    r = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if (r == -1)
    {
        fatal("setsockopt (IP_ADD_MEMBERSHIP) for IPv4 on %s failed: %s\n", interface->name, strerror(errno));
    }

    // Set non-blocking and return
    (void) fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);

    interface->sock[IPV4] = sock;
}


//
// Bind an IPv6 socket
//
static void os_bind_ipv6socket(
    interface_t *               interface)
{
    int                         sock;
    const int                   on = 1;
    const int                   off = 0;
    const int                   ttl = 255;
    int                         r;

    struct sockaddr_in6         sin6;
    struct ipv6_mreq            mreq6;

    // Create the socket
    sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1)
    {
        fatal("IPv6 socket creation failed: %s\n", strerror(errno));
    }

    // Ensure we don't end up with a mixed IPv4 / IPv6 socket
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &on, sizeof(on));

    // Set SO_REUSEADDR and SO_REUSEPORT
    r = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));
    if (r == -1)
    {
        fatal("setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
    }
    r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on));
    if (r == -1)
    {
        fatal("setsockopt(SO_REUSEPORT) failed: %s\n", strerror(errno));
    }

    // Set interface specific binding if available
#if defined(SO_BINDTODEVICE)
    r = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface->name, strlen(interface->name));
    if (r == -1)
    {
        fatal("setsockopt (SO_BINDTODEVICE) for IPv6 on %s failed: %s\n", interface->name, strerror(errno));
    }
#elif defined(IPV6_BOUND_IF)
    r = setsockopt(sock, IPPROTO_IPV6, IPV6_BOUND_IF, &interface->if_index, sizeof(interface->if_index));
    if (r == -1)
    {
        fatal("setsockopt (IPV6_BOUND_IF) for IPv6 on %s failed: %s\n", interface->name, strerror(errno));
    }
#endif

    // Set the ttl
    r = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
    if (r == -1)
    {
        fatal("setsockopt (IPV6_MULTICAST_IF) for IPv6 on %s failed: %s\n", interface->name, strerror(errno));
    }

    // Set the outbound interface
    r = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &interface->if_index, sizeof(interface->if_index));
    if (r == -1)
    {
        fatal("setsockopt (IPV6_MULTICAST_IF) for IPv6 on %s failed: %s\n", interface->name, strerror(errno));
    }

    // Disable multicast loopback
    r = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (void *) &off, sizeof(off));
    if (r == -1)
    {
        fatal("setsockopt (IPV6_MULTICAST_LOOP) for IPv6 on %s failed: %s\n", interface->name, strerror(errno));
    }

    // Bind the socket
    sin6 = ipv6_any_sockaddr;
    r = bind(sock, (struct sockaddr *) &sin6, sizeof(sin6));
    if (r == -1)
    {
        fatal("IPv6 bind to %s on %s failed: %s\n", IPV6_MCAST_ADDRESS, interface->name, strerror(errno));
    }

    // Join the multicast group
    mreq6.ipv6mr_interface = interface->if_index;
    mreq6.ipv6mr_multiaddr = ipv6_mcast_addr;
    r = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6));
    if (r == -1)
    {
        fatal("setsockopt (IPV6_JOIN_GROUP) for IPv6 on %s failed: %s\n", interface->name, strerror(errno));
    }

    // Set non-blocking and return
    (void) fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);

    interface->sock[IPV6] = sock;
}


//
// Initialize the socket infrastructure
//   - Initialize the addresses used for socket operations
//   - Create and bind sockets for all interfaces
//
void os_initialize_sockets(void)
{
    unsigned int                index;

    // Initializers for socket addresses
    // NB: this must be done at runtime due to use of htonl()/htons()
    const struct in_addr        init_ipv4_mcast_addr =
    {
        .s_addr = htonl(IPV4_HEX_MCAST_ADDRESS)
    };
    const struct in6_addr       init_ipv6_mcast_addr =
        IPV6_HEX_MCAST_ADDRESS;
    const struct sockaddr_in    init_ipv4_any_sockaddr =
    {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(MCAST_PORT),
    };
    const struct sockaddr_in6   init_ipv6_any_sockaddr =
    {
        .sin6_family=AF_INET6,
        .sin6_addr = IN6ADDR_ANY_INIT,
        .sin6_port = htons(MCAST_PORT),
    };
    const struct sockaddr_in    init_ipv4_mcast_sockaddr =
    {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(IPV4_HEX_MCAST_ADDRESS),
        .sin_port = htons(MCAST_PORT),
    };
    const struct sockaddr_in6   init_ipv6_mcast_sockaddr =
    {
        .sin6_family = AF_INET6,
        .sin6_addr = IPV6_HEX_MCAST_ADDRESS,
        .sin6_port = htons(MCAST_PORT),
    };

    // Initialize socket addresses
    ipv4_mcast_addr = init_ipv4_mcast_addr;
    ipv6_mcast_addr = init_ipv6_mcast_addr;
    ipv4_any_sockaddr = init_ipv4_any_sockaddr;
    ipv6_any_sockaddr = init_ipv6_any_sockaddr;
    ipv4_mcast_sockaddr = init_ipv4_mcast_sockaddr;
    ipv6_mcast_sockaddr = init_ipv6_mcast_sockaddr;

    // Bind the IPv4 sockets
    for (index = 0; index < ip_interface_count[IPV4]; index++)
    {
        os_bind_ipv4socket(ip_interface_list[IPV4][index]);
    }

    // Bind the IPv6 sockets
    for (index = 0; index < ip_interface_count[IPV6]; index++)
    {
        os_bind_ipv6socket(ip_interface_list[IPV6][index]);
    }
}
