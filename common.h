
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


#ifndef _COMMON_H
#define _COMMON_H 1

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>


// Version number of mdns-bridge
#define VERSION                 "2.2.0"


// Maximum packet size for mDNS per RFC 6762, section 18. Note that this
// size includes the IP/UDP headers, so actual packets will be smaller.
#define MDNS_MAX_PACKET_SIZE    9000

// Addresses and port
#define IPV4_MCAST_ADDRESS      "224.0.0.251"
#define IPV6_MCAST_ADDRESS      "ff02::fb"
#define MCAST_PORT              5353

// DNS type limits
#define DNS_MAX_NAME_LEN        256     // Includes trailing null byte
#define DNS_MAX_LABEL_LEN       64      // Includes leading length byte
#define DNS_MAX_NUM_LABELS      128     // Number of labels in a name


//
// Common types and structures
//

// Socket address and packet structures
typedef union
{
    struct sockaddr_in          sin;
    struct sockaddr_in6         sin6;
    struct sockaddr_storage     storage;
    struct sockaddr             sa;
} socket_address_t;

typedef struct
{
    // Socket source address
    socket_address_t            src_addr;
    socklen_t                   src_addr_len;

    // Current number of bytes in buffer
    unsigned int                bytes;
    unsigned char               buffer[MDNS_MAX_PACKET_SIZE];
} packet_t;


// DNS name structure
typedef struct
{
    uint16_t                    length;
    uint8_t                     count;
    uint8_t                     offset[DNS_MAX_NUM_LABELS];
    unsigned char               labels[DNS_MAX_NAME_LEN];
} dns_name_t;

// DNS matcher structure
typedef struct
{
    uint16_t                    length;
    // NB: The name array MUST be the last entry in the struct because
    //     dns_save_match_name allocates a variable sized struct based on
    //     length of the name.
    unsigned char               labels[];
} dns_match_name_t;


// Filter list strucure
typedef enum
{
    ALLOW                       = 0,
    DENY                        = 1
} filter_allow_deny_t;

typedef struct
{
    filter_allow_deny_t         allow_deny;
    unsigned int                count;
    const dns_match_name_t **   names;
} filter_list_t;


// Interface IP type
typedef enum
{
    IPV4                        = 0,
    IPV6                        = 1
} ip_type_t;
#define NUM_IP_TYPES            2

// Interface structure
typedef struct interface
{
    const char *                name;
    filter_list_t *             inbound_filter_list;
    filter_list_t *             outbound_filter_list;

    unsigned int                if_index;
    unsigned int                disable_ip[NUM_IP_TYPES];

    struct in_addr              ipv4_addr;
    struct in6_addr             ipv6_addr;
    char                        ipv4_addr_str[INET_ADDRSTRLEN];
    char                        ipv6_addr_str[INET6_ADDRSTRLEN];

    int                         sock[NUM_IP_TYPES];

    struct interface **         peer_list[NUM_IP_TYPES];
    unsigned int                peer_count[NUM_IP_TYPES];
    filter_list_t **            peer_filter_list[NUM_IP_TYPES];
    unsigned int                peer_filter_count[NUM_IP_TYPES];
    unsigned int                peer_nofilter_count[NUM_IP_TYPES];
} interface_t;

// DNS state/closure (private to dns decode/encode files)
typedef void *                  dns_state_t;


//
// Global definitions
//

// Configuration filename, defined in main.c
extern const char *             config_filename;

// Warn about dns issues, defined in main.c
extern unsigned int             flag_warn;

// Socket addresses, defined in socket.c
extern struct sockaddr_in       ipv4_any_sockaddr;
extern struct sockaddr_in       ipv4_mcast_sockaddr;
extern struct sockaddr_in6      ipv6_any_sockaddr;
extern struct sockaddr_in6      ipv6_mcast_sockaddr;

// Packet filtering enable flag, defined in filter.c
extern unsigned int             filtering_enabled;

// Global filter list, defined in filter.c
extern filter_list_t *          global_filter_list;

// Count of unique outbound filters in use across all interfaces, defined in filter.c
extern unsigned int             unique_outbound_filter_count;

// Interface lists, defined in interface.c
extern interface_t *            configured_interface_list;
extern unsigned int             configured_interface_count;
extern interface_t **           ip_interface_list[NUM_IP_TYPES];
extern unsigned int             ip_interface_count[NUM_IP_TYPES];


//
// Global functions
//

// Log for abnormal events
__attribute__ ((format (printf, 1, 2)))
extern void logger(
    const char *       format,
    ...);

// Fatal error
__attribute__ ((noreturn, format (printf, 1, 2)))
extern void fatal(
    const char *       format,
    ...);

// Config processing
extern void read_config(void);
extern void dump_config(void);


// Set the interface list
extern unsigned int set_interface_list(
    char **                     list,
    unsigned int                count);

// Get an interface by name
extern interface_t * get_interface_by_name(
    const char *                name);

// Set the configured interface list
extern void set_ip_interface_lists(void);

// Validate configured interfaces against the system interface list
extern void os_validate_interfaces(void);

// Initialize the socket infrastructure
extern void os_initialize_sockets(void);


// Set the global filter list
extern unsigned int set_global_filter_list(
    const filter_allow_deny_t   allow_deny,
    char **                     list,
    unsigned int                count);

// Set an interface inbound filter list
extern unsigned int set_interface_inbound_filter_list(
    interface_t *               interface,
    filter_allow_deny_t         allow_deny,
    char **                     list,
    unsigned int                count);

// Set an interface outbound filter list
extern unsigned int set_interface_outbound_filter_list(
    interface_t *               interface,
    filter_allow_deny_t         allow_deny,
    char **                     list,
    unsigned int                count);

// Check if an inbound name is allowed by the global and inbound interface filter lists
extern unsigned int allowed_inbound(
    const interface_t *         interface,
    const dns_name_t *          name);

// Check if an inbound name is allowed by an outbound interface filter list
unsigned int allowed_outbound(
    const filter_list_t *       filter_list,
    const dns_name_t *          name);


// Create the internal DNS decode state structure
extern dns_state_t dns_state_create(void);

// Save a string as a DNS match name
extern const dns_match_name_t * dns_save_match_name(
    const char *                string);

// Check a DNS name against a DNS match name
extern unsigned int dns_subset_match(
    const dns_name_t *          name,
    const dns_match_name_t *    subset);

// Convert a DNS label sequence to a string
extern void dns_labels_to_string(
    const unsigned char *       labels,
    unsigned int                length,
    unsigned char *             string);

// Decode a DNS packet and apply source filtering
extern unsigned int dns_decode_packet(
    dns_state_t *               dns_state,
    const packet_t *            recv_packet,
    const interface_t *         interface);

// Encode a DNS packet with outbound filtering
extern unsigned int dns_encode_packet(
    dns_state_t *               dns_state,
    const packet_t *            recv_packet,
    packet_t *                  send_packet,
    const filter_list_t *       send_filter_list);

// Create a new DNS packet with outbound filtering
extern unsigned int test_dns_packet_decode(
    const packet_t *            packet);


// The main bridge loops
extern void start_bridges(void);

#endif // _COMMON_H
