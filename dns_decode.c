
//
// Copyright (c) 2024, Denny Page
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
#include <stdarg.h>
#include <errno.h>
#include <netdb.h>

#include "common.h"
#include "dns.h"


// Human readable names for RR types in error messages
static char * rr_section_name[NUM_RR_SECTION_TYPES]   = { "answer", "authority", "additional" };



//
// Log a packet error
//
__attribute__ ((format (printf, 2, 3)))
static void dns_packet_error(
    const packet_t *            packet,
    const char *                format,
    ...)
{
    char                        error_str[1024];
    char                        addr_str[INET6_ADDRSTRLEN];
    va_list                     args;

    // Format the error string
    va_start(args, format);
    vsnprintf(error_str, sizeof(error_str), format, args);
    va_end(args);

    // Format the IP address string
    getnameinfo(&packet->src_addr.sa, packet->src_addr_len, addr_str, sizeof(addr_str), NULL, 0, NI_NUMERICHOST);

    // Log the error
    logger("host %s error decoding packet: %s\n", addr_str, error_str);
}


//
// Create the internal DNS decode state structure
//
dns_state_t dns_state_create(void)
{
    _dns_state_t *          state;

    // Allocate the dns state structure
    state = (_dns_state_t *) calloc(1, sizeof(_dns_state_t));
    if (state == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }

    // Allocate the query list
    state->query_list = calloc(INITIAL_QUERY_COUNT, sizeof(dns_query_t));
    if (state->query_list == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }
    state->allocated_query_count = INITIAL_QUERY_COUNT;

    // Allocate the resource list
    state->rr_list = calloc(INITIAL_RESOURCE_COUNT, sizeof(dns_rr_t));
    if (state->rr_list == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }
    state->allocated_rr_count = INITIAL_RESOURCE_COUNT;

    // Allocate the compression list (calls fatal if memory cannot be allocated)
    clist_alloc(state);

    return ((dns_state_t) state);
}


//
// Check a DNS name against a DNS match name
//
unsigned int dns_subset_match(
    const dns_name_t *          name,
    const dns_match_name_t *    subset)
{
    if (memmem(name->labels, name->length, subset->labels, subset->length))
    {
        return 1;
    }
    return 0;
}


//
// Save a string as a DNS match name
//
// NOTE: This function returns a constant version of dns_match_name_t which is sized
//       to hold only the name provided.
//
const dns_match_name_t * dns_save_match_name(
    const char *                string)
{
    dns_match_name_t *          name;
    unsigned int                string_len;
    unsigned int                name_len;
    unsigned int                string_offset = 0;
    unsigned int                name_offset = 0;
    unsigned int                label_count = 0;
    unsigned int                label_len;
    unsigned int                i;

    // Get the length
    string_len = strlen(string);
    if (string_len < 1 || string_len >= DNS_MAX_NAME_LEN)
    {
        fatal("Invalid DNS name \"%s\"\n", string);
    }
    // NB: +1 is for the initial length byte, other length bytes are accounted for by dots in the string
    name_len = string_len + 1;

    // Allocate the name, but only as large as needed to hold the name
    name = malloc(sizeof(dns_match_name_t) + name_len);
    if (name == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }

    // Initialize the name
    name->length = name_len;

    // Save the labels
    while (string_offset < string_len)
    {
        // Ensure we have a valid label
        label_len = strcspn(string + string_offset, ".");
        label_count += 1;
        if (label_len == 0 || label_len > DNS_MAX_LABEL_LEN || label_count > MAX_NUM_LABELS)
        {
            fatal("Invalid DNS name \"%s\"\n", string);
        }

        // Copy the label
        name->labels[name_offset] = label_len;
        name_offset += 1;
        for (i = 0; i < label_len; i++)
        {
            name->labels[name_offset] = string[string_offset];
            name_offset += 1;
            string_offset += 1;
        }

        // Skip the dot/nul
        string_offset += 1;
    }

    return (name);
}


//
// Convert a DNS label sequence to a string
//
//   NOTE: The string parameter MUST be at least label_len bytes long
//
void dns_labels_to_string(
    const unsigned char *       labels,
    unsigned int                length,
    unsigned char *             string)
{
    unsigned int                labels_offset = 0;
    unsigned int                string_offset = 0;
    unsigned int                label_len;

    // If no length is provided, use the length of the first label
    if (length == 0)
    {
        length = labels[0] + 1;
    }

    while (labels_offset < length)
    {
        label_len = labels[labels_offset];
        if (label_len == 0)
        {
            break;
        }
        labels_offset += 1;

        // Sanity check
        if (labels_offset + label_len > length)
        {
            fatal("Invalid DNS name\n");
        }

        // Add the dot separator
        if (string_offset)
        {
            string[string_offset] = '.';
            string_offset += 1;
        }

        // Copy the label
        memcpy(&string[string_offset], &labels[labels_offset], label_len);
        labels_offset += label_len;
        string_offset += label_len;
    }

    string[string_offset] = 0;
}


//
// Decode (decompress) a sequence of DNS labels in a packet to a DNS name
//
static unsigned int dns_decode_name(
    const packet_t *            packet,
    unsigned int                packet_offset,
    dns_name_t *                name)
{
    unsigned int                label_offset = packet_offset;
    unsigned int                compressed = 0;
    unsigned int                name_offset = 0;
    unsigned int                label_count = 0;
    unsigned int                label_len;
    unsigned int                copy_len;
    unsigned int                pointer;

    while (1)
    {
        label_len = packet->buffer[label_offset];

        // Is it a pointer?
        if (IS_LABEL_POINTER(label_len))
        {
            // Get the pointer
            pointer = POINTER_OFFSET(label_len, packet->buffer[label_offset + 1]);

            // Bounds check on the pointer -- must be after the dns header and before the current label
            if (pointer < sizeof(dns_header_t) || pointer >= label_offset)
            {
                dns_packet_error(packet, "bad label pointer in a name");
                return 0;
            }

            // Account for the label pointer in the packet if appropriate
            if (!compressed)
            {
                packet_offset += 2;
            }
            compressed = 1;

            // Move to the pointer
            label_offset = pointer;
            continue;
        }

        // Record the offset of the label in the name
        name->offset[label_count] = name_offset;

        // Track number of labels and limit DoS
        label_count += 1;
        if (label_count > MAX_NUM_LABELS)
        {
            dns_packet_error(packet, "too many labels in a name");
            return 0;
        }

        // End of the name?
        if (label_len == 0)
        {
            name->labels[name_offset] = 0;
            name->length = name_offset + 1;
            name->count = label_count;

            // Account for the label terminator in the packet if appropriate
            if (!compressed)
            {
                packet_offset += 1;
            }
            return (packet_offset);
        }

        // Length for label copy and bounds check
        // NB: the +1 on the bounds check is to ensure room for the termination label
        copy_len = label_len + 1;
        if (label_offset + copy_len + 1 > packet->bytes || name_offset + copy_len + 1 > sizeof(name->labels))
        {
            dns_packet_error(packet, "name overrun");
            return 0;
        }

        // Copy the label
        memcpy(&name->labels[name_offset], &packet->buffer[label_offset], copy_len);
        name_offset += copy_len;
        label_offset += copy_len;
        if (!compressed)
        {
            // Only increment the packet offset if not already a compressed label
            packet_offset += copy_len;
        }
    }
}


//
// Decode the header of a DNS packet
//
static unsigned int dns_decode_header(
    _dns_state_t *              state,
    const packet_t *            packet)
{
    dns_header_t *              header;
    unsigned int                total_rr_count;
    void *                      np;

    if (packet->bytes < sizeof(dns_header_t))
    {
        dns_packet_error(packet, "dns_decode_header: packet too small");
        return 0;
    }

    // Decode the header
    header = (dns_header_t *) packet->buffer;
    state->recv_query_count = ntohs(header->query_count);
    state->recv_rr_count[RR_ANSWER] = ntohs(header->answer_count);
    state->recv_rr_count[RR_AUTHORITY] = ntohs(header->authority_count);
    state->recv_rr_count[RR_ADDITIONAL] = ntohs(header->additional_count);

    // Grow the query list if necessary
    if (state->recv_query_count > state->allocated_query_count)
    {
        // Sanity check
        if (state->recv_query_count > MAX_QUERY_COUNT)
        {
            dns_packet_error(packet, "too many queries (%u)", state->recv_query_count);
            return 0;
        }

        np = realloc(state->query_list, state->recv_query_count * sizeof(dns_query_t));
        if (np == NULL)
        {
            logger("Cannot allocate memory: %s\n", strerror(errno));
            return 0;
        }
        state->query_list = np;
        state->allocated_query_count = state->recv_query_count;
    }

    // Grow the resource record list if necessary
    total_rr_count = state->recv_rr_count[RR_ANSWER] + state->recv_rr_count[RR_AUTHORITY] + state->recv_rr_count[RR_ADDITIONAL];
    if (total_rr_count > state->allocated_rr_count)
    {
        // Sanity check
        if (total_rr_count > MAX_RESOURCE_COUNT)
        {
            dns_packet_error(packet, "too many resource records (%u)", total_rr_count);
            // Drop the packet
            return 0;
        }

        np = realloc(state->rr_list, total_rr_count * sizeof(dns_rr_t));
        if (np == NULL)
        {
            logger("Cannot allocate memory: %s\n", strerror(errno));
            // Drop the packet
            return 0;
        }
        state->rr_list = np;
        state->allocated_rr_count = total_rr_count;
    }

    return (sizeof(dns_header_t));
}


//
// Decode the query section of a DNS packet and apply source filtering
//
static unsigned int dns_decode_queries(
    _dns_state_t *              state,
    unsigned int                count,
    const interface_t *         interface,
    const packet_t *            packet,
    unsigned int                packet_offset)
{
    dns_query_t *               query;
    unsigned int                index;
    unsigned int                allowed;
    unsigned char               string[DNS_MAX_NAME_LEN];

    for (index = 0; index < count; index++)
    {
        query = &state->query_list[state->query_count];

        // Decode the name
        packet_offset = dns_decode_name(packet, packet_offset, &query->name);
        if (packet_offset == 0)
        {
            // Drop the packet
            return 0;
        }
        query->data = (dns_query_header_t *) (packet->buffer + packet_offset);

        // Sanity check
        if (packet_offset + sizeof(dns_query_header_t) > packet->bytes)
        {
            // Drop the packet
            dns_packet_error(packet, "malformed query");
            return 0;
        }

        // Get the query type
        query->type = ntohs(query->data->type);
        packet_offset += sizeof(dns_query_header_t);

        // Apply source filtering
        // NB: Changes in this switch need to be reflected in the outbound filter switch in dns_packet_encode()
        switch (query->type)
        {
            // These query types are filtered on the owner domain name
            case DNS_TYPE_SRV:
            case DNS_TYPE_TXT:
            case DNS_TYPE_SVCB:
            case DNS_TYPE_HTTPS:
            case DNS_TYPE_ANY:
                allowed = allowed_inbound(interface, &query->name);
                break;

            // These query types are not filtered
            case DNS_TYPE_A:
            case DNS_TYPE_AAAA:
            case DNS_TYPE_PTR:
            case DNS_TYPE_OPT:
                allowed = 1;
                break;

            // Report unknown query types
            default:
                dns_packet_error(packet, "unsupported query type %d (dropped)", query->type);
                dns_labels_to_string(query->name.labels, query->name.length, string);
                logger("(name %s)\n", query->name.labels);
                allowed = 0;
        }

        // Save the query
        if (allowed)
        {
            state->query_count += 1;
        }
    }

    return (packet_offset);
}


//
// Decode the RR sections of a DNS packet and apply source filtering
//
static unsigned int dns_decode_rrs(
    _dns_state_t *              state,
    rr_section_type_t           section_type,
    unsigned int                count,
    const interface_t *         interface,
    const packet_t *            packet,
    unsigned int                packet_offset)
{
    dns_rr_t *                  rr;
    unsigned int                index;
    unsigned int                allowed;
    unsigned int                data_len;
    unsigned int                tmp_offset;
    unsigned char               string[DNS_MAX_NAME_LEN];

    // Set the index for this type
    state->rr_index[section_type] = state->total_rr_count;

    for (index = 0; index < count; index++)
    {
        rr = &state->rr_list[state->total_rr_count];

        // Decode the name
        packet_offset = dns_decode_name(packet, packet_offset, &rr->name);
        if (packet_offset == 0)
        {
            // Drop the packet
            return 0;
        }

        // Sanity check
        if (packet_offset + sizeof(dns_rr_header_t) > packet->bytes)
        {
            // Drop the packet
            dns_packet_error(packet, "malformed %s record", rr_section_name[section_type]);
            return 0;
        }

        // Get the RR Type and data length
        rr->data = (dns_rr_header_t *) (packet->buffer + packet_offset);
        packet_offset += sizeof(dns_rr_header_t);
        rr->type = ntohs(rr->data->type);
        data_len = ntohs(rr->data->rdata_len);

        // Sanity check
        if (data_len == 0 || packet_offset + data_len > packet->bytes)
        {
            // Drop the packet
            dns_packet_error(packet, "invalid rdata length in %s record", rr_section_name[section_type]);
            return 0;
        }

        // Apply source filtering
        // NB: Changes in this switch need to be reflected in the outbound filter switch in dns_packet_encode()
        switch (rr->type)
        {
            // These resource types are filtered on the owner domain name
            case DNS_TYPE_SRV:
            case DNS_TYPE_TXT:
            case DNS_TYPE_HINFO:
            case DNS_TYPE_SVCB:
            case DNS_TYPE_HTTPS:
                allowed = allowed_inbound(interface, &rr->name);
                break;

            // These resource types are filtered on a domain name in the rdata section
            case DNS_TYPE_PTR:
            case DNS_TYPE_CNAME:
            case DNS_TYPE_DNAME:
                tmp_offset = dns_decode_name(packet, packet_offset, &rr->rdata_name);
                if (tmp_offset != packet_offset + data_len)
                {
                    // Drop the packet
                    dns_packet_error(packet, "rdata ptr name corruption in %s record", rr_section_name[section_type]);
                    return 0;
                }

                allowed = allowed_inbound(interface, &rr->rdata_name);
                break;

            // These resource types are not filtered
            case DNS_TYPE_A:
            case DNS_TYPE_AAAA:
            case DNS_TYPE_OPT:
            case DNS_TYPE_NSEC:
                allowed = 1;
                break;

            // Report unknown resource record types
            default:
                dns_packet_error(packet, "unsupported type %d in %s record (dropped)", rr->type, rr_section_name[section_type]);
                dns_labels_to_string(rr->name.labels, rr->name.length, string);
                logger("(name %s, data len %u)\n", rr->name.labels, data_len);
                allowed = 0;
                break;
        }

        // Additional processing for records with domain names in the rdata section
        if (allowed)
        {
            switch (rr->type)
            {
                case DNS_TYPE_SRV:
                    // This type has a fixed length secondary data structure followed by a domain name
                    rr->secondary_len = sizeof(dns_rr_srv_data_t);
                    tmp_offset = packet_offset + rr->secondary_len;
                    tmp_offset = dns_decode_name(packet, tmp_offset, &rr->rdata_name);
                    if (tmp_offset != packet_offset + data_len)
                    {
                        // Drop the packet
                        dns_packet_error(packet, "rdata srv name corruption in %s record", rr_section_name[section_type]);
                        return 0;
                    }
                    break;

                case DNS_TYPE_NSEC:
                    // This type has a domain name followed by variable length secondary data
                    tmp_offset = dns_decode_name(packet, packet_offset, &rr->rdata_name);
                    if (tmp_offset > packet_offset + data_len)
                    {
                        // Drop the packet
                        dns_packet_error(packet, "rdata nsec data name corruption in %s record", rr_section_name[section_type]);
                        return 0;
                    }

                    rr->secondary_len = data_len - (tmp_offset - packet_offset);
                    break;

                default:
                    break;
            }
        }

        // Skip over the RDATA
        packet_offset += data_len;

        // Save the resource record
        if (allowed)
        {
            state->rr_count[section_type] += 1;
            state->total_rr_count += 1;
        }
   }

    return (packet_offset);
}


//
// Decode a DNS packet and apply source filtering
//
unsigned int dns_decode_packet(
    dns_state_t *               dns_state,
    const packet_t *            packet,
    const interface_t *         interface)
{
    _dns_state_t *              state = (_dns_state_t *) dns_state;
    unsigned int                packet_offset;
    rr_section_type_t           rr_section_type;

    // Clear the counters
    state->query_count = 0;
    state->rr_count[RR_ANSWER] = 0;
    state->rr_count[RR_AUTHORITY] = 0;
    state->rr_count[RR_ADDITIONAL] = 0;
    state->total_rr_count = 0;

    // Decode the header
    packet_offset = dns_decode_header(state, packet);

    // Decode the queries
    if (packet_offset && state->recv_query_count)
    {
        packet_offset = dns_decode_queries(state, state->recv_query_count, interface, packet, packet_offset);
    }

    // Decode resource record sections (answer, authority, additional)
    for (rr_section_type = 0; rr_section_type < NUM_RR_SECTION_TYPES; rr_section_type++)
    {
        if (packet_offset && state->recv_rr_count[rr_section_type])
        {
            packet_offset = dns_decode_rrs(state, rr_section_type, state->recv_rr_count[rr_section_type], interface, packet, packet_offset);
        }
    }

    // Check the packet length
    if (packet_offset != packet->bytes)
    {
        // Drop the packet
        dns_packet_error(packet, "decoded length (%u) != packet length (%u)", packet_offset, packet->bytes);
        return 0;
    }

    // If everything has been filtered, drop the packet
    if (state->query_count == 0 &&
        state->rr_count[RR_ANSWER] == 0 &&
        state->rr_count[RR_AUTHORITY] == 0 &&
        state->rr_count[RR_ADDITIONAL] == 0)
    {
        return 0;
    }

    return (packet_offset);
}
