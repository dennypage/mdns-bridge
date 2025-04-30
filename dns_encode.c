
//
// Copyright (c) 2025, Denny Page
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
#include <netdb.h>

#include "common.h"
#include "dns.h"


// Initializer for the compression list
static const unsigned char local_label[]  = { 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c };
static const unsigned char tcp_label[]    = { 0x04, 0x5f, 0x74, 0x63, 0x70 };
static const compression_entry_t clist_initializer[] =
{
    // label, child_index, child_allocated, child_used, pointer

    // 0: (root)
    { NULL,          1, 1, 1, 0 },

    // 1: local
    { local_label,   2, 2, 1, 0 },

    // 2: local's children
    { tcp_label,     4, 4, 0, 0 },
    { NULL,          0, 0, 0, 0 },

    // 4: tcp's children
    { NULL,          0, 0, 0, 0 },
    { NULL,          0, 0, 0, 0 },
    { NULL,          0, 0, 0, 0 },
    { NULL,          0, 0, 0, 0 }
};
static const unsigned int clist_initializer_count = sizeof(clist_initializer) / sizeof(compression_entry_t);


//
// Allocate the compression list
//
void clist_alloc(
    _dns_state_t *              state)
{
    // NB: clist_initializer_count MUST be larger than clist_initializer_count
    unsigned int                count = clist_initializer_count * 16;

    state->clist = calloc(count, sizeof(compression_entry_t));
    if (state->clist == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }
    state->allocated_clist_count = count;
}


//
// Reset the compression list
//
static void clist_reset(
    _dns_state_t *              state)
{
    unsigned int                len;

    // Clear any entries following the initializer
    if (state->used_clist_count > clist_initializer_count)
    {
        len = state->used_clist_count * sizeof(compression_entry_t) - sizeof(clist_initializer);
        memset((void *) state->clist + sizeof(clist_initializer), 0, len);
    }

    // Copy the initializer in place
    memcpy(state->clist, clist_initializer, sizeof(clist_initializer));
    state->used_clist_count = clist_initializer_count;
}

//
// Expand the compression list by adding addtional entries at the end
//
static compression_entry_t * clist_expand(
    _dns_state_t *              state,
    const unsigned int          count)
{
    compression_entry_t *       new_pointer;
    unsigned int                new_count;

    // Reallocate the array
    new_count = state->allocated_clist_count + count;
    new_pointer = realloc(state->clist, new_count * sizeof(compression_entry_t));
    if (new_pointer == NULL)
    {
        logger("Cannot allocate memory to expand compression list: %s\n", strerror(errno));
        return NULL;
    }

    // Initialize the new entries
    memset(&new_pointer[state->allocated_clist_count], 0, count * sizeof(compression_entry_t));

    // Update the state
    state->clist = new_pointer;
    state->allocated_clist_count = new_count;

    return new_pointer;
}


//
// Open a space in the compression list
//
static unsigned int clist_open(
    _dns_state_t *              state,
    const unsigned int          index,
    const unsigned int          count)
{
    unsigned int                len;
    unsigned int                i;

    // Expand the array if necessary
    if (state->used_clist_count + count >= state->allocated_clist_count)
    {
        if (clist_expand(state, count) == NULL)
        {
            return 0;
        }
    }

    // Move things if we are not at the end of the list
    if (index < state->used_clist_count)
    {
        // Update child indexes
        for (i = 0; i < state->used_clist_count; i++)
        {
            if (state->clist[i].child_index >= index)
            {
                state->clist[i].child_index += count;
            }
        }

        // Open the space
        len = (state->used_clist_count - index) * sizeof(compression_entry_t);
        memmove(&state->clist[index + count], &state->clist[index], len);

        // Initialize the new entries
        len = count * sizeof(compression_entry_t);
        memset(&state->clist[index], 0, len);
    }

    // Update the state
    state->used_clist_count += count;

    return index;
}


//
// Find or add a label in a parent's list
//
static unsigned int clist_get_child(
    _dns_state_t *              state,
    const unsigned int          parent,
    const unsigned char *       label)
{
    unsigned int                limit;
    unsigned int                index;
    unsigned int                count;

    // If the parent has children, see if the label is already there
    if (state->clist[parent].child_used)
    {
        limit = state->clist[parent].child_index + state->clist[parent].child_used;

        for (index = state->clist[parent].child_index; index < limit; index++)
        {
            // Compare the labels
            if (label[0] == state->clist[index].label[0] && memcmp(label + 1, state->clist[index].label + 1, label[0]) == 0)
            {
                return index;
            }
        }
    }

    // If the parent doesn't have a child index, assign it
    if (state->clist[parent].child_allocated == 0)
    {
        state->clist[parent].child_index = state->used_clist_count;
    }

    // Where the child will go
    index = state->clist[parent].child_index + state->clist[parent].child_used;

    // Expand the children array if needed
    if (state->clist[parent].child_used >= state->clist[parent].child_allocated)
    {
        // Double the allocated count to limit the number of calls to open
        if (state->clist[parent].child_allocated)
        {
            count = state->clist[parent].child_allocated;
        }
        else
        {
            count = 1;
        }

        // Open the space
        index = clist_open(state, index, count);
        if (index == 0)
        {
            return 0;
        }

        state->clist[parent].child_allocated += count;
    }

    // Increment the parent's child count
    state->clist[parent].child_used += 1;

    // Assign the label and return
    state->clist[index].label = label;
    return index;
}


//
// Encode a DNS name with compression
//
static unsigned int dns_encode_name(
    _dns_state_t *              state,
    packet_t *                  send_packet,
    unsigned int                packet_offset,
    const dns_name_t *          name)
{
    const unsigned char *       label;
    unsigned int                ancestor_index;
    unsigned int                parent_index;
    unsigned int                child_index;
    unsigned int                name_index;
    unsigned int                copy_len;
    unsigned int                remaining;

    // If the name contians only the root label, it cannot be compressed
    if (name->count <= 1)
    {
        send_packet->buffer[packet_offset] = 0;
        packet_offset += 1;
        return packet_offset;
    }

    // The first entry in the compression list is the root label
    parent_index = 0;

    // Number of remaining labels in the name
    remaining = name->count - 1;

    // Loop through the name
    while (remaining > 0)
    {
        remaining -= 1;

        // Get the current label
        name_index = remaining;
        label = name->labels + name->offset[name_index];

        // Add the label in the parent's child list
        child_index = clist_get_child(state, parent_index, label);
        if (child_index == 0)
        {
            // Memory allocation failure
            return 0;
        }

        // If the label doesn't exist in the packet, we know we are done searching and that all
        // the remaining labels need to be added to the packet and to the compression list.
        if (state->clist[child_index].pointer == 0)
        {
            break;
        }

        // Is this the last label?
        if (remaining <= 0)
        {
            // This name is fully a duplicate of a name already in the packet,
            // and can be encoded as a single pointer
            memcpy(send_packet->buffer + packet_offset, &state->clist[child_index].pointer, sizeof(state->clist[child_index].pointer));
            packet_offset += sizeof(state->clist[child_index].pointer);

            return packet_offset;
        }

        // Adopt the new parent, and move to the next label
        parent_index = child_index;
    }

    // If the label doesn't exist in the packet, we know we are done and that the remaining
    // labels need to be added to the packet and to the compression list.
    ancestor_index = parent_index;

    // Expand the array if necessary
    if (state->used_clist_count + remaining > state->allocated_clist_count)
    {
        if (clist_expand(state, remaining) == NULL)
        {
            // Memory allocation failure
            return 0;
        }
    }

    // Copy the labels to the packet
    copy_len = name->offset[name_index] + label[0] + 1;
    memcpy(send_packet->buffer + packet_offset, name->labels, copy_len);

    // Set the pointer for the current label
    state->clist[child_index].pointer = OFFSET_TO_POINTER(packet_offset + name->offset[name_index]);

    // Add any remaining labels to the compression list
    while (remaining > 0)
    {
        remaining -= 1;

        // The child becomes a parent
        parent_index = child_index;

        // Get the current label
        name_index = remaining;
        label = name->labels + name->offset[name_index];

        // Add the child and set the pointer
        child_index = clist_get_child(state, parent_index, label);
        if (child_index == 0)
        {
            // Memory allocation failure
            return 0;
        }
        state->clist[child_index].pointer = OFFSET_TO_POINTER(packet_offset + name->offset[name_index]);
    }

    // Update the packet offset and add the ancestor's pointer or the root zone to the packet
    packet_offset += copy_len;
    if (state->clist[ancestor_index].pointer)
    {
        memcpy(send_packet->buffer + packet_offset, &state->clist[ancestor_index].pointer, sizeof(state->clist[ancestor_index].pointer));
        packet_offset += sizeof(state->clist[ancestor_index].pointer);
    }
    else
    {
        send_packet->buffer[packet_offset] = 0;
        packet_offset += 1;
    }

    return packet_offset;
}


//
// Encode queries with outbound filtering
//
static unsigned int dns_encode_queries(
    _dns_state_t *              state,
    packet_t *                  send_packet,
    unsigned int                packet_offset,
    const filter_list_t *       send_filter_list,
    unsigned int *              allowed_count)
{
    dns_query_t *               query;
    dns_query_header_t *        query_header;
    unsigned int                index;
    unsigned int                allowed;

    *allowed_count = 0;

    // Build the queries
    for (index = 0; index < state->query_count; index++)
    {
        query = &state->query_list[index];

        // Apply outbound filtering
        // NB: Entries in this switch need to match the source filter switch in dns_decode_queries()
        switch (query->type)
        {
            // These query types are filtered on the owner domain name
            case DNS_TYPE_SRV:
            case DNS_TYPE_TXT:
            case DNS_TYPE_ANY:
                allowed = allowed_outbound(send_filter_list, &query->name);
               break;

            // Other query types are not filtered
            default:
                allowed = 1;
                break;
        }

        if (allowed)
        {
            // Encode the name
            packet_offset = dns_encode_name(state, send_packet, packet_offset, &query->name);

            // Set the header elements
            query_header = (dns_query_header_t *) (send_packet->buffer + packet_offset);
            query_header->type = query->data->type;
            query_header->class = query->data->class;
            packet_offset += sizeof(dns_query_header_t);

            *allowed_count += 1;
        }
    }

    return packet_offset;
}


//
// Encode resource records with outbound filtering
//
static unsigned int dns_encode_rrs(
    _dns_state_t *              state,
    const rr_section_type_t     section_type,
    packet_t *                  send_packet,
    unsigned int                packet_offset,
    const filter_list_t *       send_filter_list,
    unsigned int *              allowed_count)
{
    dns_rr_t *                  rr;
    dns_rr_header_t *           rr_header;

    unsigned int                index;
    unsigned int                allowed;
    unsigned int                rdata_offset;

    unsigned char *             secondary_data;
    unsigned int                len;

    *allowed_count = 0;

    for (index = state->rr_index[section_type]; index < state->rr_index[section_type] + state->rr_count[section_type]; index++)
    {
        rr = &state->rr_list[index];

        // Apply outbound filtering
        // NB: Entries in this switch need to match the source filter switch in dns_decode_rrs()
        switch (rr->type)
        {
            // These resource types are filtered on the owner domain name
            case DNS_TYPE_SRV:
            case DNS_TYPE_TXT:
            case DNS_TYPE_HINFO:
                allowed = allowed_outbound(send_filter_list, &rr->name);
                break;

            // These resource types are filtered on a domain name in the data section
            case DNS_TYPE_PTR:
            case DNS_TYPE_CNAME:
            case DNS_TYPE_DNAME:
                allowed = allowed_outbound(send_filter_list, &rr->rdata_name);
                break;

            // Other resource types are not filtered
            default:
                allowed = 1;
                break;
        }

        if (allowed)
        {
            // Encode the name
            packet_offset = dns_encode_name(state, send_packet, packet_offset,&rr->name);

            // Set the header elements
            rr_header = (dns_rr_header_t *) (send_packet->buffer + packet_offset);
            rr_header->type = rr->data->type;
            rr_header->class = rr->data->class;
            rr_header->ttl = rr->data->ttl;
            packet_offset += sizeof(dns_rr_header_t);

            // Set the rdata
            rdata_offset = packet_offset;
            switch (rr->type)
            {
                // These types simply have a domain name in the rdata section
                case DNS_TYPE_PTR:
                case DNS_TYPE_CNAME:
                case DNS_TYPE_DNAME:
                    // Encode the name
                    packet_offset = dns_encode_name(state, send_packet, packet_offset, &rr->rdata_name);
                    break;

                // This type has a fixed length secondary data structure followed by a domain name
                case DNS_TYPE_SRV:
                    // Copy the secondary data from the original packet
                    secondary_data = (unsigned char *) rr->data + sizeof(dns_rr_header_t);
                    memcpy(send_packet->buffer + packet_offset, secondary_data, rr->secondary_len);
                    packet_offset += rr->secondary_len;

                    // Encode the name
                    packet_offset = dns_encode_name(state, send_packet, packet_offset, &rr->rdata_name);
                    break;

                // This type has a domain name followed by variable length secondary data
                case DNS_TYPE_NSEC:
                    // Encode the name
                    packet_offset = dns_encode_name(state, send_packet, packet_offset, &rr->rdata_name);

                    // Copy the secondary data from the original packet
                    secondary_data = (unsigned char *) rr->data + sizeof(dns_rr_header_t);
                    secondary_data += ntohs(rr->data->rdata_len) - rr->secondary_len;
                    memcpy(send_packet->buffer + packet_offset, secondary_data, rr->secondary_len);
                    packet_offset += rr->secondary_len;
                    break;

                // These types do not have a domain name in the rdata section
                default:
                    // Get the length and data from the original packet
                    len = ntohs(rr->data->rdata_len);
                    memcpy(send_packet->buffer + packet_offset, (unsigned char *) rr->data + sizeof(dns_rr_header_t), len);
                    packet_offset += len;
                    break;
            }

            // Set the data length in the rr header
            rr_header->rdata_len = htons(packet_offset - rdata_offset);

            *allowed_count += 1;
        }
    }

    return packet_offset;
}


//
// Encode a DNS packet with outbound filtering
//
unsigned int dns_encode_packet(
    dns_state_t *               dns_state,
    const packet_t *            recv_packet,
    packet_t *                  send_packet,
    const filter_list_t *       send_filter_list)
{
    _dns_state_t *              state = (_dns_state_t *) dns_state;
    dns_header_t *              header;
    unsigned int                query_count = 0;
    unsigned int                rr_count[NUM_RR_SECTION_TYPES] = {0, 0, 0};
    unsigned int                packet_offset;
    unsigned int                rr_section_type;

    // Reset the compression list
    clist_reset(state);

    // Skip the header which will be filled in later
    packet_offset = sizeof(dns_header_t);

    // Encode the queries
    packet_offset = dns_encode_queries(state, send_packet, packet_offset, send_filter_list, &query_count);

    // Encode the resource record sections (answer, authority, additional)
    for (rr_section_type = 0; rr_section_type < NUM_RR_SECTION_TYPES; rr_section_type++)
    {
        packet_offset = dns_encode_rrs(state, rr_section_type, send_packet, packet_offset,
            send_filter_list,  &rr_count[rr_section_type]);
    }

    // If everything has been filtered, drop the packet
    if (query_count == 0 &&
        rr_count[RR_ANSWER] == 0 &&
        rr_count[RR_AUTHORITY] == 0 &&
        rr_count[RR_ADDITIONAL] == 0)
    {
        return 0;
    }

    // Fill in the packet header
    header = (dns_header_t *) send_packet->buffer;
    header->transaction_id = ((dns_header_t *) recv_packet->buffer)->transaction_id;
    header->flags = ((dns_header_t *) recv_packet->buffer)->flags;
    header->query_count = htons(query_count);
    header->answer_count = htons(rr_count[RR_ANSWER]);
    header->authority_count = htons(rr_count[RR_AUTHORITY]);
    header->additional_count = htons(rr_count[RR_ADDITIONAL]);

    // Set the length and return
    send_packet->bytes = packet_offset;

    return packet_offset;
}
