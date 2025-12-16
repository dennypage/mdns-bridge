
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


#ifndef _DNS_H
#define _DNS_H 1

#include <stdint.h>
#include <netdb.h>
#include <sys/types.h>

#include "common.h"


// DNS limits
#define MAX_LABEL_LEN               (64)    // Includes leading length byte
#define MAX_NUM_LABELS              (127)   // Number of labels in a name

// Initial/max query and response counts
#define INITIAL_QUERY_COUNT         (25)
#define INITIAL_RESOURCE_COUNT      (50)
#define MAX_QUERY_COUNT             (1498)
#define MAX_RESOURCE_COUNT          (749)

// Labels with the top two bits set are pointer labels. The lower 6 bits of
// the label length are the high order bits of the offset to the next label.

#define IS_LABEL_POINTER(len)       (((len) & 0xC0) == 0xC0)
#define POINTER_OFFSET(hb, lb)      (((unsigned) (hb) & 0x3F) << 8 | (lb))
#define OFFSET_TO_POINTER(off)      (htons(((off) & 0x3FFF) | 0xC000))

// KnownDNS types used in query and/or resource records
#define DNS_TYPE_A                  (1)
#define DNS_TYPE_CNAME              (5)
#define DNS_TYPE_PTR                (12)
#define DNS_TYPE_HINFO              (13)
#define DNS_TYPE_TXT                (16)
#define DNS_TYPE_AAAA               (28)
#define DNS_TYPE_SRV                (33)
#define DNS_TYPE_DNAME              (39)
#define DNS_TYPE_OPT                (41)
#define DNS_TYPE_NSEC               (47)
#define DNS_TYPE_SVCB               (64)
#define DNS_TYPE_HTTPS              (65)
#define DNS_TYPE_ANY                (255)

#define DNS_FLAG_RESPONSE(flags)    ((flags) & 0x8000)
#define DNS_FLAG_OPCODE(flags)      ((flags) & 0x7800)
#define DNS_FLAG_RCODE(flags)       ((flags) & 0x000F)


//
// DNS packet structures
//

// Main DNS header at beginning of packet.
typedef struct __attribute__((__packed__))
{
    uint16_t                    transaction_id;
    uint16_t                    flags;
    uint16_t                    query_count;
    uint16_t                    answer_count;
    uint16_t                    authority_count;
    uint16_t                    additional_count;
} dns_header_t;

// DNS Query data. Preceded by name.
typedef struct __attribute__((__packed__))
{
    // NAME
    uint16_t                    type;
    uint16_t                    class;
} dns_query_header_t;

// DNS Resource Record data. Preceded by name, followed by RDATA.
typedef struct __attribute__((__packed__))
{
    // NAME
    uint16_t                    type;
    uint16_t                    class;
    uint32_t                    ttl;
    uint16_t                    rdata_len;
    // RDATA
} dns_rr_header_t;

// DNS SRV Resource Record data. In the RDATA section, followed by target name.
typedef struct __attribute__((__packed__))
{
    // RR data
    uint16_t                    priority;
    uint16_t                    weight;
    uint16_t                    port;
    // Target name
} dns_rr_srv_data_t;

// Resource record section types
typedef enum
{
    RR_ANSWER                   = 0,
    RR_AUTHORITY                = 1,
    RR_ADDITIONAL               = 2
} rr_section_type_t;
#define NUM_RR_SECTION_TYPES            3

// DNS query structure
typedef struct
{
    // Location of the query data
    dns_query_header_t *        data;

    // Query type
    uint16_t                    type;

    // DNS name
    dns_name_t                  name;
} dns_query_t;

// DNS resource record structure
typedef struct
{
    // Location of the resource record data
    dns_rr_header_t *           data;

    // Resource record type
    uint16_t                    type;

    // Length of secondary data in the RDATA section
    uint16_t                    secondary_len;

    // DNS names
    dns_name_t                  name;
    dns_name_t                  rdata_name;
} dns_rr_t;

// DNS name compression entry
typedef struct
{
    // Label
    const unsigned char *       label;

    // Index and count of children
    uint16_t                    child_index;
    uint16_t                    child_allocated;
    uint16_t                    child_used;

    // Offset pointer of the label in the packet
    uint16_t                    pointer;
} compression_entry_t;

// Internal DNS decode/encode state structure
typedef struct
{
    // Section counts
    uint16_t                    recv_query_count;
    uint16_t                    recv_rr_count[NUM_RR_SECTION_TYPES];

    // Number of query and resource records
    unsigned int                query_count;
    unsigned int                rr_index[NUM_RR_SECTION_TYPES];
    unsigned int                rr_count[NUM_RR_SECTION_TYPES];
    unsigned int                total_rr_count;

    // Allocated query and resource records
    unsigned int                allocated_query_count;
    unsigned int                allocated_rr_count;
    dns_query_t *               query_list;
    dns_rr_t *                  rr_list;

    // Name compression state
    unsigned int                used_clist_count;
    unsigned int                allocated_clist_count;
    compression_entry_t *       clist;
} _dns_state_t;


//
// Allocate the compression list
//
void clist_alloc(
    _dns_state_t *              state);

#endif // DNS_H
