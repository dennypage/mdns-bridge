
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


// Packet filtering enable flag
unsigned int                    filtering_enabled = 1;

// The global filter list
filter_list_t *                 global_filter_list = NULL;

// Count of unique outbound filters in use across all interfaces
unsigned int                    unique_outbound_filter_count = 0;



//
// Compare two strings for sort
//
static int qsort_strcmp(
    const void *                p1,
    const void *                p2)
{
    return strcmp(*(const char **) p1, *(const char **) p2);
}


//
// Create a filter list
//
static filter_list_t * filter_list_create(
    const filter_allow_deny_t   allow_deny,
    char **                     list,
    unsigned int                count)
{
    filter_list_t *             filter_list;
    unsigned int                index;

    // Sort the array
    qsort(list, count, sizeof(list[0]), qsort_strcmp);

    // Remove duplicates
    for (index = 1; index < count; index++)
    {
        if (strcmp(list[index - 1], list[index]) == 0)
        {
            if (index < count - 1)
            {
                memmove(list + index, list + index + 1, sizeof(list[0]) * (count - index - 1));
                index--;
            }
            count--;
        }
    }

    // Allocate the filter list
    filter_list = calloc(1, sizeof(filter_list_t));
    if (filter_list == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }

    // Allocate the name list
    filter_list->names = calloc(count, sizeof(dns_match_name_t *));
    if (filter_list->names == NULL)
    {
        fatal("Cannot allocate memory: %s\n", strerror(errno));
    }

    // Save the filter names
    for (index = 0; index < count; index++)
    {
        // NB: dns_save_name calls fatal() on any error
        filter_list->names[index] = dns_save_match_name(list[index]);
    }

    // Set the count and allow/deny flag
    filter_list->count = count;
    filter_list->allow_deny = allow_deny;

    return filter_list;
}


//
// Destroy a filter list
//
static void filter_list_destroy(
   filter_list_t *              filter_list)
{
    unsigned int                index;

    // Free the dns names
    for (index = 0; index < filter_list->count; index++)
    {
        free((void *) filter_list->names[index]);
    }

    // Free the names array and the list itself
    free(filter_list->names);
    free(filter_list);
}


//
// Compare two filter lists for equality
//
static int filter_list_compare(
   const filter_list_t *        l1,
   const filter_list_t *        l2)
{
    if (l1->allow_deny != l2->allow_deny || l1->count != l2->count)
    {
        return 1;
    }

    for (unsigned int index = 0; index < l1->count; index++)
    {
        if (l1->names[index]->length != l2->names[index]->length)
        {
            return 1;
        }

        if (memcmp (l1->names[index]->labels, l2->names[index]->labels, l1->names[index]->length))
        {
            return 1;
        }
    }

    return 0;
}


//
// Set the global filter list
//
unsigned int set_global_filter_list(
    const filter_allow_deny_t   allow_deny,
    char **                     list,
    unsigned int                count)
{
    // If a list was previously defined, return error
    if (global_filter_list)
    {
        return 1;
    }

    // Create the list
    global_filter_list = filter_list_create(allow_deny, list, count);
    return 0;
}


//
// Set an interface inbound filter list
//
unsigned int set_interface_inbound_filter_list(
    interface_t *               interface,
    const filter_allow_deny_t   allow_deny,
    char **                     list,
    unsigned int                count)
{
    filter_list_t *             filter_list;
    unsigned int                index;

    // If a list was previously defined, return error
    if (interface->inbound_filter_list)
    {
        return 1;
    }

    // Create the list
    filter_list = filter_list_create(allow_deny, list, count);

    // Check if this is a duplicate of the global list
    if (global_filter_list && filter_list_compare(global_filter_list, filter_list) == 0)
    {
        logger("Interface %s inbound filter discarded (duplicate of the global filter)\n", interface->name);
        filter_list_destroy(filter_list);
        return 0;
    }

    // Check if this is a duplicate of an already existing interface filter list
    for (index = 0; index < configured_interface_count; index++)
    {
        if (configured_interface_list[index].inbound_filter_list &&
            filter_list_compare(configured_interface_list[index].inbound_filter_list, filter_list) == 0)
        {
            filter_list_destroy(filter_list);
            filter_list = configured_interface_list[index].inbound_filter_list;
            break;
        }
    }

    // Assign the list to the interface
    interface->inbound_filter_list = filter_list;
    return 0;
}


//
// Set an interface outbound filter list
//
unsigned int set_interface_outbound_filter_list(
    interface_t *               interface,
    const filter_allow_deny_t   allow_deny,
    char **                     list,
    unsigned int                count)
{
    filter_list_t *             filter_list;
    unsigned int                index;

    // If a list was previously defined, return error
    if (interface->outbound_filter_list)
    {
        return 1;
    }

    // Create the list
    filter_list = filter_list_create(allow_deny, list, count);

    // Check if this is a duplicate of an already existing interface filter list
    for (index = 0; index < configured_interface_count; index++)
    {
        if (configured_interface_list[index].outbound_filter_list &&
            filter_list_compare(configured_interface_list[index].outbound_filter_list, filter_list) == 0)
        {
            // If the new list is a duplicate, adopt the existing list
            filter_list_destroy(filter_list);
            filter_list = configured_interface_list[index].outbound_filter_list;
            break;
        }
    }

    // Assign the list to the interface
    interface->outbound_filter_list = filter_list;
    unique_outbound_filter_count += 1;
    return 0;
}


//
// Check if a name is allowed by a filter list
//
static unsigned int filter_list_allowed(
    const filter_list_t *       filter_list,
    const dns_name_t *          name)
{
    unsigned int                index;
    unsigned int                match = 0;

    for (index = 0; index < filter_list->count; index++)
    {
        if (dns_subset_match(name, filter_list->names[index]))
        {
            match = 1;
            break;
        }
    }

    if ((match && filter_list->allow_deny == ALLOW) ||
       (!match && filter_list->allow_deny == DENY))
    {
        return 1;
    }

    return 0;
}


//
// Check if an name is allowed by the global and interface inbound filter lists
//
unsigned int allowed_inbound(
    const interface_t *         interface,
    const dns_name_t *          name)
{
    unsigned int                allowed = 1;

    // Check the global filter list
    if (global_filter_list)
    {
        allowed = filter_list_allowed(global_filter_list, name);
    }

    // Check the interface filter list
    if (allowed && interface->inbound_filter_list)
    {
        allowed = filter_list_allowed(interface->inbound_filter_list, name);
    }

    return allowed;
}


//
// Check if an name is allowed by an interface outbound filter list
//
unsigned int allowed_outbound(
    const filter_list_t *       filter_list,
    const dns_name_t *          name)
{
    unsigned int                allowed = 1;

    // Check the filter list
    if (filter_list)
    {
        allowed = filter_list_allowed(filter_list, name);
    }

    return allowed;
}
