
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
#include <ctype.h>

#include "common.h"


// Limits for internal configuration arrays
#define MAX_INPUT_LINE                  16384
#define MAX_LIST_ARRAY                  1024

// Global section
#define GLOBAL_SECTION                  "[global]"

// Keys specific to the global section
#define KEY_INTERFACES                  "interfaces"
#define KEY_DISABLE_PACKET_FILTERING    "disable-packet-filtering"

// Keys common to global and interface sections
#define KEY_DISABLE_IPV4                "disable-ipv4"
#define KEY_DISABLE_IPV6                "disable-ipv6"

// Keys specific to interface sections
#define KEY_ALLOW_INBOUND_FILTERS       "allow-inbound-filters"
#define KEY_DENY_INBOUND_FILTERS        "deny-inbound-filters"
#define KEY_ALLOW_OUTBOUND_FILTERS      "allow-outbound-filters"
#define KEY_DENY_OUTBOUND_FILTERS       "deny-outbound-filters"
#define KEY_PEER_ALLOW_OUTBOUND_FILTERS "peer-allow-outbound-filters"
#define KEY_PEER_DENY_OUTBOUND_FILTERS  "peer-deny-outbound-filters"

// Global config flags
static unsigned int                     global_disable_ipv4 = 0;
static unsigned int                     global_disable_ipv6 = 0;

// Current configuration line
static unsigned int                     config_lineno = 0;



//
// Trim (skip) leading whitespace from a string
//
static char * trim_leading_whitespace(
    char *                      str)
{
    while (*str && isspace((unsigned char) *str))
    {
        str += 1;
    }

    return (str);
}


//
// Trim trailing whitespace from a string
//
static void trim_trailing_whitespace(
    char *                      str)
{
    char *                      end;
    unsigned int                len;

    len = strlen(str);
    if (len == 0)
    {
        return;
    }

    end = str + len - 1;
    while (end >= str && isspace((unsigned char) *end))
    {
        *end = '\0';
        end -= 1;
    }
}


//
// Split a line into a key and value
//
static char * split_keyvalue(
    char *                      line)
{
    char *                      value;

    // Ensure it's actually an assignment
    value = strchr(line, '=');
    if (value == NULL)
    {
        fatal("%s line %u: Syntax error - missing assignment\n", config_filename, config_lineno);
    }
    *value = '\0';

    // Trim the key and ensure it is not empty
    trim_trailing_whitespace(line);
    if (*line == '\0')
    {
        fatal("%s line %u: Syntax error - missing key\n", config_filename, config_lineno);
    }

    // Trim the value and ensure it is not empty
    value = trim_leading_whitespace(value + 1);
    if (*value == '\0')
    {
        fatal("%s line %u: Syntax error - missing value\n", config_filename, config_lineno);
    }

    return (value);
}


//
// Convert a comma separated list of strings into an array of strings
// NB: The array MUST be at least MAX_LIST_ARRAY in size
//
static unsigned int split_comma_list(
    char *                      str,
    char **                     array)
{
    unsigned int                index = 0;

    // Add the first element to the array
    array[index] = str;

    while (*str)
    {
        if (*str == ',')
        {
            if (index + 1 >= MAX_LIST_ARRAY)
            {
                fatal("%s line %u: Invalid list - elements exceed max allowed (%u)\n", config_filename, config_lineno, MAX_LIST_ARRAY);
            }

            // Terminate the current element
            *str = '\0';
            trim_trailing_whitespace(array[index]);

            // Ensure the current element is not empty
            if (*array[index] == '\0')
            {
                fatal("%s line %u: Invalid list - empty element\n", config_filename, config_lineno);
            }

            // Insure the next element is not empty
            str = trim_leading_whitespace(str + 1);
            if (*str == '\0')
            {
                fatal("%s line %u: Invalid list - empty element\n", config_filename, config_lineno);
            }

            // Add the new element to the array
            index += 1;
            array[index] = str;
        }
        else
        {
            str += 1;
        }
    }

    return (index + 1);
}


//
// Read a line from the config file
// NB: The buffer MUST be at least MAX_INPUT_LINE in size
//
static char * read_line(
    FILE *                      fp,
    char *                      buffer)
{
    char *                      line;

    while (fgets(buffer, MAX_INPUT_LINE, fp) != NULL)
    {
        config_lineno += 1;

        // Trim leading whitespace spaces
        line = trim_leading_whitespace(buffer);

        // Ignore empty and comment lines
        if (*line == '\0' || *line == '#')
        {
            continue;
        }

        // Trim trailing whitespace
        trim_trailing_whitespace(line);
        return line;
    }

    return NULL;
}


//
// Read and process the config file
//
void read_config(void)
{
    FILE *                      fp;
    char                        buffer[MAX_INPUT_LINE];
    char *                      list_array[MAX_LIST_ARRAY];
    unsigned int                list_array_count;
    interface_t *               interface;
    interface_t *               peer;
    char *                      line;
    char *                      value;
    unsigned int                index;
    unsigned int                len;

    // Open the config file
    fp = fopen(config_filename, "r");
    if (fp == NULL)
    {
        fatal("Unable to open config file \"%s\"\n", config_filename);
    }

    // Ensure the global section is the first section in the config file
    line = read_line(fp, buffer);
    if ((line == NULL) || strcmp(line, GLOBAL_SECTION) != 0)
    {
        fatal("%s: File does not contain [global] as the first section\n", config_filename);
    }

    // Process the lines in the global section
    while ((line = read_line(fp, buffer)))
    {
        if (*line == '[')
        {
            break;
        }

        // Split the key/value pair
        value = split_keyvalue(line);

        if (strcmp(line, KEY_INTERFACES) == 0)
        {
            list_array_count = split_comma_list(value, list_array);
            if (list_array_count < 2)
            {
                fatal("%s line %u: A minimum of 2 interfaces are required\n", config_filename, config_lineno);
            }

            // Error if an interface list was previously defined
            if (configured_interface_list)
            {
                fatal("%s line %u: Only one interface list is allowed\n", config_filename, config_lineno);
            }

            // Set the interface list
            set_interface_list(list_array, list_array_count);
        }
        else if (strcmp(line, KEY_DISABLE_IPV4) == 0)
        {
            if (strcmp(value, "yes") == 0)
            {
                global_disable_ipv4 = 1;
            }
            else if (strcmp(value, "no") == 0)
            {
                global_disable_ipv4 = 0;
            }
            else
            {
                fatal("%s line %u: Invalid value for %s \"%s\"\n", config_filename, config_lineno, KEY_DISABLE_IPV4, value);
            }
        }
        else if (strcmp(line, KEY_DISABLE_IPV6) == 0)
        {
            if (strcmp(value, "yes") == 0)
            {
                global_disable_ipv6 = 1;
            }
            else if (strcmp(value, "no") == 0)
            {
                global_disable_ipv6 = 0;
            }
            else
            {
                fatal("%s line %u: Invalid value for %s \"%s\"\n", config_filename, config_lineno, KEY_DISABLE_IPV6, value);
            }
        }
        else if (strcmp(line, KEY_DISABLE_PACKET_FILTERING) == 0)
        {
            if (strcmp(value, "yes") == 0)
            {
                if (global_filter_list)
                {
                    fatal("%s line %u: %s cannot be combined with %s or %s\n", config_filename, config_lineno,
                          KEY_DISABLE_PACKET_FILTERING, KEY_ALLOW_INBOUND_FILTERS, KEY_DENY_INBOUND_FILTERS);
                }

                filtering_enabled = 0;
            }
            else if (strcmp(value, "no") == 0)
            {
                filtering_enabled = 1;
            }
            else
            {
                fatal("%s line %u: Invalid value for %s \"%s\"\n", config_filename, config_lineno,
                      KEY_DISABLE_PACKET_FILTERING, value);
            }

            // Warn that the disable-packet-filtering option is deprecated
            logger("%s line %u: WARNING: the %s option is deprecated and will be removed in a future version\n",
                    config_filename, config_lineno, KEY_DISABLE_PACKET_FILTERING);
        }
        else if (strcmp(line, KEY_ALLOW_INBOUND_FILTERS) == 0)
        {
            if (filtering_enabled == 0)
            {
                fatal("%s line %u: %s cannot be combined with %s\n", config_filename, config_lineno,
                      KEY_ALLOW_INBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
            }

            if (global_filter_list)
            {
                fatal("%s line %u: Only one global filter list is allowed\n", config_filename, config_lineno);
            }

            list_array_count = split_comma_list(value, list_array);
            set_global_filter_list(ALLOW, list_array, list_array_count);
        }
        else if (strcmp(line, KEY_DENY_INBOUND_FILTERS) == 0)
        {
            if (filtering_enabled == 0)
            {
                fatal("%s line %u: %s cannot be combined with %s\n", config_filename, config_lineno,
                      KEY_DENY_INBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
            }

            if (global_filter_list)
            {
                fatal("%s line %u: Only one global filter list is allowed\n", config_filename, config_lineno);
            }

            list_array_count = split_comma_list(value, list_array);
            set_global_filter_list(DENY, list_array, list_array_count);
        }
        else
        {
            fatal("%s line %u: Unknown [global] parameter \"%s\"\n", config_filename, config_lineno, line);
        }
    }


    // Ensure we found an interface list
    if (configured_interface_list == NULL)
    {
        fatal("%s: [global] section missing required parameter \"%s\"\n", config_filename, KEY_INTERFACES);
    }

    // Initialize the interface IP settings to match global settings
    if (global_disable_ipv4)
    {
        for (index = 0; index < configured_interface_count; index++)
        {
            configured_interface_list[index].disable_ip[IPV4] = 1;
        }
    }
    if (global_disable_ipv6)
    {
        for (index = 0; index < configured_interface_count; index++)
        {
            configured_interface_list[index].disable_ip[IPV6] = 1;
        }
    }

    // Process lines in interface sections
    while (line && line[0] == '[')
    {
        // Ignore leading whitespace
        line = trim_leading_whitespace(line + 1);

        // Ensure the section name (interface name) is terminated
        len = strlen(line);
        if (len == 0 || line[len - 1] != ']')
        {
            fatal("%s line %u: Syntax error\n", config_filename, config_lineno);
        }
        line[len - 1] = '\0';

        // Ignore trailing whitespace
        trim_trailing_whitespace(line);

        // Insure the interface name is valid
        if (strlen(line) == 0 || strpbrk(line, "[]") != NULL)
        {
            fatal("%s line %u: Syntax error\n", config_filename, config_lineno);
        }

        // Find the interface
        interface = get_interface_by_name(line);
        if (interface == NULL)
        {
            fatal("%s line %u: Interface \"%s\" is not in the [global] interfaces list\n", config_filename, config_lineno, line);
        }

        // Read the rest of the interface section
        while ((line = read_line(fp, buffer)))
        {
            if (*line == '[')
            {
                break;
            }

            // Split the key/value pair
            value = split_keyvalue(line);

            if (strcmp(line, KEY_DISABLE_IPV4) == 0)
            {
                if (strcmp(value, "yes") == 0)
                {
                    interface->disable_ip[IPV4] = 1;
                }
                else if (strcmp(value, "no") == 0)
                {
                    if (global_disable_ipv4)
                    {
                        fatal("%s line %u: IPv4 is globally disabled\n", config_filename, config_lineno);
                    }
                    interface->disable_ip[IPV4] = 0;
                }
                else
                {
                    fatal("%s line %u: Invalid value for %s \"%s\"\n", config_filename, config_lineno, KEY_DISABLE_IPV4, value);
                }
            }
            else if (strcmp(line, KEY_DISABLE_IPV6) == 0)
            {
                if (strcmp(value, "yes") == 0)
                {
                    interface->disable_ip[IPV6] = 1;
                }
                else if (strcmp(value, "no") == 0)
                {
                    if (global_disable_ipv6)
                    {
                        fatal("%s line %u: IPv6 is globally disabled\n", config_filename, config_lineno);
                    }
                    interface->disable_ip[IPV6] = 0;
                }
                else
                {
                    fatal("%s line %u: Invalid value for %s \"%s\"\n", config_filename, config_lineno, KEY_DISABLE_IPV6, value);
                }
            }
            else if (strcmp(line, KEY_ALLOW_INBOUND_FILTERS) == 0)
            {
                if (filtering_enabled == 0)
                {
                    fatal("%s line %u: %s cannot be combined with %s\n", config_filename, config_lineno,
                          KEY_ALLOW_INBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
                }

                if (interface->inbound_filter_list)
                {
                    fatal("%s line %u: Only one inbound filter list per interface is allowed\n", config_filename, config_lineno);
                }

                list_array_count = split_comma_list(value, list_array);
                set_interface_inbound_filter_list(interface, ALLOW, list_array, list_array_count);
            }
            else if (strcmp(line, KEY_DENY_INBOUND_FILTERS) == 0)
            {
                if (filtering_enabled == 0)
                {
                    fatal("%s line %u: %s cannot be combined with %s\n", config_filename, config_lineno,
                          KEY_DENY_INBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
                }

                if (interface->inbound_filter_list)
                {
                    fatal("%s line %u: Only one inbound filter list per interface is allowed\n", config_filename, config_lineno);
                }

                list_array_count = split_comma_list(value, list_array);
                set_interface_inbound_filter_list(interface, DENY, list_array, list_array_count);
            }
            else if (strcmp(line, KEY_ALLOW_OUTBOUND_FILTERS) == 0)
            {
                if (filtering_enabled == 0)
                {
                    fatal("%s line %u: %s cannot be combined with %s\n", config_filename, config_lineno,
                          KEY_ALLOW_OUTBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
                }

                if (interface->outbound_filter_list)
                {
                    fatal("%s line %u: Only one outbound filter list per interface is allowed\n", config_filename, config_lineno);
                }

                list_array_count = split_comma_list(value, list_array);
                set_interface_outbound_filter_list(interface, ALLOW, list_array, list_array_count);
            }
            else if (strcmp(line, KEY_DENY_OUTBOUND_FILTERS) == 0)
            {
                if (filtering_enabled == 0)
                {
                    fatal("%s line %u: %s cannot be combined with %s\n", config_filename, config_lineno,
                          KEY_DENY_OUTBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
                }

                if (interface->outbound_filter_list)
                {
                    fatal("%s line %u: Only one outbound filter list per interface is allowed\n", config_filename, config_lineno);
                }

                list_array_count = split_comma_list(value, list_array);
                set_interface_outbound_filter_list(interface, DENY, list_array, list_array_count);
            }
            else if (strcmp(line, KEY_PEER_ALLOW_OUTBOUND_FILTERS) == 0)
            {
                if (filtering_enabled == 0)
                {
                    fatal("%s line %u: %s cannot be combined with %s\n", config_filename, config_lineno,
                          KEY_PEER_ALLOW_OUTBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
                }

                list_array_count = split_comma_list(value, list_array);
                if (list_array_count < 2)
                {
                    fatal("%s line %u: missing filter\n", config_filename, config_lineno);
                }

                peer = get_interface_by_name(list_array[0]);
                if (peer == NULL)
                {
                    fatal("%s line %u: Interface \"%s\" is not in the [global] interfaces list\n", config_filename, config_lineno, list_array[0]);
                }

                if (interface->peer_outbound_filter_list && interface->peer_outbound_filter_list[peer->index])
                {
                    fatal("%s line %u: Only one peer outbound filter list per peer is allowed\n", config_filename, config_lineno);
                }
                set_interface_peer_outbound_filter_list(interface, peer, ALLOW, &list_array[1], list_array_count - 1);
            }
            else if (strcmp(line, KEY_PEER_DENY_OUTBOUND_FILTERS) == 0)
            {
                if (filtering_enabled == 0)
                {
                    fatal("%s line %u: %s cannot be combined with %s\n", config_filename, config_lineno,
                          KEY_PEER_DENY_OUTBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
                }

                list_array_count = split_comma_list(value, list_array);
                if (list_array_count < 2)
                {
                    fatal("%s line %u: missing filter\n", config_filename, config_lineno);
                }

                peer = get_interface_by_name(list_array[0]);
                if (peer == NULL)
                {
                    fatal("%s line %u: Interface \"%s\" is not in the [global] interfaces list\n", config_filename, config_lineno, list_array[0]);
                }

                if (interface->peer_outbound_filter_list && interface->peer_outbound_filter_list[peer->index])
                {
                    fatal("%s line %u: Only one peer outbound filter list per peer is allowed\n", config_filename, config_lineno);
                }
                set_interface_peer_outbound_filter_list(interface, peer, DENY, &list_array[1], list_array_count - 1);
            }
            else
            {
                fatal("%s line %u: Unknown interface parameter \"%s\"\n", config_filename, config_lineno, line);
            }
        }
    }

    if (line != NULL)
    {
        fatal("%s line %u: Syntax error\n", config_filename, config_lineno);
    }

    fclose(fp);
}


//
// Dump the configuration for human readability
//
static void print_peer_list(
    char *                      prefix,
    unsigned int                count,
    interface_t *               list[])
{
    unsigned int                index;

    printf("%s: ", prefix);
    for (index = 0; index < count; index++)
    {
        if (index < count - 1)
        {
            printf("%s, ", list[index]->name);
        }
        else
        {
            printf("%s\n", list[index]->name);
        }
    }
}

static void print_filter_list(
    char *                      prefix,
    filter_list_t *             list)
{
    unsigned int                index;
    unsigned char               string[DNS_MAX_NAME_LEN];

    if (list == NULL)
    {
        printf("%s: none\n", prefix);
        return;
    }

    if (list->allow_deny == DENY_ALL)
    {
        printf("%s: (deny all)\n", prefix);
        return;
    }

    printf("%s: (%s) ", prefix, list->allow_deny == ALLOW ? "allow" : "deny");
    for (index = 0; index < list->count; index++)
    {
        dns_labels_to_string(list->names[index]->labels, list->names[index]->length, string);
        if (index < list->count - 1)
        {
            printf("%s, ", string);

        }
        else
        {
            printf("%s\n", string);
        }
    }
}

static void print_interface_ip(
    interface_t *               interface,
    ip_type_t                   ip_type)
{
    interface_t *               peer;
    interface_t *               peer2;
    dest_filter_list_t **       peer_filter_list;
    dest_filter_list_t *        peer_filter;
    filter_list_t *             filter_list;
    unsigned int                peer_filter_index;
    unsigned int                peer_index;
    unsigned int                peer2_index;
    unsigned int                count;

    if (interface->disable_ip[ip_type] == 0)
    {
        printf("  %s configuration:\n", ip_type == IPV4 ? "IPv4" : "IPv6");
        printf("   address: %s\n", ip_type == IPV4 ? interface->ipv4_addr_str : interface->ipv6_addr_str);

        // Print peer interface list
        for (peer_index = 0; peer_index < configured_interface_count; peer_index++)
        {
            peer = &configured_interface_list[peer_index];
            if (peer == interface || peer->disable_ip[ip_type])
            {
                continue;
            }
            break;
        }
        printf("   peer interfaces: %s", peer->name);
        for (peer_index = peer_index + 1; peer_index < configured_interface_count; peer_index++)
        {
            peer = &configured_interface_list[peer_index];
            if (peer == interface || peer->disable_ip[ip_type])
            {
                continue;
            }
            printf(", %s", peer->name);
        }
        printf("\n");

        // Print peer source list
        count = 1;
        for (peer_index = 0; peer_index < configured_interface_count; peer_index++)
        {
            peer = &configured_interface_list[peer_index];
            if (peer == interface || peer->disable_ip[ip_type])
            {
                continue;
            }

            filter_list = get_filter_list_for_peer(interface, peer);

            for (peer2_index = 0; peer2_index < peer_index; peer2_index++)
            {
                peer2 = &configured_interface_list[peer2_index];
                if (peer2 == interface || peer2->disable_ip[ip_type])
                {
                    continue;
                }

                // Have we already seen this filter list?
                if (get_filter_list_for_peer(interface, peer2) == filter_list)
                {
                    break;
                }
            }

            if (peer2_index >= peer_index)
            {
                printf("   source %u:\n", count++);
                printf("    interfaces: %s", peer->name);
                for (peer2_index = peer_index + 1; peer2_index < configured_interface_count; peer2_index++)
                {
                    peer2 = &configured_interface_list[peer2_index];
                    if (peer2 == interface || peer2->disable_ip[ip_type])
                    {
                        continue;
                    }

                    if (get_filter_list_for_peer(interface, peer2) == filter_list)
                    {
                        printf(", %s", peer2->name);
                    }
                }
                printf("\n");
                print_filter_list("    filter", filter_list);
            }
        }

        // Print peer destination list
        count = 1;
        peer_filter_list = interface->dest_filter_list[ip_type];
        for (peer_filter_index = 0; peer_filter_index < interface->dest_filter_count[ip_type]; peer_filter_index++)
        {
            peer_filter = peer_filter_list[peer_filter_index];

            printf("   destination %u:\n", count++);
            print_peer_list("    interfaces", peer_filter->peer_count, peer_filter->peer_list);
            print_filter_list("    filter", peer_filter_list[peer_filter_index]->filter);
        }
    }
    else
    {
        printf("  %s disabled\n", ip_type == IPV4 ? "IPv4" : "IPv6");
    }
}

void dump_config(void)
{
    interface_t *               interface;
    unsigned int                interface_index;
    unsigned int                index;

    // Global section
    printf("\nGlobal settings:\n");
    if (global_disable_ipv4) {
        printf(" disable ipv4 = true\n");
    } else {
        printf(" disable ipv4 = false\n");
    }
    if (global_disable_ipv6) {
        printf(" disable ipv6 = true\n");
    } else {
        printf(" disable ipv6 = false\n");
    }
    print_filter_list(" global filter", global_filter_list);
    printf("\n");

    printf("Interfaces:\n");

    for (interface_index = 0; interface_index < configured_interface_count; interface_index++)
    {
        interface = &configured_interface_list[interface_index];
        printf(" %s:\n", interface->name);

        // Print interface configuration
        print_filter_list("  inbound filter", interface->inbound_filter_list);
        print_filter_list("  outbound filter", interface->outbound_filter_list);

        if (interface->peer_outbound_filter_list)
        {
            printf("  peer specific outbound filters:\n");
            for (index = 0; index < configured_interface_count; index++)
            {
                if (interface->peer_outbound_filter_list[index])
                {
                    printf("   %s", configured_interface_list[index].name);
                    print_filter_list("", interface->peer_outbound_filter_list[index]);
                }
            }
        }

        // Print interface IP configuration
        print_interface_ip(interface, IPV4);
        print_interface_ip(interface, IPV6);
        printf("\n");
    }
}
