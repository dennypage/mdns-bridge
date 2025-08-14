
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
#include <ctype.h>

#include "common.h"


// Limits for internal configuration arrays
#define MAX_INPUT_LINE                  16384
#define MAX_LIST_ARRAY                  1024

// Global section
#define GLOBAL_SECTION                  "[global]"

// Keys specific to the global section
#define KEY_INTERFACES                  "interfaces"
#define KEY_DISABLE_PACKET_FILTERING 	"disable-packet-filtering"

// Keys common to global and interface sections
#define KEY_DISABLE_IPV4                "disable-ipv4"
#define KEY_DISABLE_IPV6                "disable-ipv6"

// Keys specific to interface sections
#define KEY_ALLOW_INBOUND_FILTERS     	"allow-inbound-filters"
#define KEY_DENY_INBOUND_FILTERS      	"deny-inbound-filters"
#define KEY_ALLOW_OUTBOUND_FILTERS    	"allow-outbound-filters"
#define KEY_DENY_OUTBOUND_FILTERS     	"deny-outbound-filters"

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
    while (isspace(*str))
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

    end = str + strlen(str) - 1;
    while (isspace(*end))
    {
        *end = 0;
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
        fatal("%s line %d: Syntax error - missing assignment\n", config_filename, config_lineno);
    }
    *value = 0;

    // Trim the value and ensure it is not empty
    value = trim_leading_whitespace(value + 1);
    if (*value == 0)
    {
        fatal("%s line %d: Syntax error - missing value\n", config_filename, config_lineno);
    }

    // Trim the key
    trim_trailing_whitespace(line);

    return (value);
}


//
// Convert a comma separated list of strings into a sorted array
// NB: The array MUST be at least MAX_LIST_ARRAY in size
//
static unsigned int split_comma_list(
    char *                      str,
    char **                     array)
{
    unsigned int                index = 0;

    // Add the first element to the array
    array[0] = str;

    while (*str)
    {
        if (*str == ',')
        {
            if (index + 1 >= MAX_LIST_ARRAY)
            {
                fatal("%s line %d: Invalid list - elements exceed max allowed (%u)\n", config_filename, config_lineno, MAX_LIST_ARRAY);
            }

            // Terminate the current element
            *str = 0;
            trim_trailing_whitespace(str);

            // Ensure the current element is not empty
            if (array[index] == str)
            {
                fatal("%s line %d: Invalid list - empty element\n", config_filename, config_lineno);
            }

            // Insure the next element is not empty
            str = trim_leading_whitespace(str + 1);
            if (*str == 0)
            {
                fatal("%s line %d: Invalid list - empty element\n", config_filename, config_lineno);
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
        if (*line == 0 || *line == '#')
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
    char *                      line;
    char *                      value;
    unsigned int                offset;
    unsigned int                index;

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
                fatal("%s line %d: A minimum of 2 interfaces are required\n", config_filename, config_lineno);
            }

            if (set_interface_list(list_array, list_array_count))
            {
                fatal("%s line %d: Only one interface list is allowed\n", config_filename, config_lineno);
            }
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
                fatal("%s line %d: Invalid value for %s \"%s\"\n", config_filename, config_lineno, KEY_DISABLE_IPV4, value);
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
                fatal("%s line %d: Invalid value for %s \"%s\"\n", config_filename, config_lineno, KEY_DISABLE_IPV6, value);
            }
        }
        else if (strcmp(line, KEY_DISABLE_PACKET_FILTERING) == 0)
        {
            if (strcmp(value, "yes") == 0)
            {
                if (global_filter_list)
                {
                    fatal("%s line %d: %s cannot be combined with %s or %s\n", config_filename, config_lineno,
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
                fatal("%s line %d: Invalid value for %s \"%s\"\n", config_filename, config_lineno,
                      KEY_DISABLE_PACKET_FILTERING, value);
            }
        }
        else if (strcmp(line, KEY_ALLOW_INBOUND_FILTERS) == 0)
        {
            if (filtering_enabled == 0)
            {
                fatal("%s line %d: %s cannot be combined with %s\n", config_filename, config_lineno,
                      KEY_ALLOW_INBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
            }
            list_array_count = split_comma_list(value, list_array);
            if (set_global_filter_list(ALLOW, list_array, list_array_count))
            {
                fatal("%s line %d: Only one global filter list is allowed\n", config_filename, config_lineno);
            }
        }
        else if (strcmp(line, KEY_DENY_INBOUND_FILTERS) == 0)
        {
            if (filtering_enabled == 0)
            {
                fatal("%s line %d: %s cannot be combined with %s\n", config_filename, config_lineno,
                      KEY_DENY_INBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
            }
            list_array_count = split_comma_list(value, list_array);
            if (set_global_filter_list(DENY, list_array, list_array_count))
            {
                fatal("%s line %d: Only one global filter list is allowed\n", config_filename, config_lineno);
            }
        }
        else
        {
            fatal("%s line %d: Unknown [global] parameter \"%s\"\n", config_filename, config_lineno, line);
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
        offset = strlen(line) - 1;
        if (line[offset] != ']')
        {
            fatal("%s line %d: Syntax error\n", config_filename, config_lineno);
        }
        line[offset] = 0;

        // Ignore trailing whitespace
        trim_trailing_whitespace(line);

        // Insure the interface name is valid
        if (strlen(line) == 0 || strpbrk(line, "[]") != NULL)
        {
            fatal("%s line %d: Syntax error\n", config_filename, config_lineno);
        }

        // Find the interface
        interface = get_interface_by_name(line);
        if (interface == NULL)
        {
            fatal("%s line %d: Interface \"%s\" is not in the [global] interfaces list\n", config_filename, config_lineno, line);
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
                        fatal("%s line %d: IPv4 is globally disabled\n", config_filename, config_lineno);
                    }
                    interface->disable_ip[IPV4] = 0;
                }
                else
                {
                    fatal("%s line %d: Invalid value for %s \"%s\"\n", config_filename, config_lineno, KEY_DISABLE_IPV4, value);
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
                        fatal("%s line %d: IPv6 is globally disabled\n", config_filename, config_lineno);
                    }
                    interface->disable_ip[IPV6] = 0;
                }
                else
                {
                    fatal("%s line %d: Invalid value for %s \"%s\"\n", config_filename, config_lineno, KEY_DISABLE_IPV6, value);
                }
            }
            else if (strcmp(line, KEY_ALLOW_INBOUND_FILTERS) == 0)
            {
                if (filtering_enabled == 0)
                {
                    fatal("%s line %d: %s cannot be combined with %s\n", config_filename, config_lineno,
                          KEY_ALLOW_INBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
                }

                list_array_count = split_comma_list(value, list_array);
                if (set_interface_inbound_filter_list(interface, ALLOW, list_array, list_array_count))
                {
                    fatal("%s line %d: Only one inbound filter list per interface is allowed\n", config_filename, config_lineno);
                }
            }
            else if (strcmp(line, KEY_DENY_INBOUND_FILTERS) == 0)
            {
                if (filtering_enabled == 0)
                {
                    fatal("%s line %d: %s cannot be combined with %s\n", config_filename, config_lineno,
                          KEY_DENY_INBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
                }

                list_array_count = split_comma_list(value, list_array);
                if (set_interface_inbound_filter_list(interface, DENY, list_array, list_array_count))
                {
                    fatal("%s line %d: Only one inbound filter list per interface is allowed\n", config_filename, config_lineno);
                }
            }
            else if (strcmp(line, KEY_ALLOW_OUTBOUND_FILTERS) == 0)
            {
                if (filtering_enabled == 0)
                {
                    fatal("%s line %d: %s cannot be combined with %s\n", config_filename, config_lineno,
                          KEY_ALLOW_OUTBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
                }

                list_array_count = split_comma_list(value, list_array);
                if (set_interface_outbound_filter_list(interface, ALLOW, list_array, list_array_count))
                {
                    fatal("%s line %d: Only one outbound filter list per interface is allowed\n", config_filename, config_lineno);
                }
            }
            else if (strcmp(line, KEY_DENY_OUTBOUND_FILTERS) == 0)
            {
                if (filtering_enabled == 0)
                {
                    fatal("%s line %d: %s cannot be combined with %s\n", config_filename, config_lineno,
                          KEY_DENY_OUTBOUND_FILTERS, KEY_DISABLE_PACKET_FILTERING);
                }

                list_array_count = split_comma_list(value, list_array);
                if (set_interface_outbound_filter_list(interface, DENY, list_array, list_array_count))
                {
                    fatal("%s line %d: Only one outbound filter list per interface is allowed\n", config_filename, config_lineno);
                }
            }
            else
            {
                fatal("%s line %d: Unknown interface parameter \"%s\"\n", config_filename, config_lineno, line);
            }
        }
    }

    if (line != NULL)
    {
        fatal("%s line %d: Syntax error\n", config_filename, config_lineno);
    }

    fclose(fp);
}


//
// Dump the configuration
//
static void dump_filter_list(
    char *                      name,
    filter_list_t *             list)
{
    unsigned int                index;
    unsigned char               string[DNS_MAX_NAME_LEN];

    if (list)
    {
        printf("  %s (%s):\n", name, list->allow_deny == ALLOW ? "allow" : "deny");
        for (index = 0; index < list->count; index++)
        {
            dns_labels_to_string(list->names[index]->labels, list->names[index]->length, string);
            printf("   %s\n", string);
        }
    }
    else
    {
        printf("  %s: (none)\n", name);
    }
}


//
// Dump the configuration
//
void dump_config(void)
{
    interface_t *               interface;
    unsigned int                index;
    unsigned int                peer;

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
    dump_filter_list("global filter", global_filter_list);

    // Interfaces
    printf("\nInterface list:\n");
    for (index = 0; index < configured_interface_count; index++)
    {
        interface = &configured_interface_list[index];
        printf(" %s (%u)\n", interface->name, interface->if_index);
        if (interface->disable_ip[IPV4] == 0)
        {
            printf("  ipv4 address %s\n", interface->ipv4_addr_str);
            printf("   peer interfaces:");
            for (peer = 0; peer < interface->peer_count[IPV4]; peer++)
            {
                printf(" %s", interface->peer_list[IPV4][peer]->name);
            }
            printf("\n");
        }
        else
        {
            printf("  ipv4 disabled\n");
        }

        if (interface->disable_ip[IPV6] == 0)
        {
            printf("  ipv6 address %s\n", interface->ipv6_addr_str);
            printf("   peer interfaces:");
            for (peer = 0; peer < interface->peer_count[IPV6]; peer++)
            {
                printf(" %s", interface->peer_list[IPV6][peer]->name);
            }
            printf("\n");
        }
        else
        {
            printf("  ipv6 disabled\n");
        }

        if (interface->inbound_filter_list)
        {
            dump_filter_list("inbound filter list", interface->inbound_filter_list);
        }
        if (interface->outbound_filter_list)
        {
            dump_filter_list("outbound filter list", interface->outbound_filter_list);
        }
        printf("\n");
    }
}
