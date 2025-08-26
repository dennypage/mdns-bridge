# mDNS Bridge (mdns-bridge)

**mdns-bridge is a daemon for forwarding mDNS data between network
interfaces. It is intended for use by firewalls to provide service
discovery across network segments, with and without filtering, for
both IPv4 and IPv6.**

---

### The Command Line

The command line usage for mdns-bridge is:

```
mdns-bridge [-h] [-f] [-s] [-w] [-c config_file] [-p pid_file]

    -h                  Display usage
    -f                  Run in the foreground           (default is to self-background)
    -s                  Log notifications via syslog    (default is stderr)
    -w                  Warn on various mDNS decoding errors
    -c config_file      Configuration file to use       (default is mdns-bridge.conf)
    -p pid_file         Process ID filename             (default is no pid file)
```

##### Example:

```mdns-bridge -s -c /etc/mdns-bridge.conf -p /var/run/mdns-bridge.pid```

See the Configuration File Format section below for more information on
configuring mdns-bridge.

---

### Forwarding and Filtering

By default mDNS Bridge forwards all service information between interfaces,
however one of the biggest benefits offered by mdns-bridge is its ability to
provide filtering on the service information shared between networks.

mdns-bridge has very flexible filtering, supporting both global filter lists
that apply to all interfaces, as well as interface specific filter lists for
both inbound and outbound.

In all cases, filters may either be specified as 'allow', in which case only
names that match the filter will be forewarded, or 'deny', in which case
only names that do not match the filter will be forwarded.

#### Labels

The filter matching in mdns-bridge is based on a subset of an mDNS
name. A filter subset is one or more "labels" (a DNS term) from a
mDNS name. Labels are commonly separated by a `.` in mDNS names.

##### Example mDNS names:
*  `Office-Printer._ipp._tcp.local`
*  `Office-Printer._ipps._tcp.local`
*  `Personal-Printer._ipp._tcp.local`
*  `MyAppleTV._airplay._tcp.local`
*  `mywebserver._http._tcp.local`
*  `laptop._ssh._tcp.local`

In these examples, `Office-Printer`, `_ipp`, `_ipps`, `_tcp`, `local`,
`Personal-Printer`, `MyAppleTV`, `_airplay`, `mywebserver`, `_http`,
`laptop` and `_ssh` are all labels.

In general, filtering is be applied at the service level. In the
above examples, `_ipp`, `_ipps`, `_airplay`, `_http` and `_ssh` are
labels that denote services.

#### Filters

A filter consists of one or more labels. Labels in mdns-bridge are
treated as case sensitive. Note that it is not necessary (or useful) to
include `_tcp` or `local` labels in filters as these are redundant.

##### Examples of (useful) filters based on the above DNS names:
```
    _ipp                      Select the Internet Printing Protocol (_ipp)
                              services for all hosts.
    Office-Printer            Select all services on host Office Printer.
    Office-Printer._ipp       Select all the Internet Printing Protocol on
                              host Office Printer.
    _airplay                  Select all Airplay services.
    MyAppleTV._airplay        Select the Airplay service on host MyAppleTV.
```

Note that when specifying allow rules, it is generally necessary to allow
an entire service, such as `_airplay`, rather than a hostname/service
combination such as `MyAppleTV._airplay`. Filters including hostnames are
best used ***only*** in deny filters.


#### Filter Lists

A filter list is a collection of filters separated by commas.
##### Example filter lists:
```
    _ipp, _ipps, _airplay
    _http, _ssh
    mywebserver._http, Office-Printer._ipps, _ssh
```

---

# Configuration File Format

The configuration file for mdns-bridge is an ini styled file, containing a
global configuration section, and optionally an interface section for each
configured interface.

## The Global Section

The global section is required, and must be the first section in the
configuration file.

#### Example global section:

```
[global]
  # The list of interfaces (mandatory).
  interfaces = ix0, igc0

  # Optionally Disable ipv4.
  disable-ipv4 = no

  # Optionally Disable ipv6.
  disable-ipv6 = no

  # An optional list of filters to globally allow
  allow-inbound-filters = _ipp, _ipps, _airplay

  # Optionally disable all packet filtering. If no filters are defined, use
  # of this option will completely disable packet decoding. Packets received
  # on an interface will be forwarded directly to neighboring interfaces
  # without any form of validation. Use this option with caution.
  disable-packet-filtering = no

```

#### The following properties may be defined in the global section:

* `interfaces`: The list of interfaces that mdns-bridge will operate on.
    All interfaces listed must be present in the system. This parameter is
    required.
* `disable-ipv4`: This allows IPv4 to be disabled globally. Valid values
    are `yes` or `no`. The default is `no`.
* `disable-ipv6`: This allows IPv6 to be disabled globally. Valid values
    are `yes` or `no`. The default is `no`.
* `allow-inbound-filters`: If defined, any names that do not match one
    of the filters in the list will be discarded from incoming packets on
    all interfaces. The default is to allow all names.
* `deny-inbound-filters`: If defined, any names that match one of the
    filters in the list will be discarded from incoming packets on all
    interfaces. There is no default.
* `disable-packet-filtering`: If no filters are defined, setting this option
    to `yes` will completely disable packet decoding. Packets received on an
    interface will be forwarded directly to neighboring interfaces without
    any form of validation. **Use this option with caution**.

##### Notes:
* Only one global filter list may be provided. Either an allow list, or a
    deny list, but not both.
* The global filter is applied immediately upon receipt of packets from
    any interface, prior to processing interface specific filters. Interface
    specific filters do not override the global filter.
* The default behavior is to allow all names.
* `disable-packet-filtering = yes` may not be combined filters of any kind,
    either in the global section or in interface sections.

---

## Interface Sections

Interface sections are optional and may be in any order. All parameters in
an interface section are optional.

#### Example interface section:

```
[ix0]
  # Optionally Disable ipv4.
  disable-ipv4 = no

  # Optionally Disable ipv6.
  disable-ipv6 = no

  # An optional list of filters to allow inbound
  allow-inbound-filters = _ipp, _ipps, _airplay

  # An option list of filters to deny outbound
  deny-outbound-filters = _ssh

```

#### The following properties may be defined in interface sections:

* `disable-ipv4`: This allows IPv4 to be disabled for this interface.
   Valid values are `yes` or `no`. The default is `no`.
* `disable-ipv6`: This allows IPv6 to be disabled for this interface.
   Valid values are `yes` or `no`. The default is `no`.
* `allow-inbound-filters`: If defined, any names that do not match one of
    the filters in the list will be discarded from incoming packets on
    this interface. The default is to allow all names.
* `deny-inbound-filters`: If defined, any names that match one of the
    filters in the list will be discarded from incoming packets on this
    interfaces. There is no default.
* `allow-outbound-filters`: If defined, any names that do not match one
    of the filters in the list will be discarded from outgoing packets on
    this interface. The default is to allow all names.
* `deny-outbound-filters`: If defined, any names that match one of the
    filters in the list will be discarded from outgoing packets on this
    interfaces. There is no default.

##### Notes:
* The parameter to enable or disable IPv4/IPv6 cannot override the global
    setting. I.E. if the global setting is `disable-ipv6 = yes`, an
    interface may not specify `disable-ipv6 = no`.
* Only one inbound filter list may be provided per interface. Either an
    allow list, or a deny list, but not both.
* Only one outbound filter list may be provided per interface. Either an
    allow list, or a deny list, but not both.
* Inbound interface filters are applied following the global filters. An
    inbound interface filter does not override the global filter list.
* Outbound interface filters are applied prior to sending packets to the
    interface.
* The default behavior is to allow all names inbound and outbound.

---

## Technical information

### Supported mDNS types
The following mDNS types are supported by mdns-bridge:

| Type    |  ID  | Description               | Filtering                        |
| :------ | ---: | :------------------------ | :------------------------------- |
| A       |   1  | IPv4 address              | Link local addresses<sup>*</sup> |
| CNAME   |   5  | Name alias                | Target name                      |
| PTR     |  12  | Pointer to a name         | Target name                      |
| HINFO   |  13  | Host information          | Owner domain name                |
| TXT     |  16  | Text records              | Owner domain name                |
| AAAA    |  28  | IPv6 address              | Link local addresses<sup>*</sup> |
| SRV     |  33  | Service location          | Owner domain name                |
| DNAME   |  39  | Domain alias              | Target name                      |
| OPT     |  41  | EDNS indicator            | Not filtered                     |
| NSEC    |  47  | Nonexistence indicator    | Not filtered                     |
| SVCB    |  64  | Service binding           | Owner domain name                |
| HTTPS   |  65  | Service binding (https)   | Owner domain name                |
| ANY     | 255  | All record types request  | Not filtered                     |

<sup>*</sup> A and AAAA records are not filtered by name, but link local addresses are never forwarded.
  
### Unsupported mDNS types
The following mDNS types are not supported by mdns-bridge, and will be
dropped if found in mDNS packets:

| Type    |  ID  | Description               |
| :------ | ---: | :------------------------ |
| NS      |   2  | Name server               |
| SOA     |   6  | Zone authority            |
| MX      |  15  | Mail exchange             |
| RP      |  17  | Responsible person        |
| AFSDB   |  18  | AFS database cell         |
| RT      |  21  | No longer used            |
| PX      |  26  | No longer used            |
| KX      |  36  | Key exchange              |

There is an option (-w) that can be used to enable a warning message
whenever an unsupported type is encountered.

**If anyone encounters a valid use case for an unsupported mDNS
type, please create an issue describing the situation.**
