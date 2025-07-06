# Zone Tools

A collection of DNS zone file management utilities for automating common DNS administration tasks.

## Tools Overview

### Core Zone Management
- **mkarpa** - Generate reverse zone files from forward zone files
- **mkkea** - Generate Kea DHCP reservations from DNS zone files  
- **dhcpgen** - Generate DNS $GENERATE directives for DHCP host ranges
- **checkzone** - Wrapper around named-checkzone

### Zone File Parser Library
- **zoneparser** - Go library for parsing DNS zone files with support for $GENERATE, $INCLUDE, and various record types

## Tool Details

### mkarpa
Generates DNS reverse zone files from forward zone files using the zoneparser library.

**Key Features:**
- Converts A records to PTR records in appropriate reverse zones
- Processes $GENERATE directives and converts them to PTR directives  
- Handles $INCLUDE files with comment markers
- Supports input-order preservation or numerical IP sorting
- Extracts SOA information automatically
- Excludes A records marked with ";inaddr" comments

**Usage:**
```bash
mkarpa [-o output_file] [-d reverse_domain] [-s] zone_file [zone_file ...]
```

**Example:**
```bash
# Generate reverse zone from forward zone
mkarpa -o reverse.zone example.com.zone
```

**Example Output:**
```dns
; Reverse zone file for domain 'example.com.'
$TTL 86400
@    IN    SOA    ns.example.com. admin.example.com. (...)
     IN    NS     ns.example.com.

$ORIGIN 1.0.10.in-addr.arpa.
10    IN    PTR    web.example.com.
20    IN    PTR    mail.example.com.
$GENERATE 100-199 $ IN PTR host-$.example.com.
```

### mkkea  
Extracts DHCP reservation data from DNS zone files and generates Kea DHCP server configuration.

**Key Features:**
- Parses TXT records with "kea:" prefix for DHCP configuration
- Filters A records by network CIDR ranges
- Multiple sorting options (hostname, IP address, MAC address)
- JSON output compatible with Kea DHCP server
- Supports complex zone files with $INCLUDE directives

**TXT Record Format:**
```dns
host1    IN    A      192.168.1.10
host1    IN    TXT    "kea: mac=aa:bb:cc:dd:ee:ff client-class=kids"
```

**Usage:**
```bash
mkkea [-o output_file] [-n network/cidr] [-H|-I|-M] zone_file [zone_file ...]
```

**Example:**
```bash
# Extract DHCP reservations sorted by hostname
mkkea -H -o reservations.json example.com.zone
```

**Example Output:**
```json
[
  {
    "hostname": "host1.example.com.",
    "ip-address": "192.168.1.10",
    "hw-address": "aa:bb:cc:dd:ee:ff",
    "client-classes": ["kids"]
  }
]
```

### dhcpgen
Creates DNS $GENERATE directives for bulk DHCP host creation across IP ranges.

**Key Features:**
- Handles Class C network boundaries automatically
- Skips reserved addresses (.0 and .255)  
- Sequential host numbering across networks
- Optional MX record generation
- Detailed comments showing mappings
- Validates IPv4 addresses and ranges

**Usage:**
```bash
dhcpgen [-hoststart N] [-hostname prefix] [-origin domain] [-mx host] [-comments] start_ip end_ip
```

**Example:**
```bash
# Generate DHCP host ranges with comments
dhcpgen -comments 10.1.50.10 10.1.51.20
```

**Example Output:**
```dns
; Creating $GENERATE directives for addresses 10.1.50.10 through 10.1.51.20
; 267 hosts total, starting from host 0

; 10.1.50.10-10.1.50.255 => dhcp-000 to dhcp-245, 246 hosts  
$GENERATE 10-255 dhcp-${0,3,d} IN A 10.1.50.$

; 10.1.51.0-10.1.51.20 => dhcp-246 to dhcp-266, 21 hosts
$GENERATE 1-20 dhcp-${246,3,d} IN A 10.1.51.$
```

### checkzone
Validates DNS zone files using named-checkzone with automatic zone type detection.

**Key Features:**
- Automatically detects forward vs reverse zones
- Extracts $ORIGIN from forward zones for proper validation
- Handles multiple zone formats (.inaddr, .arpa)
- Clear error messages for different failure types
- Suitable for automated validation scripts

**Usage:**
```bash
checkzone zone_file
```

**Example:**
```bash
# Validate a zone file
checkzone example.com.zone
```

**Example Output:**
```
 > example.com.zone: valid
```

## Prerequisites
- Go 1.19+ (for Go tools)
- BIND named-checkzone (for checkzone script)

## Zone Parser Library

The `zoneparser` package provides comprehensive DNS zone file parsing capabilities:

**Supported Features:**
- Standard DNS record types (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, etc.)
- Zone file directives ($ORIGIN, $TTL, $GENERATE, $INCLUDE)
- Multi-line records with parentheses
- Comment preservation and handling
- Source file tracking for included files

**Usage Example:**
```go
import "zone-tools/zoneparser"

parser := zoneparser.NewParser("example.com.zone")
zoneData, metadata, err := parser.Parse()
if err != nil {
    log.Fatal(err)
}

for _, entry := range zoneData {
    switch entry.Type {
    case zoneparser.EntryTypeRecord:
        // Process DNS records
    case zoneparser.EntryTypeGenerate:
        // Process $GENERATE directives
    }
}
```

## Documentation

Comprehensive manual pages are available in the `man/` directory:
- `man/mkarpa3.1` - Reverse zone generation
- `man/mkkea3.1` - DHCP reservation extraction  
- `man/dhcpgen.1` - DHCP range generation

## Error Handling

All tools provide clear error messages and appropriate exit codes:
- **0** - Success
- **1** - Error (invalid input, file not found, validation failed, etc.)

