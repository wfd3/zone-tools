# Zone Parser Library Documentation

The `zoneparser` package provides comprehensive DNS zone file parsing functionality for Go applications. It supports parsing standard DNS zone files with various record types and zone file directives.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Supported Record Types](#supported-record-types)
- [Supported Directives](#supported-directives)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Features](#features)
- [Testing](#testing)

## Installation

```bash
go get zone-tools/zoneparser
```

## Quick Start

```go
package main

import (
    "fmt"
    "zone-tools/zoneparser"
)

func main() {
    // Create a new parser
    parser := zoneparser.NewParser("example.zone")
    
    // Parse the zone file
    zone, metadata, err := parser.Parse()
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    // Print zone metadata
    fmt.Printf("Origin: %s\n", metadata.Origin)
    fmt.Printf("TTL: %d\n", metadata.TTL)
    
    // Process entries
    for _, entry := range zone {
        switch entry.Type {
        case zoneparser.EntryTypeRecord:
            fmt.Printf("Host: %s\n", entry.HostRecord.Hostname)
        case zoneparser.EntryTypeOrigin:
            fmt.Printf("$ORIGIN %s\n", entry.Origin.Domain)
        // ... handle other entry types
        }
    }
}
```

## Supported Record Types

The library supports the following DNS record types:

### Core Record Types
- **A** - IPv4 address records
- **AAAA** - IPv6 address records  
- **CNAME** - Canonical name records
- **MX** - Mail exchange records
- **TXT** - Text records
- **NS** - Name server records
- **SOA** - Start of authority records
- **PTR** - Pointer records

### Extended Record Types
- **SRV** - Service location records
- **CAA** - Certification Authority Authorization records
- **HINFO** - Host information records
- **NAPTR** - Naming Authority Pointer records
- **SPF** - Sender Policy Framework records

## Supported Directives

### Zone File Directives
- **$ORIGIN** - Sets the origin domain for relative names
- **$TTL** - Sets the default TTL for records
- **$INCLUDE** - Includes another zone file
- **$GENERATE** - Generates multiple records from a template

### Special Features
- **Multi-line records** - Supports records spanning multiple lines with parentheses
- **Comments** - Handles semicolon-delimited comments while preserving quoted content
- **Quote handling** - Properly processes quoted strings in TXT and other records
- **Source tracking** - Tracks which file each record came from (useful with $INCLUDE)

## API Reference

### Core Types

#### Parser
```go
type Parser struct {
    // Internal fields
}

// NewParser creates a new zone file parser
func NewParser(filename string) *Parser

// Parse parses the zone file and returns the parsed data
func (p *Parser) Parse() (ZoneData, ZoneMetadata, error)
```

#### ZoneData and ZoneMetadata
```go
type ZoneData []ZoneEntry

type ZoneMetadata struct {
    Origin string
    TTL    uint32
}
```

#### ZoneEntry
```go
type ZoneEntry struct {
    Type       EntryType
    HostRecord *HostRecord
    TTL        *TTLDirective
    Origin     *OriginDirective
    Include    *IncludeDirective
    Generate   *GenerateDirective
    SourceFile string
}
```

### Record Types

#### ResourceRecord (Base)
```go
type ResourceRecord struct {
    TTL   uint32
    Class string
}
```

#### A Record
```go
type ARecord struct {
    ResourceRecord
    Address net.IP
    Inaddr  bool  // Set to true if record has ";inaddr" or ";in-addr" comment
}
```

#### AAAA Record
```go
type AAAARecord struct {
    ResourceRecord
    Address net.IP
}
```

#### CNAME Record
```go
type CNAMERecord struct {
    ResourceRecord
    Target string
}
```

#### MX Record
```go
type MXRecord struct {
    ResourceRecord
    Priority uint16
    Mail     string
}
```

#### TXT Record
```go
type TXTRecord struct {
    ResourceRecord
    Text string
}
```

#### NS Record
```go
type NSRecord struct {
    ResourceRecord
    NameServer string
}
```

#### SOA Record
```go
type SOARecord struct {
    ResourceRecord
    PrimaryNS  string
    Email      string
    Serial     uint32
    Refresh    uint32
    Retry      uint32
    Expire     uint32
    MinimumTTL uint32
}
```

#### SRV Record
```go
type SRVRecord struct {
    ResourceRecord
    Priority uint16
    Weight   uint16
    Port     uint16
    Target   string
}
```

#### CAA Record
```go
type CAARecord struct {
    ResourceRecord
    Flags uint8
    Tag   string
    Value string
}
```

### Utility Functions

#### Format Functions
```go
// FormatHostname formats a hostname relative to an origin
func FormatHostname(hostname, origin string) string

// HasAnyRecords checks if a DNSRecords struct contains any records
func HasAnyRecords(records *DNSRecords) bool

// PrintHostRecords prints all records for a host in zone file format
func PrintHostRecords(host *HostRecord, origin string)
```

## Examples

### Basic Zone File Parsing

```go
parser := zoneparser.NewParser("example.zone")
zone, metadata, err := parser.Parse()
if err != nil {
    log.Fatal(err)
}

// Print all A records
for _, entry := range zone {
    if entry.Type == zoneparser.EntryTypeRecord {
        for _, aRecord := range entry.HostRecord.Records.A {
            fmt.Printf("%s IN A %s\n", 
                entry.HostRecord.Hostname, 
                aRecord.Address.String())
        }
    }
}
```

### Handling Different Record Types

```go
for _, entry := range zone {
    if entry.Type == zoneparser.EntryTypeRecord {
        records := entry.HostRecord.Records
        hostname := entry.HostRecord.Hostname
        
        // Process A records
        for _, record := range records.A {
            fmt.Printf("%s has IPv4: %s\n", hostname, record.Address)
        }
        
        // Process MX records
        for _, record := range records.MX {
            fmt.Printf("%s has mail server: %s (priority %d)\n", 
                hostname, record.Mail, record.Priority)
        }
        
        // Process TXT records
        for _, record := range records.TXT {
            fmt.Printf("%s has text: %s\n", hostname, record.Text)
        }
    }
}
```

### Working with Zone Directives

```go
for _, entry := range zone {
    switch entry.Type {
    case zoneparser.EntryTypeOrigin:
        fmt.Printf("Origin changed to: %s\n", entry.Origin.Domain)
        
    case zoneparser.EntryTypeTTL:
        fmt.Printf("TTL changed to: %d\n", entry.TTL.Value)
        
    case zoneparser.EntryTypeGenerate:
        gen := entry.Generate
        fmt.Printf("Generate directive: %s %s %s %s\n",
            gen.Range, gen.OwnerName, gen.RRType, gen.RData)
            
    case zoneparser.EntryTypeInclude:
        fmt.Printf("Including file: %s\n", entry.Include.Filename)
    }
}
```

### Output Formatting

```go
// Print records in zone file format
for _, entry := range zone {
    if entry.Type == zoneparser.EntryTypeRecord {
        zoneparser.PrintHostRecords(entry.HostRecord, metadata.Origin)
    }
}
```

## Features

### Advanced Parsing Capabilities

1. **Multi-line Record Support**: Handles records that span multiple lines using parentheses:
   ```
   example.com. IN SOA ns1.example.com. admin.example.com. (
       2023010101  ; Serial
       3600        ; Refresh
       1800        ; Retry
       604800      ; Expire
       86400 )     ; Minimum TTL
   ```

2. **Comment Handling**: Preserves content within quotes while removing comments:
   ```
   test IN TXT "text ; with semicolon" ; this is a comment
   ```

3. **Quote-Aware Tokenization**: Properly handles quoted strings with spaces:
   ```
   test IN TXT "hello world" "multiple strings"
   ```

4. **Source File Tracking**: Each entry tracks its source file for debugging:
   ```go
   fmt.Printf("Record from file: %s\n", entry.SourceFile)
   ```

### Special Record Features

1. **Inaddr Detection**: A records with `;inaddr` or `;in-addr` comments are flagged:
   ```go
   if aRecord.Inaddr {
       fmt.Println("This record should appear in reverse zones")
   }
   ```

2. **Domain Qualification**: Relative domain names are automatically qualified with the current origin

3. **TXT Record Handling**: Properly processes multiple quoted segments and single quoted strings

### Error Handling

The parser provides detailed error messages with line numbers and context:
```go
zone, metadata, err := parser.Parse()
if err != nil {
    fmt.Printf("Parse error: %v\n", err)
    // Error includes file name, line number, and context
}
```

## Testing

The library includes comprehensive tests covering:

- All record types and their validation
- Zone directive processing  
- Multi-line record parsing
- Comment handling
- Quote processing
- Error conditions
- Integration scenarios

Run tests with:
```bash
go test -v ./zoneparser
```

Run tests with coverage:
```bash
go test -v -cover ./zoneparser
```

Current test coverage: **86.5%**

### Test Files

The `testdata/` directory contains example zone files for testing:
- `simple.zone` - Basic zone with common record types
- `complex.zone` - Advanced features and edge cases
- `generate.zone` - $GENERATE directive examples
- `include.zone` - $INCLUDE directive examples
- `errors.zone` - Invalid syntax for error testing

## Best Practices

1. **Error Handling**: Always check the error return value from `Parse()`
2. **Memory Usage**: For large zone files, process entries incrementally rather than storing all in memory
3. **Source Tracking**: Use the `SourceFile` field to provide context in error messages
4. **Domain Names**: Remember that domain names returned by the parser are fully qualified (end with '.')
5. **Record Processing**: Check record type before accessing type-specific fields

## License

This library is part of the zone-tools project. See the main project LICENSE file for details.