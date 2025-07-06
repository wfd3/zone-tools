package main

import (
	"fmt"
	"zone-tools/zoneparser"
)

// Example usage and test of the DNS zone parser
func main() {
	parser := zoneparser.NewParser("example.zone")
	zone, metadata, err := parser.Parse()
	if err != nil {
		fmt.Printf("Error parsing zone file: %v\n", err)
		return
	}

	// Print a summary of what we parsed
	fmt.Printf("Parsed zone file with %d entries\n", len(zone))
	for i, entry := range zone {
		switch entry.Type {
		case zoneparser.EntryTypeRecord:
			fmt.Printf("Entry %d: Record for %s (from %s)\n", i, entry.HostRecord.Hostname, entry.SourceFile)
		case zoneparser.EntryTypeGenerate:
			fmt.Printf("Entry %d: $GENERATE %s (from %s)\n", i, entry.Generate.Range, entry.SourceFile)
		case zoneparser.EntryTypeTTL:
			fmt.Printf("Entry %d: $TTL %d (from %s)\n", i, entry.TTL.Value, entry.SourceFile)
		case zoneparser.EntryTypeOrigin:
			fmt.Printf("Entry %d: $ORIGIN %s (from %s)\n", i, entry.Origin.Domain, entry.SourceFile)
		case zoneparser.EntryTypeInclude:
			fmt.Printf("Entry %d: $INCLUDE %s (from %s)\n", i, entry.Include.Filename, entry.SourceFile)
		}
	}

	// Only print metadata headers once from metadata, not from zone entries
	fmt.Printf("\n$ORIGIN %s\n", metadata.Origin)
	fmt.Printf("$TTL %d\n\n", metadata.TTL)

	// Process each entry in the order they appeared in the file
	for _, entry := range zone {
		switch entry.Type {
		case zoneparser.EntryTypeRecord:
			zoneparser.PrintHostRecords(entry.HostRecord, metadata.Origin)

		case zoneparser.EntryTypeTTL:
			// Don't print TTL directive as it was already printed from metadata
			continue

		case zoneparser.EntryTypeOrigin:
			// Only print ORIGIN directive if it's different from the original
			if entry.Origin.Domain != metadata.Origin {
				fmt.Printf("$ORIGIN %s\n", entry.Origin.Domain)
			}

		case zoneparser.EntryTypeInclude:
			fmt.Printf("$INCLUDE %s\n", entry.Include.Filename)

		case zoneparser.EntryTypeGenerate:
			gen := entry.Generate
			fmt.Printf("$GENERATE %s %s %s %s \"%s\"\n",
				gen.Range, gen.OwnerName, gen.Class, gen.RRType, gen.RData)
		}
	}
}