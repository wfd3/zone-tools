package main

//
// mkkea3 - Generate Kea DHCP reservations from DNS zone files
//
// mkkea3 extracts Kea DHCP reservation data from DNS zone files and outputs
// them in JSON format suitable for inclusion in Kea DHCP server configuration.
//
// The program looks for TXT records with the prefix "kea:" followed by
// key-value pairs. Currently supported Kea directives are:
//  - hw-address: MAC address for the reservation
//  - client-classes: Array of client classes (e.g., [kids, test])
//
// Only A records without the ";inaddr" comment are processed, as inaddr
// records are intended for reverse DNS generation, not DHCP reservations.
//

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"zone-tools/zoneparser"
)

const KEA_PREFIX = "kea:"

// The Kea directives we support in the TXT record
var supportedKeys = map[string]bool{
	"hw-address":     true,
	"client-classes": true,
}

var filterNetwork *net.IPNet

// KeaReservation represents a single Kea DHCP reservation
type KeaReservation struct {
	Hostname  string
	IPAddress string
	KeaData   map[string]string
}

// Comparison function type
type CompareFunc func(i, j KeaReservation) bool

//
// helper functions
//

func unescapeTXT(s string) string {
	s = strings.ReplaceAll(s, `\\`, `\`)
	s = strings.ReplaceAll(s, `\"`, `"`)
	return s
}

func splitOutsideBrackets(s string) []string {
	var result []string
	level := 0
	start := 0

	for i, r := range s {
		switch r {
		case '[':
			level++
		case ']':
			if level > 0 {
				level--
			} else {
				return nil // Handle mismatched brackets gracefully
			}
		case ',':
			if level == 0 {
				part := strings.TrimSpace(s[start:i])
				if part != "" {
					result = append(result, part)
				}
				start = i + 1
			}
		}
	}
	if start < len(s) {
		result = append(result, strings.TrimSpace(s[start:]))
	}
	if level > 0 {
		return nil // Unclosed brackets
	}
	return result
}

func quoteCSVList(bracketed string) string {
	// Trim outer brackets
	trimmed := strings.TrimSpace(bracketed)
	if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		trimmed = trimmed[1 : len(trimmed)-1]
	} else {
		return bracketed // not a bracketed list, return as-is
	}

	// Split and quote each item if needed
	parts := strings.Split(trimmed, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
		if !strings.HasPrefix(parts[i], "\"") {
			parts[i] = `"` + parts[i]
		}
		if !strings.HasSuffix(parts[i], "\"") {
			parts[i] = parts[i] + `"`
		}
	}

	return "[" + strings.Join(parts, ", ") + "]"
}

func parseKeaRecords(txt string) (map[string]string, bool, error) {
	// Is this a KEA-tagged TXT record?
	if !strings.HasPrefix(txt, KEA_PREFIX) {
		return map[string]string{}, false, nil
	}

	// Remove the KEA_PREFIX
	txt = strings.TrimPrefix(txt, KEA_PREFIX)
	txt = strings.TrimSpace(txt)

	// Now parse the concatenated string
	pairs := splitOutsideBrackets(txt)

	ok := false
	result := make(map[string]string)
	for _, pair := range pairs {
		kv := strings.SplitN(pair, " ", 2)
		if len(kv) != 2 {
			return map[string]string{}, false, nil
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		if !supportedKeys[key] {
			return nil, false, fmt.Errorf("unknown KEA directive '%s'", key)
		}

		if key == "client-classes" {
			if !strings.HasPrefix(value, "[") {
				return nil, false, fmt.Errorf("Missing '[' in client-classes: %s", value)
			}
			if !strings.HasSuffix(value, "]") {
				return nil, false, fmt.Errorf("Missing ']' in client-classes: %s", value)
			}
			value = quoteCSVList(value)
		}

		result[key] = value
		ok = true
	}
	return result, ok, nil
}

// isValidIP checks if an IP address is in the configured network filter
func isValidIP(ipStr string) bool {
	if filterNetwork == nil {
		return true
	}
	ip := net.ParseIP(ipStr)
	return ip != nil && filterNetwork.Contains(ip)
}

// normalizeMACAddress converts a MAC address string to a comparable format
// Handles different formats like "aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff", etc.
func normalizeMACAddress(mac string) string {
	// Remove common separators and convert to lowercase
	normalized := strings.ToLower(mac)
	normalized = strings.ReplaceAll(normalized, ":", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, ".", "")
	normalized = strings.ReplaceAll(normalized, " ", "")
	return normalized
}

// parseZone parses a zone file using the new parser and returns Kea reservations
func parseZone(inputFile string) ([]KeaReservation, error) {
	var reservations []KeaReservation

	// Create parser and parse the file
	parser := zoneparser.NewParser(inputFile)
	zone, _, err := parser.Parse()
	if err != nil {
		return nil, fmt.Errorf("error parsing zone file %s: %v", inputFile, err)
	}

	// Process each entry in the zone
	for _, entry := range zone {
		// We only care about host records
		if entry.Type != zoneparser.EntryTypeRecord {
			continue
		}

		hostRecord := entry.HostRecord
		hostname := hostRecord.Hostname

		// Find first valid A record (not inaddr, in network)
		validIP := findValidIP(hostRecord.Records.A)
		if validIP == "" {
			continue
		}

		// Process TXT records for Kea data
		for _, txtRecord := range hostRecord.Records.TXT {
			txt := unescapeTXT(txtRecord.Text)
			keaRecords, ok, err := parseKeaRecords(txt)
			if err != nil {
				return nil, fmt.Errorf("error processing TXT record for %s: %v", hostname, err)
			}
			if !ok {
				continue // Not a Kea TXT record
			}

			// Create reservation
			reservation := KeaReservation{
				Hostname:  hostname,
				IPAddress: validIP,
				KeaData:   keaRecords,
			}
			reservations = append(reservations, reservation)
		}
	}

	return reservations, nil
}

// findValidIP returns the first valid IP from A records (not inaddr, in network)
func findValidIP(aRecords []zoneparser.ARecord) string {
	for _, aRecord := range aRecords {
		if aRecord.Inaddr {
			continue // Skip reverse DNS records
		}
		if ip := aRecord.Address.String(); isValidIP(ip) {
			return ip
		}
	}
	return ""
}

func writeKea(outFile *os.File, allReservations []KeaReservation, files []string, networkFilter string) {
	if len(allReservations) == 0 {
		return
	}

	fmt.Fprintf(outFile, "// Generated by %s\n", os.Args[0])
	fmt.Fprintf(outFile, "// This file is auto-generated. Do not edit.\n")
	fmt.Fprintf(outFile, "//\n")
	fmt.Fprintf(outFile, "// Generated on %s\n", time.Now().Format(time.RFC1123))
	fmt.Fprintf(outFile, "// Input files: %s\n", strings.Join(files, ", "))
	if networkFilter != "" {
		fmt.Fprintf(outFile, "//\n")
		fmt.Fprintf(outFile, "// Network: %s\n", networkFilter)
	}
	fmt.Fprintf(outFile, "//\n")
	fmt.Fprintf(outFile, "\n")

	for i, reservation := range allReservations {
		if i > 0 {
			fmt.Fprintf(outFile, ",\n")
		}

		fmt.Fprintf(outFile, "{\n")
		fmt.Fprintf(outFile, "    \"hostname\": \"%s\",\n", reservation.Hostname)
		fmt.Fprintf(outFile, "    \"ip-address\": \"%s\",\n", reservation.IPAddress)

		// Sort keys for consistent output
		keys := make([]string, 0, len(reservation.KeaData))
		for key := range reservation.KeaData {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for i, key := range keys {
			value := reservation.KeaData[key]
			isLast := i == len(keys)-1
			needsQuote := !strings.HasPrefix(value, "[")
			fmt.Fprintf(outFile, "    \"%s\": ", key)
			if needsQuote {
				fmt.Fprint(outFile, "\"")
			}
			fmt.Fprintf(outFile, "%s", value)
			if needsQuote {
				fmt.Fprint(outFile, "\"")
			}

			if !isLast {
				fmt.Fprintf(outFile, ",")
			}
			fmt.Fprintf(outFile, "\n")
		}
		fmt.Fprintf(outFile, "}")
	}
	fmt.Fprintf(outFile, "\n")
}

// Individual comparator functions
func compareByHostname(i, j KeaReservation) bool {
	return i.Hostname < j.Hostname
}

func compareByIP(i, j KeaReservation) bool {
	ipA := net.ParseIP(i.IPAddress)
	ipB := net.ParseIP(j.IPAddress)
	return bytes.Compare(ipA, ipB) < 0
}

func compareByMAC(i, j KeaReservation) bool {
	macA := i.KeaData["hw-address"]
	macB := j.KeaData["hw-address"]
	if macA == "" && macB == "" {
		return false
	}
	if macA == "" {
		return true
	}
	if macB == "" {
		return false
	}
	return normalizeMACAddress(macA) < normalizeMACAddress(macB)
}

// Simplified sort function
func sortReservations(allReservations []KeaReservation, compareFunc CompareFunc) []KeaReservation {
	if len(allReservations) > 0 && compareFunc != nil {
		sort.Slice(allReservations, func(i, j int) bool {
			return compareFunc(allReservations[i], allReservations[j])
		})
	}
	return allReservations
}

func main() {
	log.SetFlags(0)
	outputFile := flag.String("o", "", "The output file (optional)")
	stop := flag.Bool("s", false, "Stop if no Kea records found in input")
	sortByHostname := flag.Bool("H", false, "Sort output by hostname")
	sortByIP := flag.Bool("I", false, "Sort output by IP address")
	sortByMAC := flag.Bool("M", false, "Sort output by MAC address")
	networkFilter := flag.String("n", "", "Limit output to specified network in CIDR format (e.g., 192.168.1.0/24)")
	help := flag.Bool("h", false, "Show help")

	flag.Parse()
	args := flag.Args()

	if len(args) < 1 || *help {
		fmt.Println("Usage: mkkea3 [-o <output file>] [-s] [-H|-I|-M] [-n <network_cidr>] <input file> [<input file> ... ]")
		fmt.Println("Extract and format the contents of a Kea 'reservations' stanza from a BIND Zone file.")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Validate that only one sort option is specified
	sortFlags := 0
	var compareFunc CompareFunc

	if *sortByHostname {
		compareFunc = compareByHostname
		sortFlags++
	}
	if *sortByIP {
		compareFunc = compareByIP
		sortFlags++
	}
	if *sortByMAC {
		compareFunc = compareByMAC
		sortFlags++
	}
	if sortFlags > 1 {
		log.Fatalf("Only one sort option can be specified (-H, -I, or -M)")
	}

	// Parse network filter if provided
	if *networkFilter != "" {
		var err error
		_, filterNetwork, err = net.ParseCIDR(*networkFilter)
		if err != nil {
			log.Fatalf("Error parsing network CIDR: %v\n", err)
		}
	}

	// Setup output file
	var outFile *os.File = os.Stdout
	var err error
	if *outputFile != "" {
		outFile, err = os.Create(*outputFile)
		if err != nil {
			log.Fatalf("Error creating output file: %v\n", err)
		}
		defer outFile.Close()
	}

	// Process all the inputs and collect reservations
	var allReservations []KeaReservation
	for _, inputFile := range args {
		reservations, err := parseZone(inputFile)
		if err != nil {
			log.Fatalf("Error processing %s: %v", inputFile, err)
		}
		allReservations = append(allReservations, reservations...)
	}

	allReservations = sortReservations(allReservations, compareFunc)

	// Output results
	if len(allReservations) == 0 {
		fmt.Println("No Kea records found in input files")
		if *stop {
			log.Fatal("Exiting")
		}
	}

	writeKea(outFile, allReservations, args, *networkFilter)
}
