package main

// mkarpa3 - Generate DNS reverse zone files from forward zone files
//
// This program reads one or more DNS forward zone files using the zoneparser library,
// and generates a reverse zone file containing PTR records for all A records found that
// are not marked with ";inaddr" comments.
//
// Features:
// - Converts A records to PTR records in appropriate reverse zones
// - Processes $GENERATE directives for A records and converts them to PTR directives
// - Handles $INCLUDE files and marks transitions with comments
// - Supports both input-order preservation and numerical IP address sorting
// - Extracts SOA information from the first zone file processed
// - Automatically qualifies hostnames with the SOA domain
//
// Usage:
//   mkarpa3 [-o output_file] [-d reverse_domain] [-s] zone_file [zone_file ...]
//

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"zone-tools/zoneparser"
)

type soaInfo struct {
	authns      string
	domain      string
	contact     string
	serial      uint32
	refresh     uint32
	retry       uint32
	expire      uint32
	minimum     uint32
	nameservers []string
}

type ptrRecord struct {
	lastOctet string
	hostname  string
}

type reverseZone struct {
	origin    string
	records   []ptrRecord
	generates []string
	comments  []string // Comments to include before this zone's records
}

var domain string
var ttl string
var soa soaInfo
var nsARecord string
var reverseZones map[string]*reverseZone
var reverseZoneOrder []string    // Track order of zone creation
var currentIncludeFile string    // Track current include file being processed
var includeFileCommentAdded bool // Track if we've already added a comment for current include file

// Helper function to check if a hostname is a nameserver
func isNameServer(hostname string) bool {
	for _, ns := range soa.nameservers {
		if ns == hostname {
			return true
		}
	}
	return false
}

// Add a nameserver to the list if not already present
func addNameServer(ns string) {
	for _, existing := range soa.nameservers {
		if existing == ns {
			return
		}
	}
	soa.nameservers = append(soa.nameservers, ns)
}

// Find the common domain between two different hostnames
func commonDomain(h1, h2 string) string {
	if h1 == "" && h2 == "" {
		return ""
	}
	if h1 == "" {
		return h2
	}
	if h2 == "" {
		return h1
	}

	a1 := strings.Split(strings.TrimSuffix(h1, "."), ".")
	a2 := strings.Split(strings.TrimSuffix(h2, "."), ".")
	a1len := len(a1)
	a2len := len(a2)
	var common string

	for {
		if a1len == 0 || a2len == 0 {
			break
		}
		a1len--
		a2len--
		if a1[a1len] != a2[a2len] {
			break
		}
		common = a1[a1len] + "." + common
	}
	return common
}

// Create reverse zone origin from IP address (e.g., "10.0.1.2" -> "1.0.10.in-addr.arpa.")
func createReverseOrigin(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	// For IP a.b.c.d, reverse origin is c.b.a.in-addr.arpa.
	return fmt.Sprintf("%s.%s.%s.in-addr.arpa.", parts[2], parts[1], parts[0])
}

// Get the reverse zone for an IP address
func getReverseZone(ip string) *reverseZone {
	origin := createReverseOrigin(ip)
	if origin == "" {
		return nil
	}

	if reverseZones[origin] == nil {
		reverseZones[origin] = &reverseZone{
			origin:    origin,
			records:   make([]ptrRecord, 0),
			generates: make([]string, 0),
			comments:  make([]string, 0),
		}
		// Add include file comment if we're processing an included file (only once per file)
		if currentIncludeFile != "" && !includeFileCommentAdded {
			reverseZones[origin].comments = append(reverseZones[origin].comments,
				fmt.Sprintf("; From $INCLUDE file %s", currentIncludeFile))
			includeFileCommentAdded = true
		}
		// Track order of zone creation
		reverseZoneOrder = append(reverseZoneOrder, origin)
	}
	return reverseZones[origin]
}

// Convert a $GENERATE directive for A records to PTR records
func convertGenerate(gen *zoneparser.GenerateDirective) (string, error) {
	if gen.RRType != "A" {
		return "", fmt.Errorf("can only convert A record GENERATE directives")
	}

	// Parse the range
	rangeParts := strings.Split(gen.Range, "-")
	if len(rangeParts) != 2 {
		return "", fmt.Errorf("invalid range in $GENERATE directive")
	}
	start, err := strconv.Atoi(rangeParts[0])
	if err != nil {
		return "", fmt.Errorf("invalid start value in range")
	}
	stopStep := strings.Split(rangeParts[1], "/")
	stop, err := strconv.Atoi(stopStep[0])
	if err != nil {
		return "", fmt.Errorf("invalid stop value in range")
	}
	step := 1
	if len(stopStep) == 2 {
		step, err = strconv.Atoi(stopStep[1])
		if err != nil {
			return "", fmt.Errorf("invalid step value in range")
		}
	}

	// Create PTR directive
	ptrDirective := fmt.Sprintf("$GENERATE %d-%d", start, stop)
	if step != 1 {
		ptrDirective += fmt.Sprintf("/%d", step)
	}

	// Parse IP template to get the last octet placeholder
	rhsParts := strings.Split(gen.RData, ".")
	if len(rhsParts) != 4 {
		return "", fmt.Errorf("invalid IP address format in template")
	}

	reverseTemplate := rhsParts[3]

	// Qualify the owner name with the SOA domain if needed
	ownerName := gen.OwnerName
	if !strings.HasSuffix(ownerName, ".") {
		ownerName = ownerName + "." + soa.domain
		if !strings.HasSuffix(ownerName, ".") {
			ownerName += "."
		}
	}

	ptrDirective += fmt.Sprintf(" %s IN PTR %s", reverseTemplate, ownerName)
	return ptrDirective, nil
}

// Format SOA record for output
func formatSOA() string {
	result := fmt.Sprintf("@\tIN\tSOA\t%s\t%s.%s (\n",
		soa.authns, soa.contact, soa.domain)
	result += fmt.Sprintf("\t\t\t\t%d\t ; Serial\n", soa.serial)
	result += fmt.Sprintf("\t\t\t\t%d\t\t ; Refresh\n", soa.refresh)
	result += fmt.Sprintf("\t\t\t\t%d\t\t ; Retry\n", soa.retry)
	result += fmt.Sprintf("\t\t\t\t%d\t\t ; Expire\n", soa.expire)
	result += fmt.Sprintf("\t\t\t\t%d )\t\t ; Minimum\n", soa.minimum)
	for _, ns := range soa.nameservers {
		result += fmt.Sprintf("\t\tIN\tNS\t%s\n", ns)
	}
	return result
}

// Parse zone file using the new zoneparser library
func parseZoneFile(inputFile string) error {
	parser := zoneparser.NewParser(inputFile)
	zoneData, metadata, err := parser.Parse()
	if err != nil {
		return fmt.Errorf("error parsing zone file %s: %v", inputFile, err)
	}

	// Set default TTL if not already set
	if ttl == "" {
		ttl = fmt.Sprintf("$TTL %d", metadata.TTL)
	}

	// Process each entry in the zone
	var lastSourceFile string
	for _, entry := range zoneData {
		// Track source file changes for include file comments
		if entry.SourceFile != lastSourceFile && entry.SourceFile != inputFile {
			currentIncludeFile = entry.SourceFile
			includeFileCommentAdded = false // Reset flag for new include file
			lastSourceFile = entry.SourceFile
		} else if entry.SourceFile == inputFile {
			currentIncludeFile = ""
			includeFileCommentAdded = false
			lastSourceFile = entry.SourceFile
		}

		switch entry.Type {
		case zoneparser.EntryTypeRecord:
			processHostRecord(entry.HostRecord)

		case zoneparser.EntryTypeGenerate:
			if entry.Generate.RRType == "A" {
				if ptrDirective, err := convertGenerate(entry.Generate); err == nil {
					// Add the GENERATE directive to the appropriate reverse zone
					// For now, we need to determine which reverse zone this belongs to
					// by parsing the IP template in the GENERATE directive
					rhsParts := strings.Split(entry.Generate.RData, ".")
					if len(rhsParts) == 4 {
						// Create a sample IP to determine the reverse zone
						sampleIP := fmt.Sprintf("%s.%s.%s.1", rhsParts[0], rhsParts[1], rhsParts[2])
						reverseZone := getReverseZone(sampleIP)
						if reverseZone != nil {
							reverseZone.generates = append(reverseZone.generates, ptrDirective)
						}
					}
				} else {
					fmt.Fprintf(os.Stderr, "Warning: Error converting GENERATE directive: %v\n", err)
				}
			}

		}
	}

	return nil
}

// Process a host record and extract relevant information
func processHostRecord(host *zoneparser.HostRecord) {
	hostname := host.Hostname
	records := &host.Records

	// Process SOA records
	for _, soaRecord := range records.SOA {
		if soa.domain == "" {
			// Extract domain from email field
			emailParts := strings.Split(soaRecord.Email, ".")
			if len(emailParts) > 1 {
				soa.domain = strings.Join(emailParts[1:], ".")
			}
		}
		soa.domain = commonDomain(soa.domain, strings.TrimSuffix(hostname, "."))
		soa.contact = strings.Split(soaRecord.Email, ".")[0]
		soa.authns = soaRecord.PrimaryNS
		soa.serial = soaRecord.Serial
		soa.refresh = soaRecord.Refresh
		soa.retry = soaRecord.Retry
		soa.expire = soaRecord.Expire
		soa.minimum = soaRecord.MinimumTTL
		addNameServer(soaRecord.PrimaryNS)
	}

	// Process NS records
	for _, nsRecord := range records.NS {
		addNameServer(nsRecord.NameServer)
	}

	// Process A records
	for _, aRecord := range records.A {
		// Check if this should be shown (not marked as inaddr)
		show := !aRecord.Inaddr

		if show {
			// Create PTR record and add to appropriate reverse zone
			addrParts := strings.Split(aRecord.Address.String(), ".")
			if len(addrParts) == 4 {
				reverseZone := getReverseZone(aRecord.Address.String())
				if reverseZone != nil {
					reverseZone.records = append(reverseZone.records, ptrRecord{
						lastOctet: addrParts[3],
						hostname:  hostname,
					})
				}
			}
		} else {
			// Check if this host is a nameserver, if so save the A record
			if isNameServer(hostname) {
				nsARecord = fmt.Sprintf("%s\t\tIN\tA\t%s ;inaddr", hostname, aRecord.Address.String())
			}
		}
	}
}

// Generate reverse zone file
func generateReverseZone(out *os.File, inputNames []string, sortByAddress bool) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "<unknown>"
	}

	// Print header
	fmt.Fprintln(out, ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;")
	fmt.Fprintf(out, "; Reverse zone file for domain '%s'\n", soa.domain)
	fmt.Fprintf(out, ";\n")
	fmt.Fprintf(out, "; DO NOT EDIT THIS FILE; it is programmatically updated\n")
	fmt.Fprintf(out, ";\n")
	fmt.Fprintf(out, "; Generated %s from:\n", time.Now().Format(time.UnixDate))
	for _, input := range inputNames {
		absPath, _ := filepath.Abs(input)
		fmt.Fprintf(out, ";  %s:%s\n", hostname, absPath)
	}
	fmt.Fprintln(out, ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;")

	// Print TTL
	fmt.Fprintf(out, "%s\n", ttl)

	// Print SOA
	fmt.Fprint(out, formatSOA())

	// Print nameserver A record if needed
	if nsARecord != "" {
		fmt.Fprintf(out, "\n%s\n\n", nsARecord)
	}

	// Print custom origin if specified
	if domain != "" {
		fmt.Fprintf(out, "\n$ORIGIN %s\n\n", domain)
	}

	// Get reverse zone origins in the correct order
	var origins []string
	if sortByAddress {
		origins = getSortedOrigins()
	} else {
		// Preserve input order from zone creation
		origins = reverseZoneOrder
	}

	// Output each reverse zone with its $ORIGIN directive
	for _, origin := range origins {
		reverseZone := reverseZones[origin]

		// Print any comments for this zone
		for _, comment := range reverseZone.comments {
			fmt.Fprintf(out, "%s\n", comment)
		}

		// Print the $ORIGIN directive
		fmt.Fprintf(out, "$ORIGIN %s\n", origin)

		// Sort records by last octet for consistent output
		sort.Slice(reverseZone.records, func(i, j int) bool {
			octI, _ := strconv.Atoi(reverseZone.records[i].lastOctet)
			octJ, _ := strconv.Atoi(reverseZone.records[j].lastOctet)
			return octI < octJ
		})

		// Print PTR records
		for _, record := range reverseZone.records {
			fmt.Fprintf(out, "%s\t\tIN\tPTR\t\t%s\n", record.lastOctet, record.hostname)
		}

		// Print GENERATE directives for this zone
		for _, generate := range reverseZone.generates {
			fmt.Fprintf(out, "%s\n", generate)
		}
	}
}

func main() {
	outputFile := flag.String("o", "", "The output file (optional)")
	revDomain := flag.String("d", "", "Reverse Domain (optional)")
	sortByAddress := flag.Bool("s", false, "Sort reverse zones by IP address numerically")
	help := flag.Bool("h", false, "Show help")

	flag.Parse()
	args := flag.Args()

	if len(args) < 1 || *help {
		fmt.Println("Usage: mkarpa3 [-o <output file>] [-d <reverse_domain>] [-s] <input file> [<input file> ... ]")
		fmt.Println("Generate a reverse zone file from one or more forward zone files using zoneparser library")
		flag.PrintDefaults()
		os.Exit(1)
	}

	domain = *revDomain

	// Initialize
	reverseZones = make(map[string]*reverseZone)
	reverseZoneOrder = make([]string, 0)
	currentIncludeFile = ""
	includeFileCommentAdded = false
	soa = soaInfo{nameservers: make([]string, 0)}

	// Process all input files
	for _, inputFile := range args {
		if err := parseZoneFile(inputFile); err != nil {
			fmt.Printf("Error processing file %s: %v\n", inputFile, err)
			os.Exit(1)
		}
	}

	// Generate output
	var outFile *os.File = os.Stdout
	var err error
	if *outputFile != "" {
		outFile, err = os.Create(*outputFile)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	generateReverseZone(outFile, args, *sortByAddress)
}

// getSortedOrigins returns reverse zone origins sorted numerically by IP address
func getSortedOrigins() []string {
	var origins []string
	for origin := range reverseZones {
		origins = append(origins, origin)
	}
	sort.Slice(origins, func(i, j int) bool {
		// Extract first octet from origins like "0.254.10.in-addr.arpa."
		partsI := strings.Split(origins[i], ".")
		partsJ := strings.Split(origins[j], ".")
		if len(partsI) >= 1 && len(partsJ) >= 1 {
			octI, errI := strconv.Atoi(partsI[0])
			octJ, errJ := strconv.Atoi(partsJ[0])
			if errI == nil && errJ == nil {
				return octI < octJ
			}
		}
		// Fallback to alphabetical if parsing fails
		return origins[i] < origins[j]
	})
	return origins
}
