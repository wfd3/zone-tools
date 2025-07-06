package main

//
// dhcpgen - Generate DNS $GENERATE directives for DHCP host ranges
//
// This program creates DNS $GENERATE directives for bulk DHCP host creation across
// IP address ranges. It automatically handles Class C network boundaries, skips
// reserved addresses (.0 and .255), and provides sequential host numbering.
//
// Usage:
//   dhcpgen [-options] start_ip end_ip
//
// Example:
//   dhcpgen -comments -hoststart 100 -hostname guest 10.1.50.10 10.1.51.20
//

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Network constants
const (
	ClassCNetworkMask = 0xFFFFFF00
	MaxHostInNetwork  = 0xFE // x.x.x.254 max
	LastOctetMask     = 0xFF
)

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
}

func uint32ToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func isValidDNSDomain(domain string) bool {
	var dnsRegex = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(\.)?$`)

	if len(domain) > 253 {
		return false
	}

	return dnsRegex.MatchString(domain)
}

func getFieldWidth(maxValue int) int {
	if maxValue == 0 {
		return 1
	}
	return len(strconv.Itoa(maxValue))
}

func fqdn(host, domain string) string {
	if strings.HasSuffix(host, ".") {
		return host
	}

	if domain == "" {
		return host
	}

	fqdn := strings.Join([]string{host, domain}, ".")
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}

	return fqdn
}

// countValidHosts counts usable host addresses in the range (excludes .0 and .255)
func countValidHosts(startIP, endIP uint32) int {
	if startIP > endIP {
		return 0
	}

	count := 0
	for ip := startIP; ip <= endIP; ip++ {
		octet := int(ip & LastOctetMask)
		if octet != 0 && octet != 255 {
			count++
		}
	}
	return count
}

func makeHostPattern(host, domain string, offset, width int) string {
	s := fmt.Sprintf("%s-${%d,%d,d}", host, offset, width)
	return fqdn(s, domain)
}

func makeHostName(host string, width, offset int) string {
	return fmt.Sprintf("%s-%0*d", host, width, offset)
}

// network represents a Class C network for generation
type network struct {
	baseIP     uint32 // Network base (e.g., 10.1.1.0)
	startOctet int    // Starting octet in this network
	endOctet   int    // Ending octet in this network
	hostStart  int    // Starting host number
}

// generateForNetwork creates $GENERATE statements for a single network
func generateForNetwork(net network, hostName, origin string, width int, comments bool, mx string, mxPri uint) []string {
	var statements []string

	// Create IP pattern (e.g., "10.1.1.$")
	baseIP := uint32ToIP(net.baseIP)
	parts := strings.Split(baseIP.String(), ".")
	ipPattern := fmt.Sprintf("%s.%s.%s.$", parts[0], parts[1], parts[2])

	// Count valid hosts for comments
	validHosts := 0
	for octet := net.startOctet; octet <= net.endOctet; octet++ {
		if octet != 0 && octet != 255 {
			validHosts++
		}
	}

	// Add comment if requested
	if comments && validHosts > 0 {
		startIP := fmt.Sprintf("%s.%s.%s.%d", parts[0], parts[1], parts[2], net.startOctet)
		endIP := fmt.Sprintf("%s.%s.%s.%d", parts[0], parts[1], parts[2], net.endOctet)
		startHost := makeHostName(hostName, width, net.hostStart)
		endHost := makeHostName(hostName, width, net.hostStart+validHosts-1)
		comment := fmt.Sprintf("\n; %s-%s => %s to %s, %d hosts",
			startIP, endIP, startHost, endHost, validHosts)
		statements = append(statements, comment)
	}

	// Generate $GENERATE statements, skipping .0 and .255
	hostOffset := net.hostStart
	for octet := net.startOctet; octet <= net.endOctet; octet++ {
		if octet == 0 || octet == 255 {
			continue // Skip reserved addresses
		}

		// Find continuous range of valid octets
		rangeStart := octet
		for octet <= net.endOctet && octet != 0 && octet != 255 {
			octet++
		}
		rangeEnd := octet - 1

		// Generate A record
		aRecord := fmt.Sprintf("$GENERATE %d-%d %s IN A %s",
			rangeStart, rangeEnd,
			makeHostPattern(hostName, origin, hostOffset, width),
			ipPattern)
		statements = append(statements, aRecord)

		// Generate MX record if specified
		if mx != "" {
			mxRecord := fmt.Sprintf("$GENERATE %d-%d %s IN MX \"%d %s\"",
				rangeStart, rangeEnd,
				makeHostPattern(hostName, origin, hostOffset, width),
				mxPri, fqdn(mx, origin))
			statements = append(statements, mxRecord)
		}

		// Update host offset
		hostOffset += (rangeEnd - rangeStart + 1)
		octet-- // Adjust for outer loop increment
	}

	return statements
}

// getNetworksInRange splits IP range into Class C networks
func getNetworksInRange(startIP, endIP uint32, hostStart int) []network {
	var networks []network
	current := startIP
	hostOffset := hostStart

	for current <= endIP {
		// Get network base (e.g., 10.1.1.0)
		networkBase := current & ClassCNetworkMask

		// Find range within this network
		startOctet := int(current & LastOctetMask)
		networkEnd := min(networkBase|255, endIP)
		endOctet := int(networkEnd & LastOctetMask)

		// Count valid hosts in this network
		validHosts := 0
		for octet := startOctet; octet <= endOctet; octet++ {
			if octet != 0 && octet != 255 {
				validHosts++
			}
		}

		// Add network if it has valid hosts
		if validHosts > 0 {
			networks = append(networks, network{
				baseIP:     networkBase,
				startOctet: startOctet,
				endOctet:   endOctet,
				hostStart:  hostOffset,
			})
			hostOffset += validHosts
		}

		// Move to next Class C network
		current = ((networkBase >> 8) + 1) << 8
	}

	return networks
}

// validateIPRange validates the IP range inputs
func validateIPRange(startIP, endIP string) (uint32, uint32, error) {
	start := net.ParseIP(startIP)
	if start == nil {
		return 0, 0, fmt.Errorf("invalid start IP address: %s", startIP)
	}

	end := net.ParseIP(endIP)
	if end == nil {
		return 0, 0, fmt.Errorf("invalid end IP address: %s", endIP)
	}

	if bytes.Compare(start, end) > 0 {
		return 0, 0, fmt.Errorf("start IP must be less than or equal to end IP")
	}

	return ipToUint32(start), ipToUint32(end), nil
}

func generateStatements(startIP, endIP string, hostStart int, hostName string, origin string, comments bool, mx string, mxPri uint) ([]string, error) {
	// Validate inputs
	startUint, endUint, err := validateIPRange(startIP, endIP)
	if err != nil {
		return nil, err
	}
	if hostStart < 0 {
		return nil, fmt.Errorf("hostStart cannot be negative: %d", hostStart)
	}

	// Count total valid hosts and calculate field width
	totalHosts := countValidHosts(startUint, endUint)
	if totalHosts == 0 {
		return nil, fmt.Errorf("no valid host addresses in range %s to %s", startIP, endIP)
	}
	maxHostNumber := hostStart + totalHosts - 1
	width := getFieldWidth(maxHostNumber)

	var statements []string

	// Add header comment
	if comments {
		header := fmt.Sprintf("; Creating $GENERATE directives for addresses %s through %s\n; %d hosts total, starting from host %d",
			startIP, endIP, totalHosts, hostStart)
		statements = append(statements, header)
	}

	// Get networks and generate statements for each
	networks := getNetworksInRange(startUint, endUint, hostStart)
	for _, net := range networks {
		netStatements := generateForNetwork(net, hostName, origin, width, comments, mx, mxPri)
		statements = append(statements, netStatements...)
	}

	return statements, nil
}

func main() {
	hostStart := flag.Int("hoststart", 0, "Where to start host numbering (optional)")
	hostName := flag.String("hostname", "dhcp", "Hostname prefix (optional)")
	origin := flag.String("origin", "", "DNS domain (optional)")
	comments := flag.Bool("comments", false, "Add comments for each $GENERATE directive")
	outputFile := flag.String("o", "", "Output file (optional)")
	mx := flag.String("mx", "", "Add MX record (optional)")
	mxPri := flag.Uint("mx_priority", 0, "MX priority (optional, default 0)")
	help := flag.Bool("h", false, "Show help")

	flag.Parse()

	args := flag.Args()
	if len(args) != 2 || *help {
		fmt.Println("Usage: dhcpgen [-hoststart N] [-hostname prefix] [-origin origin] [-mx <mx_host>] [-mx_priority N] [-comments] [-o output] start_ip end_ip")
		fmt.Println("Create $GENERATE directives for DHCP hosts in a specific address range")
		flag.Usage()
		os.Exit(1)
	}

	startIP := args[0]
	endIP := args[1]

	// Validate the input
	if startIP == "" || endIP == "" {
		fmt.Println("Error: Both startIP and endIP must be specified.")
		flag.Usage()
		os.Exit(1)
	}

	// Validate that the IP addresses are in the correct format
	startIPAddr := net.ParseIP(startIP)
	if startIPAddr == nil || startIPAddr.To4() == nil {
		fmt.Println("Error: startIP is not a valid IPv4 address.")
		os.Exit(1)
	}

	endIPAddr := net.ParseIP(endIP)
	if endIPAddr == nil || endIPAddr.To4() == nil {
		fmt.Println("Error: endIP is not a valid IPv4 address.")
		os.Exit(1)
	}

	// Additional validation
	if *hostStart < 0 {
		fmt.Println("Error: hoststart cannot be negative.")
		os.Exit(1)
	}

	if *hostName == "" {
		fmt.Println("Error: hostname cannot be empty.")
		os.Exit(1)
	}

	if *origin != "" && !isValidDNSDomain(*origin) {
		fmt.Printf("Error: Origin '%s' is not a valid DNS domain.\n", *origin)
		os.Exit(1)
	}

	statements, err := generateStatements(startIP, endIP, *hostStart, *hostName, *origin, *comments, *mx, *mxPri)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Generate output
	var outFile *os.File = os.Stdout
	if *outputFile != "" {
		// Output to the specified file
		outFile, err = os.Create(*outputFile)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	for _, stmt := range statements {
		fmt.Fprintln(outFile, stmt)
	}
}
