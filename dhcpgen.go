package main

import (
	"bytes"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
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

func computeFieldWidth(maxValue int) int {
	if maxValue == 0 {
		return 1
	}

	absValue := int(math.Abs(float64(maxValue)))
	return len(strconv.Itoa(absValue))
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

func countClassCNetworks(startIP, endIP uint32) int {
	if startIP > endIP {
		return 0
	}

	startNetwork := startIP & 0xFFFFFF00
	endNetwork := endIP & 0xFFFFFF00
	networkDiff := endNetwork - startNetwork

	numNetworks := int(networkDiff >> 8)

	// Account for the possibility of a single extra network in the last byte
	if (startIP&0xFF) != 0 && (endIP&0xFF) == 255 {
		numNetworks++
	}

	return numNetworks
}

func hostPatternFormat(host, domain string, offset, width int) string {
	s := fmt.Sprintf("%s-${%d,%d,d}", host, offset, width)
	return fqdn(s, domain)
}

func hostNameFormat(host string, width, offset int) string {
	return fmt.Sprintf("%s-%0*d", host, width, offset)
}

func calculateNetworkEnd(currentIP uint32, endIP uint32) uint32 {
	networkEnd := currentIP&0xFFFFFF00 | 0xFE // x.x.x.254 max
	return min(networkEnd, endIP)
}

func generateGenerateStatements(startIP, endIP string, hostStart int, hostName string, origin string, comments bool, mx string, mx_pri uint) ([]string, error) {
	start := net.ParseIP(startIP)
	if start == nil {
		return nil, fmt.Errorf("invalid start IP address: %s", startIP)
	}

	end := net.ParseIP(endIP)
	if end == nil {
		return nil, fmt.Errorf("invalid end IP address: %s", endIP)
	}

	if bytes.Compare(start, end) > 0 {
		return nil, fmt.Errorf("start IP must be less than or equal to end IP")
	}

	startUint := ipToUint32(start)
	endUint := ipToUint32(end)

	totalHosts := int(endUint) - int(startUint) - countClassCNetworks(startUint, endUint)
	width := computeFieldWidth(totalHosts)

	var statements []string
	var offset int = 0

	if comments {
		statements = append(statements,
			fmt.Sprintf("; Creating $GENERATE directives for addresses %s through %s\n; %d hosts total", startIP, endIP, totalHosts))
	}

	var generateStatement string
	for current := startUint; current <= endUint; {
		// Determine the end of the current Class C network

		currentNetworkEnd := calculateNetworkEnd(current, endUint)
		start := int(current & 0xff)
		end := int(currentNetworkEnd) & 0xff

		if hostStart != 0 {
			offset = int(hostStart - start)
		}

		currentIP := uint32ToIP(current)
		currentIPParts := strings.Split(currentIP.String(), ".")
		ipPattern := fmt.Sprintf("%s.%s.%s.$", currentIPParts[0], currentIPParts[1], currentIPParts[2])

		generateStatement = ""

		if comments {
			generateStatement = fmt.Sprintf("\n; %s-%s => %s to %s, %d hosts", currentIP, uint32ToIP(currentNetworkEnd),
				hostNameFormat(hostName, width, offset), hostNameFormat(hostName, width, offset+end), end-start)
			statements = append(statements, generateStatement)
		}

		generateStatement = fmt.Sprintf(";$reverse-domain %s.%s.%s.in-addr.arpa.", currentIPParts[2], currentIPParts[1], currentIPParts[0])
		statements = append(statements, generateStatement)

		generateStatement = fmt.Sprintf("$GENERATE %d-%d %s IN A %s", start, end, hostPatternFormat(hostName, origin, offset, width), ipPattern)
		statements = append(statements, generateStatement)

		if mx != "" {
			generateStatement = fmt.Sprintf("$GENERATE %d-%d %s IN MX \"%d %s\"", start, end, hostPatternFormat(hostName, origin, offset, width),
				mx_pri, fqdn(mx, origin))
			statements = append(statements, generateStatement)
		}

		// Move to the next Class C network & next hostStart
		current = ((current >> 8) + 1) << 8
		hostStart = 1 + offset + end
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
	mx_pri := flag.Uint("mx_priority", 0, "MX priority (optional, default 0)")
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
	if net.ParseIP(startIP) == nil {
		fmt.Println("Error: startIP is not a valid IPv4 address.")
		os.Exit(1)
	}

	if net.ParseIP(endIP) == nil {
		fmt.Println("Error: endIP is not a valid IPv4 address.")
		os.Exit(1)
	}

	if *origin != "" && !isValidDNSDomain(*origin) {
		fmt.Printf("Error: Origin '%s' is not a valid DNS domain.\n", *origin)
		os.Exit(1)
	}

	statements, err := generateGenerateStatements(startIP, endIP, *hostStart, *hostName, *origin, *comments, *mx, *mx_pri)
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
