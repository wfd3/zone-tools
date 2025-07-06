package main

// Generate reverse zone files from one or more forward zones

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

const KEA_PREFIX = "kea:"

// The Kea directives we support in the TXT record
var supportedKeys = map[string]bool{
	"hw-address":     true,
	"client-classes": true,
}

var filterNetwork *net.IPNet

// Regular expressions
var extractQuotes = regexp.MustCompile(`"((?:\\.|[^"\\])*)"`)
var commentToEndOfLine = regexp.MustCompile(`;.*`)

//
// helper functions
//

func trimQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func isInNetwork(ipStr string) bool {
	if filterNetwork == nil {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return filterNetwork.Contains(ip)
}

func stripUnquotedComment(s string) string {
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				return strings.TrimSpace(s[:i])
			}
		}
	}
	return s
}

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
				panic(fmt.Sprintf("Mismatched closing bracket: %s", s))
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

func readLogicalLine(r *bufio.Reader, line *uint32) (string, error) {
	var result string
	var insideParens bool

	for {
		*line++
		s, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}

		s = strings.TrimRight(s, "\r\n")
		//s = commentToEndOfLine.ReplaceAllString(s, "") // remove ; comments
		s = stripUnquotedComment(s) // remove ; comments
		s = strings.TrimSpace(s)

		if s == "" {
			if err == io.EOF {
				break
			}
			continue
		}

		// Append to result
		if result != "" {
			result += " "
		}
		result += s

		// Handle parentheses
		insideParens = strings.Contains(result, "(") && !strings.Contains(result, ")")

		if !insideParens || strings.Contains(result, ")") {
			break
		}

		if err == io.EOF {
			break
		}
	}
	return result, nil
}

func parseARecord(line string) (hostname string, ip string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) >= 4 &&
		strings.ToUpper(fields[1]) == "IN" &&
		strings.ToUpper(fields[2]) == "A" {
		return fields[0], fields[3], true
	}
	return "", "", false
}

func parseTXTLine(line string) (name string, txt string, ok bool, err error) {
	// txtRecord matches a TXT RR with optional parens and one or more quoted strings.
	// It captures an optional hostname and the full quoted payload (e.g. "foo" "bar").
	// Allows lines like: name IN TXT ("str1" "str2") or name IN TXT "str1"
	txtRecord := regexp.MustCompile(`(?i)^\s*(?:(\S+)\s+)?IN\s+TXT\s+\(?\s*((?:"(?:\\.|[^"\\])*"\s*)+)\s*\)?$`)

	matches := txtRecord.FindStringSubmatch(line)
	if matches == nil {
		return "", "", false, nil // Not a TXT record
	}
	name = matches[1]
	raw := matches[2]

	segments := extractQuotes.FindAllStringSubmatch(raw, -1)
	if segments == nil {
		return "", "", false, fmt.Errorf("no quoted segments found in TXT record: %q", line)
	}

	for _, s := range segments {
		txt += unescapeTXT(trimQuotes(strings.TrimSpace(s[1])))
		txt += " "
	}
	txt = strings.TrimSpace(txt)
	return name, txt, true, nil
}

func parseKeaRecords(txt string) (map[string]string, bool, error) {

	// Join multiple lines with ", " and trim quotes/space

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
			return nil, false, fmt.Errorf("Unknown KEA directive '%s'", key)
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

func isKeaTXTRecord(line string, host string) (map[string]string, bool, error) {
	// Check if the line is a TXT record
	name, txt, ok, err := parseTXTLine(line)
	if err != nil || !ok {
		return nil, false, err
	}

	// Check if the TXT record contains Kea records
	kearecords, ok, err := parseKeaRecords(txt)
	if !ok {
		return nil, false, err
	}

	// The TXT record contained valid Kea records, make sure we have a good hostname
	if host == "" && name == "" {
		return nil, false, fmt.Errorf("No hostname found")
	}
	if host != name && name != "" {
		return nil, false, fmt.Errorf("Hostname mismatch: %s != %s", name, host)
	}

	return kearecords, true, nil
}

// Zonefile parsing
func parseZone(inputFile string, out *os.File) bool {
	var line uint32
	var needComma bool = false
	var emittedHeader bool = false
	var host string = ""
	var ip string = ""

	in, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Error opening input file: %v\n", err)
	}
	defer in.Close()

	r := bufio.NewReader(in)

	for {
		s, err := readLogicalLine(r, &line)
		if s == "" && err == nil {
			break
		}

		s = strings.TrimSpace(s)

		if s == "" || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "\n") || strings.HasPrefix(s, "$ORIGIN") {
			continue
		}

		// Looking at a complete A RR "host IN A 1.2.3.4"?
		name, addr, ok := parseARecord(s)
		if ok && isInNetwork(addr) {
			host = name
			ip = addr
			continue // Go to next line
		}

		// Looking at a complete TXT RR w/ Kea records?
		keaRecords, ok, err := isKeaTXTRecord(s, host)
		if err != nil {
			log.Fatalf("\nError at line %d: %v", line, err)
		}
		if !ok {
			continue // Not a TXT record
		}

		recordLen := len(keaRecords)

		// We have a valid Kea record, so let's format it
		if !emittedHeader {
			fmt.Fprintf(out, "// Generated by %s\n", os.Args[0])
			fmt.Fprintf(out, "// This file is auto-generated. Do not edit.\n")
			fmt.Fprintf(out, "//\n")
			fmt.Fprintf(out, "// Generated on %s\n", time.Now().Format(time.RFC1123))
			fmt.Fprintf(out, "// Input file: %s\n", inputFile)
			fmt.Fprintf(out, "//\n")
			fmt.Fprintf(out, "\n")
			emittedHeader = true
		}

		if needComma {
			fmt.Fprintf(out, ",\n")
		}
		needComma = true

		fmt.Fprintf(out, "{\n")
		fmt.Fprintf(out, "    \"hostname\": \"%s\",\n", host)
		fmt.Fprintf(out, "    \"ip-address\": \"%s\",\n", ip)
		count := 0
		for key, value := range keaRecords {
			count++
			isLast := count == recordLen
			needsQuote := !strings.HasPrefix(value, "[")
			fmt.Fprintf(out, "    \"%s\": ", key)
			if needsQuote {
				fmt.Fprint(out, "\"")
			}
			fmt.Fprintf(out, "%s", value)
			if needsQuote {
				fmt.Fprint(out, "\"")
			}

			if !isLast {
				fmt.Fprintf(out, ",")
			}
			fmt.Fprintf(out, "\n")
		}
		fmt.Fprintf(out, "}")

		// Reset for the next record
		host = ""
		ip = ""
	}
	fmt.Fprintf(out, "\n")

	return emittedHeader // Did we emit something?
}

func main() {

	log.SetFlags(0)
	outputFile := flag.String("o", "", "The output file (optional)")
	stop := flag.Bool("s", false, "Stop if no Kea records found in input")
	networkFilter := flag.String("n", "", "Limit output to specified network in CIDR format (e.g., 192.168.1.0/24)")
	help := flag.Bool("h", false, "Show help")

	flag.Parse()
	args := flag.Args()

	if len(args) < 1 || *help {
		fmt.Println("Usage: mkkea [-o <output file>] [-s] [-n <network_cidr>] <input file> [<input file> ... ]")
		fmt.Println("Extract and format the contents of a Kea 'reservations' stanza from a BIND Zone file.")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Parse network filter if provided
	if *networkFilter != "" {
		var err error
		_, filterNetwork, err = net.ParseCIDR(*networkFilter)
		if err != nil {
			log.Fatalf("Error parsing network CIDR: %v\n", err)
		}
	}

	// Generate output
	var outFile *os.File = os.Stdout
	var err error
	if *outputFile != "" {
		// Output to the specified file
		outFile, err = os.Create(*outputFile)
		if err != nil {
			log.Fatalf("Error creating output file: %v\n", err)
		}
		defer outFile.Close()
	}

	// Process all the inputs
	var foundKeaRecords bool = false
	for _, inputFile := range args {
		foundKeaRecords = foundKeaRecords || parseZone(inputFile, outFile)
	}
	if !foundKeaRecords {
		if *stop {
			log.Fatalf("No Kea records found in input files")
		} else {
			fmt.Println("No Kea records found in input files")
		}
	}
}
