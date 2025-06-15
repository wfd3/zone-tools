package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// DEBUG enables debug logging
const DEBUG = false

// EntryType represents the type of zone file entry
type EntryType int

const (
	EntryTypeRecord EntryType = iota
	EntryTypeGenerate
	EntryTypeTTL
	EntryTypeOrigin
	EntryTypeInclude
)

// ResourceRecord represents the base for all DNS resource records
type ResourceRecord struct {
	TTL   uint32
	Class string
}

// A record (IPv4 address)
type ARecord struct {
	ResourceRecord
	Address net.IP
	Inaddr  bool
}

// AAAA record (IPv6 address)
type AAAARecord struct {
	ResourceRecord
	Address net.IP
}

// CNAME record (canonical name)
type CNAMERecord struct {
	ResourceRecord
	Target string
}

// MX record (mail exchange)
type MXRecord struct {
	ResourceRecord
	Priority uint16
	Mail     string
}

// TXT record (text data)
type TXTRecord struct {
	ResourceRecord
	Text string
}

// NS record (name server)
type NSRecord struct {
	ResourceRecord
	NameServer string
}

// SOA record (start of authority)
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

// PTR record (pointer)
type PTRRecord struct {
	ResourceRecord
	Pointer string
}

// SRV record (service location)
type SRVRecord struct {
	ResourceRecord
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// CAA record (certification authority authorization)
type CAARecord struct {
	ResourceRecord
	Flags uint8
	Tag   string
	Value string
}

// HINFO record (host information)
type HINFORecord struct {
	ResourceRecord
	CPU string
	OS  string
}

// NAPTR record (naming authority pointer)
type NAPTRRecord struct {
	ResourceRecord
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement string
}

// SPF record (sender policy framework)
type SPFRecord struct {
	ResourceRecord
	Text string
}

// DNSRecords holds all DNS record types
type DNSRecords struct {
	A     []ARecord
	AAAA  []AAAARecord
	CNAME []CNAMERecord
	MX    []MXRecord
	TXT   []TXTRecord
	NS    []NSRecord
	SOA   []SOARecord
	PTR   []PTRRecord
	SRV   []SRVRecord
	CAA   []CAARecord
	HINFO []HINFORecord
	NAPTR []NAPTRRecord
	SPF   []SPFRecord
}

// HostRecord represents DNS records for a specific hostname
type HostRecord struct {
	Hostname string
	Records  DNSRecords
}

// GenerateDirective represents a $GENERATE directive
type GenerateDirective struct {
	Range     string // e.g., "0-254"
	OwnerName string // e.g., "dhcp-${0,5,d}"
	RRType    string // e.g., "A"
	RData     string // e.g., "10.254.0.$"
	TTL       uint32 // TTL at the time of directive
	Class     string // Class at the time of directive
	Origin    string // Origin at the time of directive
}

// TTLDirective represents a $TTL directive
type TTLDirective struct {
	Value uint32
}

// OriginDirective represents a $ORIGIN directive
type OriginDirective struct {
	Domain string
}

// IncludeDirective represents a $INCLUDE directive
type IncludeDirective struct {
	Filename string
}

// ZoneEntry represents any entry in a zone file
type ZoneEntry struct {
	Type EntryType

	// Entry data - only one of these will be populated based on Type
	HostRecord *HostRecord
	Generate   *GenerateDirective
	TTL        *TTLDirective
	Origin     *OriginDirective
	Include    *IncludeDirective

	// Raw line for debugging
	RawLine string
}

// ZoneData represents all entries in a zone file
type ZoneData []ZoneEntry

// ZoneMetadata holds zone-level information
type ZoneMetadata struct {
	Origin string
	TTL    uint32
}

// Parser holds the parsing state
type Parser struct {
	origin      string
	ttl         uint32
	file        string
	zone        ZoneData
	originFound bool // track if $ORIGIN has been found
	metadata    ZoneMetadata
	ttlWritten  bool // Keep track of whether we've already written $TTL to the zone
}

// Log prints debug messages if DEBUG is enabled
func Log(format string, args ...interface{}) {
	if DEBUG {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

// NewParser creates a new zone file parser
func NewParser(filename string) *Parser {
	return &Parser{
		file:       filename,
		zone:       make(ZoneData, 0),
		ttlWritten: false,
	}
}

// Parse parses the zone file and returns the organized zone entries
func (p *Parser) Parse() (ZoneData, ZoneMetadata, error) {
	err := p.parseFile(p.file)
	if err != nil {
		return nil, ZoneMetadata{}, err
	}

	// Update metadata with final values
	p.metadata.Origin = p.origin
	p.metadata.TTL = p.ttl

	return p.zone, p.metadata, nil
}

// parseFile handles parsing a file and supports $INCLUDE directives
func (p *Parser) parseFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", filename, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	var currentName string

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		origLine := line // Save for debug
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		Log("Processing line %d: %s", lineNum, line)

		// Handle multi-line records
		if containsUnquotedParenthesis(line) {
			line = p.handleMultiLine(scanner, line, &lineNum)
			Log("After multi-line handling: %s", line)
		}

		// Handle directives
		if strings.HasPrefix(line, "$") {
			err := p.handleDirective(line, filename, &currentName, origLine)
			if err != nil {
				return fmt.Errorf("line %d: %v", lineNum, err)
			}
			continue
		}

		// Parse regular record
		err := p.parseRecord(line, &currentName, origLine)
		if err != nil {
			return fmt.Errorf("line %d: %v", lineNum, err)
		}
	}

	// Check if $ORIGIN was found (only in the main file)
	if filename == p.file && !p.originFound {
		return fmt.Errorf("$ORIGIN directive not found in zone file")
	}

	return scanner.Err()
}

// handleMultiLine processes multi-line records enclosed in parentheses
func (p *Parser) handleMultiLine(scanner *bufio.Scanner, line string, lineNum *int) string {
	var continuedLine strings.Builder

	// Remove opening parenthesis and get content before it
	parts := strings.Split(line, "(")
	continuedLine.WriteString(parts[0])

	// Add content after opening parenthesis if any
	if len(parts) > 1 {
		content := strings.TrimLeft(parts[1], " ")
		// Remove comments from this content (but not if semicolon is inside quotes)
		content = removeCommentsRespectingQuotes(content)
		if strings.TrimSpace(content) != "" {
			trimmedContent := strings.TrimSpace(content)
			Log("First line content after '(': '%s'", trimmedContent)
			// If this is a quoted string, extract the content without quotes
			if strings.HasPrefix(trimmedContent, "\"") && strings.HasSuffix(trimmedContent, "\"") && strings.Count(trimmedContent, "\"") == 2 {
				unquotedContent := trimmedContent[1 : len(trimmedContent)-1]
				continuedLine.WriteString(" \"")
				continuedLine.WriteString(unquotedContent)
				Log("Initial quoted content: '%s'", unquotedContent)
			} else {
				continuedLine.WriteString(" ")
				continuedLine.WriteString(trimmedContent)
			}
		}
	}

	// Continue reading until closing parenthesis
	foundClosing := false
	for scanner.Scan() {
		*lineNum++
		nextLine := scanner.Text()

		// Remove comments from continuation line (but not if semicolon is inside quotes)
		nextLine = removeCommentsRespectingQuotes(nextLine)
		nextLine = strings.TrimSpace(nextLine)

		if strings.Contains(nextLine, ")") {
			foundClosing = true
			// Remove closing parenthesis
			parts := strings.Split(nextLine, ")")
			if strings.TrimSpace(parts[0]) != "" {
				continuedLine.WriteString(" ")
				continuedLine.WriteString(strings.TrimSpace(parts[0]))
			}
			break
		}

		if nextLine != "" {
			trimmedNext := strings.TrimSpace(nextLine)
			
			// If this is a standalone quoted string, remove quotes and concatenate content directly
			if strings.HasPrefix(trimmedNext, "\"") && strings.HasSuffix(trimmedNext, "\"") && strings.Count(trimmedNext, "\"") == 2 {
				// Extract content between quotes (preserving any internal spaces)
				unquotedContent := trimmedNext[1 : len(trimmedNext)-1]
				continuedLine.WriteString(unquotedContent)
				Log("Concatenating quoted string content: '%s'", unquotedContent)
			} else {
				// Normal space-separated concatenation
				continuedLine.WriteString(" ")
				continuedLine.WriteString(nextLine)
			}
		}
	}

	if foundClosing {
		result := continuedLine.String()
		// If we were concatenating quoted strings, add closing quote
		if strings.Contains(result, " \"") && !strings.HasSuffix(result, "\"") {
			result += "\""
		}
		return result
	}
	return line
}

// handleDirective processes different zone file directives
func (p *Parser) handleDirective(line, filename string, currentName *string, origLine string) error {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return fmt.Errorf("incomplete directive: %s", line)
	}

	Log("Handling directive: %s", line)

	switch parts[0] {
	case "$GENERATE":
		if len(parts) < 5 {
			return fmt.Errorf("invalid $GENERATE format")
		}

		// Parse $GENERATE directive
		rangePart := parts[1]
		lhs := parts[2]
		rrType := parts[3]

		// Everything after the RR type is the RHS template
		rhs := ""
		for i := 4; i < len(parts); i++ {
			if i > 4 {
				rhs += " "
			}
			// Remove quotes if present
			rhs += strings.Trim(parts[i], "\"")
		}

		// Store the $GENERATE directive as a top-level entry
		directive := GenerateDirective{
			Range:     rangePart,
			OwnerName: lhs,
			RRType:    rrType,
			RData:     rhs,
			TTL:       p.ttl,
			Class:     "IN",
			Origin:    p.origin,
		}

		entry := ZoneEntry{
			Type:     EntryTypeGenerate,
			Generate: &directive,
			RawLine:  origLine,
		}
		p.zone = append(p.zone, entry)
		return nil

	case "$INCLUDE":
		if len(parts) < 2 {
			return fmt.Errorf("$INCLUDE missing filename")
		}

		includeFile := parts[1]
		// Make relative paths relative to the including file
		if !strings.HasPrefix(includeFile, "/") {
			dir := filepath.Dir(filename)
			includeFile = filepath.Join(dir, includeFile)
		}

		// Create the $INCLUDE entry
		directive := IncludeDirective{
			Filename: includeFile,
		}
		entry := ZoneEntry{
			Type:    EntryTypeInclude,
			Include: &directive,
			RawLine: origLine,
		}
		p.zone = append(p.zone, entry)

		// Parse the included file
		err := p.parseFile(includeFile)
		if err != nil {
			return fmt.Errorf("failed to include file %s: %v", includeFile, err)
		}
		return nil

	case "$ORIGIN":
		if len(parts) < 2 {
			return fmt.Errorf("$ORIGIN missing domain")
		}

		p.origin = parts[1]
		if !strings.HasSuffix(p.origin, ".") {
			p.origin += "."
		}
		p.originFound = true

		// Store the $ORIGIN directive
		directive := OriginDirective{
			Domain: p.origin,
		}
		entry := ZoneEntry{
			Type:    EntryTypeOrigin,
			Origin:  &directive,
			RawLine: origLine,
		}
		p.zone = append(p.zone, entry)
		return nil

	case "$TTL":
		if len(parts) < 2 {
			return fmt.Errorf("$TTL missing value")
		}

		ttl, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid TTL value: %v", err)
		}
		p.ttl = uint32(ttl)

		// Store the $TTL directive
		directive := TTLDirective{
			Value: uint32(ttl),
		}
		entry := ZoneEntry{
			Type:    EntryTypeTTL,
			TTL:     &directive,
			RawLine: origLine,
		}
		p.zone = append(p.zone, entry)
		p.ttlWritten = true
		return nil

	default:
		return fmt.Errorf("unknown directive: %s", parts[0])
	}
}

// parseRecord parses a single DNS record
func (p *Parser) parseRecord(line string, currentName *string, origLine string) error {
	// Pre-process the line to extract comments (respecting quotes)
	var cleanLine string
	comment := ""

	// Find comment start (semicolon outside quotes)
	commentIndex := findCommentStart(line)
	if commentIndex >= 0 {
		comment = line[commentIndex:]
		cleanLine = line[:commentIndex]
	} else {
		cleanLine = line
	}

	Log("Parsing record: %s", cleanLine)

	// Handle special case for quoted TXT records
	var tokens []string
	if strings.Contains(cleanLine, "\"") {
		// Use a more sophisticated tokenizing approach for lines with quotes
		tokens = tokenizeWithQuotes(cleanLine)
		Log("Tokenized with quotes: %v", tokens)
	} else {
		// Simple tokenization for lines without quotes
		tokens = strings.Fields(cleanLine)
		Log("Tokenized: %v", tokens)
	}

	if len(tokens) < 3 {
		return fmt.Errorf("invalid record format: %s", cleanLine)
	}

	var name, class, rrType string
	var ttl uint32 = p.ttl
	var data []string

	// Parse record components
	tokenIndex := 0

	// Parse owner name (if present)
	// Look ahead to determine if first token is actually a hostname
	if len(tokens) >= 3 && isKnownRRType(tokens[2]) {
		// Pattern: name [ttl] [class] type data...
		// If tokens[2] is a known RR type, then tokens[0] must be a hostname
		name = tokens[tokenIndex]
		tokenIndex++
	} else if len(tokens) >= 4 && tokens[1] == "IN" && isKnownRRType(tokens[2]) {
		// Pattern: name class type data...
		name = tokens[tokenIndex]
		tokenIndex++
	} else if len(tokens) >= 4 && isNumeric(tokens[1]) && isKnownRRType(tokens[3]) {
		// Pattern: name ttl class type data...
		name = tokens[tokenIndex]
		tokenIndex++
	} else if !isNumeric(tokens[tokenIndex]) && tokens[tokenIndex] != "IN" && !isKnownRRType(tokens[tokenIndex]) {
		// Original logic as fallback
		name = tokens[tokenIndex]
		tokenIndex++
	} else {
		name = *currentName
	}

	Log("Owner name: %s", name)

	// Update current name if necessary
	if name != "" {
		*currentName = name
	}

	// Parse TTL (if present)
	if tokenIndex < len(tokens) && isNumeric(tokens[tokenIndex]) {
		if t, err := strconv.ParseUint(tokens[tokenIndex], 10, 32); err == nil {
			ttl = uint32(t)
			tokenIndex++
		}
	}

	// Parse class (defaults to IN)
	class = "IN"
	if tokenIndex < len(tokens) && strings.ToUpper(tokens[tokenIndex]) == "IN" {
		class = tokens[tokenIndex]
		tokenIndex++
	}

	// Parse RR type
	if tokenIndex >= len(tokens) {
		return fmt.Errorf("missing RR type")
	}
	rrType = strings.ToUpper(tokens[tokenIndex])
	tokenIndex++

	Log("Record type: %s", rrType)

	// Parse data fields
	data = tokens[tokenIndex:]
	Log("Data fields: %v", data)

	// Fully qualify the name if needed
	fullName := p.qualifyDomainName(name)
	Log("Fully qualified name: %s", fullName)

	// Special handling for root domain
	if fullName == p.origin {
		Log("This is the root domain (@)")
	}

	// Find or create host record entry
	var hostRecord *HostRecord
	for i := len(p.zone) - 1; i >= 0; i-- {
		if p.zone[i].Type == EntryTypeRecord && p.zone[i].HostRecord.Hostname == fullName {
			hostRecord = p.zone[i].HostRecord
			Log("Found existing host record for %s", fullName)
			break
		}
	}

	if hostRecord == nil {
		Log("Creating new host record for %s", fullName)
		hostRecord = &HostRecord{
			Hostname: fullName,
			Records:  DNSRecords{},
		}
		entry := ZoneEntry{
			Type:       EntryTypeRecord,
			HostRecord: hostRecord,
			RawLine:    origLine,
		}
		p.zone = append(p.zone, entry)
	}

	// Create base resource record
	rr := ResourceRecord{
		TTL:   ttl,
		Class: class,
	}

	// Parse specific record types
	return p.parseSpecificRecord(rrType, data, comment, &hostRecord.Records, rr)
}

// tokenizeWithQuotes tokenizes a string while respecting quoted sections
func tokenizeWithQuotes(s string) []string {
	var result []string
	var currentToken strings.Builder
	inQuotes := false

	// Convert multiple spaces/tabs to a single space for easier processing
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")

	for i := 0; i < len(s); i++ {
		char := s[i]

		if char == '"' {
			// Toggle quote state and add the quote character
			inQuotes = !inQuotes
			currentToken.WriteByte(char)
		} else if char == ' ' && !inQuotes {
			// End of token (when not in quotes)
			if currentToken.Len() > 0 {
				result = append(result, currentToken.String())
				currentToken.Reset()
			}
		} else {
			// Add character to current token
			currentToken.WriteByte(char)
		}
	}

	// Add the last token if exists
	if currentToken.Len() > 0 {
		result = append(result, currentToken.String())
	}

	return result
}

// parseSpecificRecord handles parsing of individual record types
func (p *Parser) parseSpecificRecord(rrType string, data []string, comment string, records *DNSRecords, rr ResourceRecord) error {
	Log("Parsing specific record type: %s", rrType)

	switch rrType {
	case "A":
		if len(data) < 1 {
			return fmt.Errorf("A record missing address")
		}

		ip := net.ParseIP(data[0])
		if ip == nil {
			return fmt.Errorf("invalid A record address: %s", data[0])
		}
		if ip.To4() == nil {
			return fmt.Errorf("A record must be IPv4 address: %s", data[0])
		}

		// Check if comment contains inaddr flag
		inaddr := false
		if comment != "" {
			commentText := strings.TrimSpace(comment[1:])
			if commentText == "inaddr" || commentText == "in-addr" {
				inaddr = true
			}
		}

		records.A = append(records.A, ARecord{
			ResourceRecord: rr,
			Address:        ip,
			Inaddr:         inaddr,
		})

	case "AAAA":
		if len(data) < 1 {
			return fmt.Errorf("AAAA record missing address")
		}

		ip := net.ParseIP(data[0])
		if ip == nil {
			return fmt.Errorf("invalid AAAA record address: %s", data[0])
		}
		if ip.To4() != nil {
			return fmt.Errorf("AAAA record must be IPv6 address: %s", data[0])
		}

		records.AAAA = append(records.AAAA, AAAARecord{
			ResourceRecord: rr,
			Address:        ip,
		})

	case "CNAME":
		if len(data) < 1 {
			return fmt.Errorf("CNAME record missing target")
		}
		target := p.qualifyDomainName(data[0])
		records.CNAME = append(records.CNAME, CNAMERecord{
			ResourceRecord: rr,
			Target:         target,
		})

	case "MX":
		if len(data) < 2 {
			// If we have a single token that contains both priority and mail server
			if len(data) == 1 && strings.Contains(data[0], " ") {
				// Split on space
				parts := strings.Fields(data[0])
				if len(parts) >= 2 {
					data = parts
				} else {
					return fmt.Errorf("MX record requires priority and mail server")
				}
			} else {
				return fmt.Errorf("MX record requires priority and mail server")
			}
		}

		priority, err := strconv.ParseUint(data[0], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid MX priority: %v", err)
		}
		mail := p.qualifyDomainName(data[1])
		records.MX = append(records.MX, MXRecord{
			ResourceRecord: rr,
			Priority:       uint16(priority),
			Mail:           mail,
		})

	case "TXT":
		if len(data) < 1 {
			return fmt.Errorf("TXT record missing text")
		}

		// Process TXT record data
		text := extractTXTContent(data)
		Log("TXT record content: %s", text)

		records.TXT = append(records.TXT, TXTRecord{
			ResourceRecord: rr,
			Text:           text,
		})

	case "NS":
		if len(data) < 1 {
			return fmt.Errorf("NS record missing name server")
		}
		ns := p.qualifyDomainName(data[0])
		records.NS = append(records.NS, NSRecord{
			ResourceRecord: rr,
			NameServer:     ns,
		})

	case "SOA":
		if len(data) < 7 {
			return fmt.Errorf("SOA record requires 7 fields")
		}

		serial, _ := strconv.ParseUint(data[2], 10, 32)
		refresh, _ := strconv.ParseUint(data[3], 10, 32)
		retry, _ := strconv.ParseUint(data[4], 10, 32)
		expire, _ := strconv.ParseUint(data[5], 10, 32)
		minTTL, _ := strconv.ParseUint(data[6], 10, 32)

		records.SOA = append(records.SOA, SOARecord{
			ResourceRecord: rr,
			PrimaryNS:      p.qualifyDomainName(data[0]),
			Email:          p.qualifyDomainName(data[1]),
			Serial:         uint32(serial),
			Refresh:        uint32(refresh),
			Retry:          uint32(retry),
			Expire:         uint32(expire),
			MinimumTTL:     uint32(minTTL),
		})

	case "PTR":
		if len(data) < 1 {
			return fmt.Errorf("PTR record missing pointer")
		}
		ptr := p.qualifyDomainName(data[0])
		records.PTR = append(records.PTR, PTRRecord{
			ResourceRecord: rr,
			Pointer:        ptr,
		})

	case "SRV":
		if len(data) < 4 {
			return fmt.Errorf("SRV record requires 4 fields")
		}
		priority, _ := strconv.ParseUint(data[0], 10, 16)
		weight, _ := strconv.ParseUint(data[1], 10, 16)
		port, _ := strconv.ParseUint(data[2], 10, 16)
		target := p.qualifyDomainName(data[3])

		records.SRV = append(records.SRV, SRVRecord{
			ResourceRecord: rr,
			Priority:       uint16(priority),
			Weight:         uint16(weight),
			Port:           uint16(port),
			Target:         target,
		})

	case "CAA":
		if len(data) < 3 {
			return fmt.Errorf("CAA record requires 3 fields")
		}
		flags, _ := strconv.ParseUint(data[0], 10, 8)
		tag := strings.Trim(data[1], "\"")
		value := strings.Trim(data[2], "\"")

		records.CAA = append(records.CAA, CAARecord{
			ResourceRecord: rr,
			Flags:          uint8(flags),
			Tag:            tag,
			Value:          value,
		})

	case "HINFO":
		if len(data) < 2 {
			return fmt.Errorf("HINFO record requires 2 fields")
		}
		cpu := strings.Trim(data[0], "\"")
		os := strings.Trim(data[1], "\"")

		records.HINFO = append(records.HINFO, HINFORecord{
			ResourceRecord: rr,
			CPU:            cpu,
			OS:             os,
		})

	case "NAPTR":
		if len(data) < 6 {
			return fmt.Errorf("NAPTR record requires 6 fields")
		}
		order, _ := strconv.ParseUint(data[0], 10, 16)
		preference, _ := strconv.ParseUint(data[1], 10, 16)
		flags := strings.Trim(data[2], "\"")
		service := strings.Trim(data[3], "\"")
		regexp := strings.Trim(data[4], "\"")
		replacement := p.qualifyDomainName(data[5])

		records.NAPTR = append(records.NAPTR, NAPTRRecord{
			ResourceRecord: rr,
			Order:          uint16(order),
			Preference:     uint16(preference),
			Flags:          flags,
			Service:        service,
			Regexp:         regexp,
			Replacement:    replacement,
		})

	case "SPF":
		if len(data) < 1 {
			return fmt.Errorf("SPF record missing text")
		}
		text := extractTXTContent(data)
		records.SPF = append(records.SPF, SPFRecord{
			ResourceRecord: rr,
			Text:           text,
		})

	default:
		return fmt.Errorf("unsupported RR type: %s", rrType)
	}

	return nil
}

// extractTXTContent processes TXT record data to handle quotes correctly
func extractTXTContent(data []string) string {
	// Join all data parts
	content := strings.Join(data, " ")

	// Handle quoted data: if the content is wrapped in quotes, remove the outer quotes
	if strings.HasPrefix(content, "\"") && strings.HasSuffix(content, "\"") {
		content = content[1 : len(content)-1]
	}

	return content
}

// qualifyDomainName adds the origin if the domain name is not fully qualified
func (p *Parser) qualifyDomainName(name string) string {
	if name == "@" {
		return p.origin
	}
	// Don't try to qualify dotted domains with origin - they're already absolute
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "." + p.origin
}

// isNumeric checks if a string represents a number
func isNumeric(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

// knownRRTypes is a set of supported DNS record types
var knownRRTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true,
	"TXT": true, "NS": true, "SOA": true, "PTR": true,
	"SRV": true, "CAA": true, "HINFO": true, "NAPTR": true,
	"SPF": true,
}

// isKnownRRType checks if a string is a known DNS record type
func isKnownRRType(s string) bool {
	return knownRRTypes[strings.ToUpper(s)]
}

// containsUnquotedParenthesis checks if a line contains an opening parenthesis outside of quotes
func containsUnquotedParenthesis(line string) bool {
	inQuotes := false
	for i := 0; i < len(line); i++ {
		char := line[i]
		if char == '"' {
			inQuotes = !inQuotes
		} else if char == '(' && !inQuotes {
			return true
		}
	}
	return false
}

// removeCommentsRespectingQuotes removes comments (semicolon to end of line) but only if semicolon is outside quotes
func removeCommentsRespectingQuotes(line string) string {
	commentIndex := findCommentStart(line)
	if commentIndex >= 0 {
		return line[:commentIndex]
	}
	return line
}

// findCommentStart finds the index of the first semicolon outside quotes, or -1 if none found
func findCommentStart(line string) int {
	inQuotes := false
	for i := 0; i < len(line); i++ {
		char := line[i]
		if char == '"' {
			inQuotes = !inQuotes
		} else if char == ';' && !inQuotes {
			return i
		}
	}
	return -1
}

// replacePlaceholders replaces $GENERATE placeholders with the iterator value
func replacePlaceholders(s string, iter int) string {
	result := s

	// First handle complex format ${offset,width,format}
	for strings.Contains(result, "${") {
		start := strings.Index(result, "${")
		end := strings.Index(result[start:], "}") + start
		if end <= start {
			break // Malformed placeholder
		}

		placeholder := result[start : end+1]
		specs := result[start+2 : end]
		parts := strings.Split(specs, ",")

		offset := 0
		width := 0
		format := "d"

		if len(parts) > 0 {
			offset, _ = strconv.Atoi(parts[0])
		}
		if len(parts) > 1 {
			width, _ = strconv.Atoi(parts[1])
		}
		if len(parts) > 2 {
			format = parts[2]
		}

		value := iter + offset
		replacement := ""

		switch format {
		case "d":
			if width > 0 {
				replacement = fmt.Sprintf("%0*d", width, value)
			} else {
				replacement = strconv.Itoa(value)
			}
		case "x":
			if width > 0 {
				replacement = fmt.Sprintf("%0*x", width, value)
			} else {
				replacement = fmt.Sprintf("%x", value)
			}
		}

		result = strings.Replace(result, placeholder, replacement, 1)
	}

	// Then handle simple $ placeholders
	result = strings.ReplaceAll(result, "$", strconv.Itoa(iter))

	return result
}

// formatHostname formats a hostname for zone file output
func formatHostname(hostname, origin string) string {
	if hostname == origin {
		return "@"
	}

	// Remove the origin from the hostname
	suffix := "." + origin
	if strings.HasSuffix(hostname, suffix) {
		return hostname[:len(hostname)-len(suffix)]
	}

	return hostname
}

// hasAnyRecords checks if a DNSRecords struct contains any records
func hasAnyRecords(records *DNSRecords) bool {
	return len(records.A) > 0 || len(records.AAAA) > 0 || len(records.CNAME) > 0 ||
		len(records.MX) > 0 || len(records.TXT) > 0 || len(records.NS) > 0 ||
		len(records.SOA) > 0 || len(records.PTR) > 0 || len(records.SRV) > 0 ||
		len(records.CAA) > 0 || len(records.HINFO) > 0 || len(records.NAPTR) > 0 ||
		len(records.SPF) > 0
}

// Example usage:
func main() {
	parser := NewParser("example.zone")
	zone, metadata, err := parser.Parse()
	if err != nil {
		fmt.Printf("Error parsing zone file: %v\n", err)
		return
	}

	// Print a summary of what we parsed
	fmt.Printf("Parsed zone file with %d entries\n", len(zone))
	for i, entry := range zone {
		switch entry.Type {
		case EntryTypeRecord:
			fmt.Printf("Entry %d: Record for %s\n", i, entry.HostRecord.Hostname)
		case EntryTypeGenerate:
			fmt.Printf("Entry %d: $GENERATE %s\n", i, entry.Generate.Range)
		case EntryTypeTTL:
			fmt.Printf("Entry %d: $TTL %d\n", i, entry.TTL.Value)
		case EntryTypeOrigin:
			fmt.Printf("Entry %d: $ORIGIN %s\n", i, entry.Origin.Domain)
		case EntryTypeInclude:
			fmt.Printf("Entry %d: $INCLUDE %s\n", i, entry.Include.Filename)
		}
	}

	// Only print metadata headers once from metadata, not from zone entries
	fmt.Printf("\n$ORIGIN %s\n", metadata.Origin)
	fmt.Printf("$TTL %d\n\n", metadata.TTL)

	// Process each entry in the order they appeared in the file
	for _, entry := range zone {
		switch entry.Type {
		case EntryTypeRecord:
			printHostRecords(entry.HostRecord, metadata.Origin)

		case EntryTypeTTL:
			// Don't print TTL directive as it was already printed from metadata
			continue

		case EntryTypeOrigin:
			// Only print ORIGIN directive if it's different from the original
			if entry.Origin.Domain != metadata.Origin {
				fmt.Printf("$ORIGIN %s\n", entry.Origin.Domain)
			}

		case EntryTypeInclude:
			fmt.Printf("$INCLUDE %s\n", entry.Include.Filename)

		case EntryTypeGenerate:
			gen := entry.Generate
			fmt.Printf("$GENERATE %s %s %s %s \"%s\"\n",
				gen.Range, gen.OwnerName, gen.Class, gen.RRType, gen.RData)
		}
	}
}

// printHostRecords formats and prints all DNS records for a hostname
func printHostRecords(host *HostRecord, origin string) {
	if host == nil {
		return
	}

	// Format hostname for output
	ownerName := formatHostname(host.Hostname, origin)
	records := &host.Records

	Log("Printing records for %s (formatted as %s)", host.Hostname, ownerName)

	// Print records in the specified order
	// SOA
	for _, soa := range records.SOA {
		fmt.Printf("%s\t%s\tSOA\t%s %s (\n", ownerName, soa.Class, soa.PrimaryNS, soa.Email)
		fmt.Printf("\t\t\t\t\t%d\t; Serial\n", soa.Serial)
		fmt.Printf("\t\t\t\t\t%d\t; Refresh\n", soa.Refresh)
		fmt.Printf("\t\t\t\t\t%d\t; Retry\n", soa.Retry)
		fmt.Printf("\t\t\t\t\t%d\t; Expire\n", soa.Expire)
		fmt.Printf("\t\t\t\t\t%d )\t; Minimum TTL\n", soa.MinimumTTL)
	}

	// NS
	for _, ns := range records.NS {
		fmt.Printf("%s\t%s\tNS\t%s\n", ownerName, ns.Class, ns.NameServer)
	}

	// A
	for _, a := range records.A {
		comment := ""
		if a.Inaddr {
			comment = "\t; inaddr"
		}
		fmt.Printf("%s\t%s\tA\t%s%s\n", ownerName, a.Class, a.Address.String(), comment)
	}

	// AAAA
	for _, aaaa := range records.AAAA {
		fmt.Printf("%s\t%s\tAAAA\t%s\n", ownerName, aaaa.Class, aaaa.Address.String())
	}

	// CNAME
	for _, cname := range records.CNAME {
		fmt.Printf("%s\t%s\tCNAME\t%s\n", ownerName, cname.Class, cname.Target)
	}

	// MX
	for _, mx := range records.MX {
		fmt.Printf("%s\t%s\tMX\t%d %s\n", ownerName, mx.Class, mx.Priority, mx.Mail)
	}

	// TXT
	for _, txt := range records.TXT {
		fmt.Printf("%s\t%s\tTXT\t\"%s\"\n", ownerName, txt.Class, txt.Text)
	}

	// PTR
	for _, ptr := range records.PTR {
		fmt.Printf("%s\t%s\tPTR\t%s\n", ownerName, ptr.Class, ptr.Pointer)
	}

	// SRV
	for _, srv := range records.SRV {
		fmt.Printf("%s\t%s\tSRV\t%d %d %d %s\n", ownerName, srv.Class, srv.Priority, srv.Weight, srv.Port, srv.Target)
	}

	// CAA
	for _, caa := range records.CAA {
		fmt.Printf("%s\t%s\tCAA\t%d %s \"%s\"\n", ownerName, caa.Class, caa.Flags, caa.Tag, caa.Value)
	}

	// HINFO
	for _, hinfo := range records.HINFO {
		fmt.Printf("%s\t%s\tHINFO\t\"%s\" \"%s\"\n", ownerName, hinfo.Class, hinfo.CPU, hinfo.OS)
	}

	// NAPTR
	for _, naptr := range records.NAPTR {
		fmt.Printf("%s\t%s\tNAPTR\t%d %d \"%s\" \"%s\" \"%s\" %s\n",
			ownerName, naptr.Class, naptr.Order, naptr.Preference, naptr.Flags, naptr.Service, naptr.Regexp, naptr.Replacement)
	}

	// SPF
	for _, spf := range records.SPF {
		fmt.Printf("%s\t%s\tSPF\t\"%s\"\n", ownerName, spf.Class, spf.Text)
	}

	// Add a blank line between hosts if there were any records
	if hasAnyRecords(records) {
		fmt.Println()
	}
}
