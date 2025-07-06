// Package zoneparser provides DNS zone file parsing functionality.
// It supports parsing standard DNS zone files with various record types including
// A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA, HINFO, NAPTR, and SPF records.
// The parser also handles zone file directives like $ORIGIN, $TTL, $GENERATE, and $INCLUDE.
package zoneparser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NewParser creates a new zone file parser
func NewParser(filename string) *Parser {
	return &Parser{
		file:     filename,
		ttl:      86400, // Default TTL
		origin:   "",
		zone:     make(ZoneData, 0),
		metadata: ZoneMetadata{TTL: 86400},
	}
}

// Parse parses the zone file and returns the parsed data
func (p *Parser) Parse() (ZoneData, ZoneMetadata, error) {
	err := p.parseFile(p.file)
	if err != nil {
		return nil, ZoneMetadata{}, err
	}

	// Set final metadata
	p.metadata.Origin = p.origin
	p.metadata.TTL = p.ttl

	return p.zone, p.metadata, nil
}

// parseFile parses a zone file
func (p *Parser) parseFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("error opening file %s: %v", filename, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	var currentName *string

	Log("Starting to parse file: %s", filename)

	for scanner.Scan() {
		lineNum++
		origLine := scanner.Text()
		line := strings.TrimSpace(origLine)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Handle multi-line records (parentheses)
		if containsUnquotedParenthesis(line) {
			line = p.handleMultiLine(scanner, line, &lineNum)
		}

		Log("Processing line %d: %s", lineNum, line)

		// Handle directives
		if strings.HasPrefix(line, "$") {
			err := p.handleDirective(line, filename, currentName, origLine)
			if err != nil {
				return fmt.Errorf("error on line %d: %v", lineNum, err)
			}
			continue
		}

		// Parse regular DNS records
		err := p.parseRecord(line, &currentName, origLine, filename)
		if err != nil {
			return fmt.Errorf("error parsing record on line %d: %v", lineNum, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	Log("Finished parsing file: %s", filename)
	return nil
}

// handleMultiLine processes multi-line records (records with parentheses)
func (p *Parser) handleMultiLine(scanner *bufio.Scanner, line string, lineNum *int) string {
	Log("Handling multi-line record starting at line %d", *lineNum)

	var fullLine strings.Builder
	fullLine.WriteString(line)

	// Keep reading lines until we find the closing parenthesis
	openParens := strings.Count(line, "(")
	closeParens := strings.Count(line, ")")

	for openParens > closeParens && scanner.Scan() {
		*lineNum++
		nextLine := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines within multi-line record
		if nextLine == "" || strings.HasPrefix(nextLine, ";") {
			continue
		}

		Log("Adding line %d to multi-line record: %s", *lineNum, nextLine)

		// Remove comments from this line before adding to multi-line record
		cleanNextLine, _ := parseLineWithComments(nextLine)
		nextLine = cleanNextLine

		// For multi-line TXT records, check if we're concatenating quoted strings
		lastChar := strings.TrimSpace(fullLine.String())
		if len(lastChar) > 0 && lastChar[len(lastChar)-1] == '"' && strings.HasPrefix(nextLine, "\"") {
			// Adjacent quoted strings should be concatenated without space
			fullLine.WriteString(nextLine)
		} else {
			// Add a space before the next line
			fullLine.WriteString(" ")
			fullLine.WriteString(nextLine)
		}

		openParens += strings.Count(nextLine, "(")
		closeParens += strings.Count(nextLine, ")")
	}

	result := fullLine.String()
	Log("Multi-line record result: %s", result)
	return result
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
		if len(parts) < 6 {
			return fmt.Errorf("invalid $GENERATE format")
		}

		// Parse $GENERATE directive
		// Format: $GENERATE range lhs [class] rrtype rhs
		rangePart := parts[1]
		lhs := parts[2]
		class := parts[3]  // Usually "IN"
		rrType := parts[4]

		// Everything after the RR type is the RHS template
		rhs := ""
		for i := 5; i < len(parts); i++ {
			if i > 5 {
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
			Class:     class,
			Origin:    p.origin,
		}

		entry := ZoneEntry{
			Type:       EntryTypeGenerate,
			Generate:   &directive,
			RawLine:    origLine,
			SourceFile: filename,
		}

		p.zone = append(p.zone, entry)

	case "$TTL":
		ttl, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid TTL value: %v", err)
		}
		p.ttl = uint32(ttl)

		// Add TTL directive to zone data for completeness
		directive := TTLDirective{Value: p.ttl}
		entry := ZoneEntry{
			Type:       EntryTypeTTL,
			TTL:        &directive,
			RawLine:    origLine,
			SourceFile: filename,
		}
		p.zone = append(p.zone, entry)

	case "$ORIGIN":
		p.origin = parts[1]
		if !strings.HasSuffix(p.origin, ".") {
			p.origin += "."
		}
		p.originFound = true

		// Add ORIGIN directive to zone data for completeness
		directive := OriginDirective{Domain: p.origin}
		entry := ZoneEntry{
			Type:       EntryTypeOrigin,
			Origin:     &directive,
			RawLine:    origLine,
			SourceFile: filename,
		}
		p.zone = append(p.zone, entry)

	case "$INCLUDE":
		includeFile := parts[1]

		// Resolve the include file path relative to the current file
		if !filepath.IsAbs(includeFile) {
			currentDir := filepath.Dir(filename)
			includeFile = filepath.Join(currentDir, includeFile)
		}

		Log("Including file: %s", includeFile)

		// Parse the included file
		err := p.parseFile(includeFile)
		if err != nil {
			return fmt.Errorf("error parsing included file %s: %v", includeFile, err)
		}

	default:
		return fmt.Errorf("unknown directive: %s", parts[0])
	}

	return nil
}

// parseRecord parses a single DNS record line
func (p *Parser) parseRecord(line string, currentName **string, origLine string, sourceFile string) error {
	// Remove comments while preserving semicolons in quotes
	cleanLine, comment := parseLineWithComments(line)
	if cleanLine == "" {
		return nil
	}

	parts := tokenize(cleanLine)
	if len(parts) < MinRecordTokens {
		return fmt.Errorf("incomplete record: %s", line)
	}

	Log("Parsing record with parts: %v", parts)

	// Parse the record components
	var hostname, ttlStr, class, rrType string
	var data []string

	// Determine the hostname
	// Check if line starts with whitespace (indicating blank hostname)
	startsWithWhitespace := len(origLine) > 0 && (origLine[0] == ' ' || origLine[0] == '\t')
	
	if parts[0] == "" || strings.HasPrefix(parts[0], ";") || (startsWithWhitespace && (parts[0] == ClassIN || isKnownRRType(parts[0]))) {
		// Use previous hostname
		if *currentName == nil {
			return fmt.Errorf("no previous hostname for record: %s", line)
		}
		hostname = **currentName
		// Don't remove parts[0] if it's a class or record type
		if parts[0] == "" {
			parts = parts[1:] // Remove empty hostname field
		}
	} else {
		hostname = parts[0]
		if *currentName == nil {
			*currentName = new(string)
		}
		**currentName = hostname
		parts = parts[1:]
	}

	// Parse pattern: hostname [ttl] [class] type data...
	// Need to identify which is which based on known patterns
	parseIndex := 0

	// Check for optional TTL (numeric)
	if parseIndex < len(parts) && isNumeric(parts[parseIndex]) {
		ttlStr = parts[parseIndex]
		parseIndex++
	}

	// Check for optional class (typically "IN")
	if parseIndex < len(parts) && (parts[parseIndex] == ClassIN || (!isKnownRRType(parts[parseIndex]) && parseIndex+1 < len(parts) && isKnownRRType(parts[parseIndex+1]))) {
		class = parts[parseIndex]
		parseIndex++
	} else {
		class = ClassIN // Default class
	}

	// Next should be the record type
	if parseIndex >= len(parts) || !isKnownRRType(parts[parseIndex]) {
		return fmt.Errorf("invalid or missing record type in: %s", line)
	}
	rrType = parts[parseIndex]
	parseIndex++

	// Rest is data
	data = parts[parseIndex:]

	// Parse TTL if provided, otherwise use current default
	var recordTTL uint32
	if ttlStr != "" {
		ttl, err := strconv.ParseUint(ttlStr, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid TTL: %v", err)
		}
		recordTTL = uint32(ttl)
	} else {
		recordTTL = p.ttl
	}

	// Qualify the hostname
	qualifiedHostname := qualifyDomainName(hostname, p.origin)

	Log("Parsed record: hostname=%s, ttl=%d, class=%s, type=%s, data=%v",
		qualifiedHostname, recordTTL, class, rrType, data)

	// Find existing HostRecord or create a new one
	var hostRecord *HostRecord
	for i := range p.zone {
		if p.zone[i].Type == EntryTypeRecord && p.zone[i].HostRecord.Hostname == qualifiedHostname {
			hostRecord = p.zone[i].HostRecord
			break
		}
	}

	if hostRecord == nil {
		hostRecord = &HostRecord{
			Hostname: qualifiedHostname,
			Records:  DNSRecords{},
		}

		// Add new host record to zone
		entry := ZoneEntry{
			Type:       EntryTypeRecord,
			HostRecord: hostRecord,
			RawLine:    origLine,
			SourceFile: sourceFile,
		}
		p.zone = append(p.zone, entry)
	}

	// Create base resource record
	rr := ResourceRecord{
		TTL:   recordTTL,
		Class: class,
	}

	// Parse the specific record type
	return p.parseSpecificRecord(rrType, data, comment, &hostRecord.Records, rr)
}