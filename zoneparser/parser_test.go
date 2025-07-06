package zoneparser

import (
	"os"
	"strings"
	"testing"
)

func TestNewParser(t *testing.T) {
	parser := NewParser("test.zone")
	
	if parser.file != "test.zone" {
		t.Errorf("Expected file test.zone, got %s", parser.file)
	}
	if parser.ttl != 86400 {
		t.Errorf("Expected default TTL 86400, got %d", parser.ttl)
	}
	if parser.origin != "" {
		t.Errorf("Expected empty origin, got %s", parser.origin)
	}
	if parser.metadata.TTL != 86400 {
		t.Errorf("Expected metadata TTL 86400, got %d", parser.metadata.TTL)
	}
}

func TestParseSimpleZone(t *testing.T) {
	// Create a simple test zone file
	content := `$TTL 3600
$ORIGIN example.com.
@	IN	SOA	ns1.example.com. admin.example.com. (
			2023010101	; Serial
			3600		; Refresh
			1800		; Retry
			604800		; Expire
			86400 )		; Minimum TTL

@	IN	NS	ns1.example.com.
@	IN	A	192.168.1.1
www	IN	A	192.168.1.2
mail	IN	MX	10 mail.example.com.
`

	// Write to temporary file
	tmpFile, err := os.CreateTemp("", "test-zone-*.zone")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Parse the zone
	parser := NewParser(tmpFile.Name())
	zone, metadata, err := parser.Parse()
	if err != nil {
		t.Fatalf("Failed to parse zone: %v", err)
	}

	// Check metadata
	if metadata.Origin != "example.com." {
		t.Errorf("Expected origin example.com., got %s", metadata.Origin)
	}
	if metadata.TTL != 3600 {
		t.Errorf("Expected TTL 3600, got %d", metadata.TTL)
	}

	// Check that we have the expected entries
	if len(zone) == 0 {
		t.Fatal("Expected zone entries, got none")
	}

	// Count different entry types
	var ttlEntries, originEntries, recordEntries int
	for _, entry := range zone {
		switch entry.Type {
		case EntryTypeTTL:
			ttlEntries++
		case EntryTypeOrigin:
			originEntries++
		case EntryTypeRecord:
			recordEntries++
		}
	}

	if ttlEntries != 1 {
		t.Errorf("Expected 1 TTL entry, got %d", ttlEntries)
	}
	if originEntries != 1 {
		t.Errorf("Expected 1 ORIGIN entry, got %d", originEntries)
	}
	if recordEntries < 3 {
		t.Errorf("Expected at least 3 record entries, got %d", recordEntries)
	}
}

func TestParseDirectives(t *testing.T) {
	content := `$TTL 7200
$ORIGIN test.com.
$GENERATE 1-3 host$ IN A 192.168.1.$
`

	tmpFile, err := os.CreateTemp("", "test-directives-*.zone")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	parser := NewParser(tmpFile.Name())
	zone, metadata, err := parser.Parse()
	if err != nil {
		t.Fatalf("Failed to parse zone: %v", err)
	}

	if metadata.TTL != 7200 {
		t.Errorf("Expected TTL 7200, got %d", metadata.TTL)
	}
	if metadata.Origin != "test.com." {
		t.Errorf("Expected origin test.com., got %s", metadata.Origin)
	}

	// Check for GENERATE directive
	var foundGenerate bool
	for _, entry := range zone {
		if entry.Type == EntryTypeGenerate {
			foundGenerate = true
			if entry.Generate.Range != "1-3" {
				t.Errorf("Expected GENERATE range 1-3, got %s", entry.Generate.Range)
			}
			if entry.Generate.OwnerName != "host$" {
				t.Errorf("Expected GENERATE owner host$, got %s", entry.Generate.OwnerName)
			}
			break
		}
	}
	if !foundGenerate {
		t.Error("Expected to find GENERATE directive")
	}
}

func TestParseMultilineRecord(t *testing.T) {
	content := `$TTL 3600
$ORIGIN example.com.
test	IN	TXT	( "first part "
		  "second part"
		  "third part" )
`

	tmpFile, err := os.CreateTemp("", "test-multiline-*.zone")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	parser := NewParser(tmpFile.Name())
	zone, _, err := parser.Parse()
	if err != nil {
		t.Fatalf("Failed to parse zone: %v", err)
	}

	// Find the TXT record
	var foundTXT bool
	for _, entry := range zone {
		if entry.Type == EntryTypeRecord && entry.HostRecord.Hostname == "test.example.com." {
			foundTXT = true
			if len(entry.HostRecord.Records.TXT) != 1 {
				t.Fatalf("Expected 1 TXT record, got %d", len(entry.HostRecord.Records.TXT))
			}
			
			txtContent := entry.HostRecord.Records.TXT[0].Text
			// The content should be concatenated without extra spaces between quotes
			if !strings.Contains(txtContent, "first part") || !strings.Contains(txtContent, "second part") {
				t.Errorf("Expected TXT content to contain both parts, got: %s", txtContent)
			}
			break
		}
	}
	if !foundTXT {
		t.Error("Expected to find TXT record")
	}
}

func TestParseComments(t *testing.T) {
	content := `$TTL 3600
$ORIGIN example.com.
; This is a comment line
test	IN	A	192.168.1.1	; inline comment
host	IN	TXT	"text ; with semicolon"	; real comment
`

	tmpFile, err := os.CreateTemp("", "test-comments-*.zone")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	parser := NewParser(tmpFile.Name())
	zone, _, err := parser.Parse()
	if err != nil {
		t.Fatalf("Failed to parse zone: %v", err)
	}

	// Check that we have the expected records (comments should be ignored)
	var recordCount int
	for _, entry := range zone {
		if entry.Type == EntryTypeRecord {
			recordCount++
		}
	}

	if recordCount < 2 {
		t.Errorf("Expected at least 2 records, got %d", recordCount)
	}

	// Check that TXT record preserves semicolon inside quotes
	for _, entry := range zone {
		if entry.Type == EntryTypeRecord && entry.HostRecord.Hostname == "host.example.com." {
			if len(entry.HostRecord.Records.TXT) == 1 {
				txtContent := entry.HostRecord.Records.TXT[0].Text
				if !strings.Contains(txtContent, "; with semicolon") {
					t.Errorf("Expected TXT to preserve semicolon, got: %s", txtContent)
				}
			}
		}
	}
}

func TestParseIncludeDirective(t *testing.T) {
	// Create included file
	includeContent := `host1	IN	A	192.168.1.10
host2	IN	A	192.168.1.11
`
	includeFile, err := os.CreateTemp("", "include-*.zone")
	if err != nil {
		t.Fatalf("Failed to create include file: %v", err)
	}
	defer os.Remove(includeFile.Name())

	if _, err := includeFile.WriteString(includeContent); err != nil {
		t.Fatalf("Failed to write include file: %v", err)
	}
	includeFile.Close()

	// Create main zone file
	mainContent := `$TTL 3600
$ORIGIN example.com.
main	IN	A	192.168.1.1
$INCLUDE ` + includeFile.Name() + `
after	IN	A	192.168.1.2
`

	mainFile, err := os.CreateTemp("", "main-*.zone")
	if err != nil {
		t.Fatalf("Failed to create main file: %v", err)
	}
	defer os.Remove(mainFile.Name())

	if _, err := mainFile.WriteString(mainContent); err != nil {
		t.Fatalf("Failed to write main file: %v", err)
	}
	mainFile.Close()

	parser := NewParser(mainFile.Name())
	zone, _, err := parser.Parse()
	if err != nil {
		t.Fatalf("Failed to parse zone with include: %v", err)
	}

	// Count records and check source files
	var mainFileRecords, includeFileRecords int
	for _, entry := range zone {
		if entry.Type == EntryTypeRecord {
			if strings.Contains(entry.SourceFile, "main-") {
				mainFileRecords++
			} else if strings.Contains(entry.SourceFile, "include-") {
				includeFileRecords++
			}
		}
	}

	if mainFileRecords < 2 {
		t.Errorf("Expected at least 2 records from main file, got %d", mainFileRecords)
	}
	if includeFileRecords < 2 {
		t.Errorf("Expected at least 2 records from include file, got %d", includeFileRecords)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "invalid TTL",
			content: "$TTL invalid\n",
		},
		{
			name:    "incomplete record",
			content: "host IN\n",
		},
		{
			name:    "unknown directive",
			content: "$UNKNOWN directive\n",
		},
		{
			name:    "invalid A record",
			content: "host IN A invalid.ip\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "test-error-*.zone")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.WriteString(test.content); err != nil {
				t.Fatalf("Failed to write temp file: %v", err)
			}
			tmpFile.Close()

			parser := NewParser(tmpFile.Name())
			_, _, err = parser.Parse()
			if err == nil {
				t.Errorf("Expected error for %s, but parsing succeeded", test.name)
			}
		})
	}
}

func TestParseFileNotFound(t *testing.T) {
	parser := NewParser("nonexistent.zone")
	_, _, err := parser.Parse()
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestParseBlankHostname(t *testing.T) {
	content := `$TTL 3600
$ORIGIN example.com.
@	IN	A	192.168.1.1
	IN	MX	10 mail.example.com.
	IN	TXT	"test record"
www	IN	A	192.168.1.2
	IN	CNAME	www.example.com.
`

	tmpFile, err := os.CreateTemp("", "test-blank-hostname-*.zone")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	parser := NewParser(tmpFile.Name())
	zone, _, err := parser.Parse()
	if err != nil {
		t.Fatalf("Failed to parse zone: %v", err)
	}

	// Check that records with blank hostnames use the previous hostname
	var foundOriginRecords int
	var foundWWWRecords int

	for _, entry := range zone {
		if entry.Type == EntryTypeRecord {
			if entry.HostRecord.Hostname == "example.com." {
				foundOriginRecords++
			} else if entry.HostRecord.Hostname == "www.example.com." {
				foundWWWRecords++
			}
		}
	}

	// Should have @ record with A, MX, TXT
	if foundOriginRecords == 0 {
		t.Error("Expected to find records for origin (@)")
	}

	// Should have www record  
	if foundWWWRecords == 0 {
		t.Error("Expected to find records for www")
	}
}

func TestParseSourceFileTracking(t *testing.T) {
	content := `$TTL 3600
$ORIGIN example.com.
test	IN	A	192.168.1.1
`

	tmpFile, err := os.CreateTemp("", "test-source-*.zone")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	parser := NewParser(tmpFile.Name())
	zone, _, err := parser.Parse()
	if err != nil {
		t.Fatalf("Failed to parse zone: %v", err)
	}

	// Check that all entries have source file information
	for _, entry := range zone {
		if entry.SourceFile == "" {
			t.Error("Expected source file to be set for all entries")
		}
		if !strings.Contains(entry.SourceFile, "test-source-") {
			t.Errorf("Expected source file to contain temp file name, got: %s", entry.SourceFile)
		}
	}
}