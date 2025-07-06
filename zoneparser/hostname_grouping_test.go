package zoneparser

import (
	"os"
	"testing"
)

func TestBlankHostnameGrouping(t *testing.T) {
	// Test case that reproduces the gw record issue
	content := `$TTL 86400
$ORIGIN home.drummond.us.
gw			IN	A	10.0.0.1
			IN	MX 	0 ASPMX.L.GOOGLE.COM.
			IN	TXT	"Router internal IP"
			IN	TXT     "kea: hw-address 1c:fd:08:7b:3c:18"
`

	tmpFile, err := os.CreateTemp("", "test-grouping-*.zone")
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

	// Find the gw record
	var gwRecord *ZoneEntry
	for _, entry := range zone {
		if entry.Type == EntryTypeRecord && entry.HostRecord.Hostname == "gw.home.drummond.us." {
			gwRecord = &entry
			break
		}
	}

	if gwRecord == nil {
		t.Fatal("Expected to find gw record")
	}

	// Verify all record types are grouped together
	if len(gwRecord.HostRecord.Records.A) != 1 {
		t.Errorf("Expected 1 A record, got %d", len(gwRecord.HostRecord.Records.A))
	}
	if len(gwRecord.HostRecord.Records.MX) != 1 {
		t.Errorf("Expected 1 MX record, got %d", len(gwRecord.HostRecord.Records.MX))
	}
	if len(gwRecord.HostRecord.Records.TXT) != 2 {
		t.Errorf("Expected 2 TXT records, got %d", len(gwRecord.HostRecord.Records.TXT))
	}

	// Verify the record values
	if gwRecord.HostRecord.Records.A[0].Address.String() != "10.0.0.1" {
		t.Errorf("Expected A record 10.0.0.1, got %s", gwRecord.HostRecord.Records.A[0].Address.String())
	}
	if gwRecord.HostRecord.Records.MX[0].Priority != 0 {
		t.Errorf("Expected MX priority 0, got %d", gwRecord.HostRecord.Records.MX[0].Priority)
	}
	if gwRecord.HostRecord.Records.MX[0].Mail != "ASPMX.L.GOOGLE.COM." {
		t.Errorf("Expected MX mail ASPMX.L.GOOGLE.COM., got %s", gwRecord.HostRecord.Records.MX[0].Mail)
	}
	if gwRecord.HostRecord.Records.TXT[0].Text != "Router internal IP" {
		t.Errorf("Expected TXT 'Router internal IP', got %s", gwRecord.HostRecord.Records.TXT[0].Text)
	}
	if gwRecord.HostRecord.Records.TXT[1].Text != "kea: hw-address 1c:fd:08:7b:3c:18" {
		t.Errorf("Expected TXT 'kea: hw-address 1c:fd:08:7b:3c:18', got %s", gwRecord.HostRecord.Records.TXT[1].Text)
	}

	// Verify there's only one ZoneEntry for the gw hostname
	gwCount := 0
	for _, entry := range zone {
		if entry.Type == EntryTypeRecord && entry.HostRecord.Hostname == "gw.home.drummond.us." {
			gwCount++
		}
	}
	if gwCount != 1 {
		t.Errorf("Expected exactly 1 zone entry for gw.home.drummond.us., got %d", gwCount)
	}
}