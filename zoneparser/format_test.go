package zoneparser

import (
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"testing"
)

func TestFormatHostname(t *testing.T) {
	tests := []struct {
		hostname string
		origin   string
		expected string
	}{
		{
			hostname: "example.com.",
			origin:   "example.com.",
			expected: "@",
		},
		{
			hostname: "www.example.com.",
			origin:   "example.com.",
			expected: "www",
		},
		{
			hostname: "mail.subdomain.example.com.",
			origin:   "example.com.",
			expected: "mail.subdomain",
		},
		{
			hostname: "external.org.",
			origin:   "example.com.",
			expected: "external.org.",
		},
		{
			hostname: "host.example.com.",
			origin:   "different.com.",
			expected: "host.example.com.",
		},
	}

	for _, test := range tests {
		result := FormatHostname(test.hostname, test.origin)
		if result != test.expected {
			t.Errorf("FormatHostname(%q, %q) = %q, expected %q", 
				test.hostname, test.origin, result, test.expected)
		}
	}
}

func TestHasAnyRecords(t *testing.T) {
	// Empty records
	emptyRecords := &DNSRecords{}
	if HasAnyRecords(emptyRecords) {
		t.Error("Expected HasAnyRecords to return false for empty records")
	}

	// Test each record type
	tests := []struct {
		name string
		setup func(*DNSRecords)
	}{
		{
			name: "A record",
			setup: func(r *DNSRecords) {
				r.A = append(r.A, ARecord{})
			},
		},
		{
			name: "AAAA record",
			setup: func(r *DNSRecords) {
				r.AAAA = append(r.AAAA, AAAARecord{})
			},
		},
		{
			name: "CNAME record",
			setup: func(r *DNSRecords) {
				r.CNAME = append(r.CNAME, CNAMERecord{})
			},
		},
		{
			name: "MX record",
			setup: func(r *DNSRecords) {
				r.MX = append(r.MX, MXRecord{})
			},
		},
		{
			name: "TXT record",
			setup: func(r *DNSRecords) {
				r.TXT = append(r.TXT, TXTRecord{})
			},
		},
		{
			name: "NS record",
			setup: func(r *DNSRecords) {
				r.NS = append(r.NS, NSRecord{})
			},
		},
		{
			name: "SOA record",
			setup: func(r *DNSRecords) {
				r.SOA = append(r.SOA, SOARecord{})
			},
		},
		{
			name: "PTR record",
			setup: func(r *DNSRecords) {
				r.PTR = append(r.PTR, PTRRecord{})
			},
		},
		{
			name: "SRV record",
			setup: func(r *DNSRecords) {
				r.SRV = append(r.SRV, SRVRecord{})
			},
		},
		{
			name: "CAA record",
			setup: func(r *DNSRecords) {
				r.CAA = append(r.CAA, CAARecord{})
			},
		},
		{
			name: "HINFO record",
			setup: func(r *DNSRecords) {
				r.HINFO = append(r.HINFO, HINFORecord{})
			},
		},
		{
			name: "NAPTR record",
			setup: func(r *DNSRecords) {
				r.NAPTR = append(r.NAPTR, NAPTRRecord{})
			},
		},
		{
			name: "SPF record",
			setup: func(r *DNSRecords) {
				r.SPF = append(r.SPF, SPFRecord{})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			records := &DNSRecords{}
			test.setup(records)
			if !HasAnyRecords(records) {
				t.Errorf("Expected HasAnyRecords to return true for %s", test.name)
			}
		})
	}
}

// captureOutput captures stdout for testing print functions
func captureOutput(f func()) string {
	// Save original stdout
	origStdout := os.Stdout

	// Create a pipe
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run the function
	f()

	// Close writer and restore stdout
	w.Close()
	os.Stdout = origStdout

	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	r.Close()

	return buf.String()
}

func TestPrintHostRecords_EmptyHost(t *testing.T) {
	output := captureOutput(func() {
		PrintHostRecords(nil, "example.com.")
	})
	
	if output != "" {
		t.Errorf("Expected no output for nil host, got: %s", output)
	}
}

func TestPrintHostRecords_ARecord(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	host := &HostRecord{
		Hostname: "www.example.com.",
		Records: DNSRecords{
			A: []ARecord{
				{
					ResourceRecord: ResourceRecord{TTL: 3600, Class: "IN"},
					Address:        ip,
					Inaddr:         false,
				},
			},
		},
	}

	output := captureOutput(func() {
		PrintHostRecords(host, "example.com.")
	})

	expected := "www\tIN\tA\t192.168.1.1\n\n"
	if output != expected {
		t.Errorf("Expected A record output:\n%q\nGot:\n%q", expected, output)
	}
}

func TestPrintHostRecords_ARecordWithInaddr(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	host := &HostRecord{
		Hostname: "host.example.com.",
		Records: DNSRecords{
			A: []ARecord{
				{
					ResourceRecord: ResourceRecord{TTL: 3600, Class: "IN"},
					Address:        ip,
					Inaddr:         true,
				},
			},
		},
	}

	output := captureOutput(func() {
		PrintHostRecords(host, "example.com.")
	})

	expected := "host\tIN\tA\t10.0.0.1\t; inaddr\n\n"
	if output != expected {
		t.Errorf("Expected A record with inaddr output:\n%q\nGot:\n%q", expected, output)
	}
}

func TestPrintHostRecords_MXRecord(t *testing.T) {
	host := &HostRecord{
		Hostname: "example.com.",
		Records: DNSRecords{
			MX: []MXRecord{
				{
					ResourceRecord: ResourceRecord{TTL: 3600, Class: "IN"},
					Priority:       10,
					Mail:           "mail.example.com.",
				},
			},
		},
	}

	output := captureOutput(func() {
		PrintHostRecords(host, "example.com.")
	})

	expected := "@\tIN\tMX\t10 mail.example.com.\n\n"
	if output != expected {
		t.Errorf("Expected MX record output:\n%q\nGot:\n%q", expected, output)
	}
}

func TestPrintHostRecords_TXTRecord(t *testing.T) {
	host := &HostRecord{
		Hostname: "test.example.com.",
		Records: DNSRecords{
			TXT: []TXTRecord{
				{
					ResourceRecord: ResourceRecord{TTL: 3600, Class: "IN"},
					Text:           "v=spf1 include:_spf.google.com ~all",
				},
			},
		},
	}

	output := captureOutput(func() {
		PrintHostRecords(host, "example.com.")
	})

	expected := "test\tIN\tTXT\t\"v=spf1 include:_spf.google.com ~all\"\n\n"
	if output != expected {
		t.Errorf("Expected TXT record output:\n%q\nGot:\n%q", expected, output)
	}
}

func TestPrintHostRecords_SOARecord(t *testing.T) {
	host := &HostRecord{
		Hostname: "example.com.",
		Records: DNSRecords{
			SOA: []SOARecord{
				{
					ResourceRecord: ResourceRecord{TTL: 86400, Class: "IN"},
					PrimaryNS:      "ns1.example.com.",
					Email:          "admin.example.com.",
					Serial:         2023010101,
					Refresh:        3600,
					Retry:          1800,
					Expire:         604800,
					MinimumTTL:     86400,
				},
			},
		},
	}

	output := captureOutput(func() {
		PrintHostRecords(host, "example.com.")
	})

	lines := strings.Split(output, "\n")
	if len(lines) < 6 {
		t.Fatalf("Expected at least 6 lines for SOA record, got %d", len(lines))
	}

	expectedStart := "@\tIN\tSOA\tns1.example.com. admin.example.com. ("
	if !strings.HasPrefix(lines[0], expectedStart) {
		t.Errorf("Expected SOA record to start with %q, got %q", expectedStart, lines[0])
	}

	// Check for serial number
	if !strings.Contains(output, "2023010101\t; Serial") {
		t.Error("Expected to find serial number in SOA record output")
	}
}

func TestPrintHostRecords_SRVRecord(t *testing.T) {
	host := &HostRecord{
		Hostname: "_sip._tcp.example.com.",
		Records: DNSRecords{
			SRV: []SRVRecord{
				{
					ResourceRecord: ResourceRecord{TTL: 3600, Class: "IN"},
					Priority:       10,
					Weight:         5,
					Port:           5060,
					Target:         "sipserver.example.com.",
				},
			},
		},
	}

	output := captureOutput(func() {
		PrintHostRecords(host, "example.com.")
	})

	expected := "_sip._tcp\tIN\tSRV\t10 5 5060 sipserver.example.com.\n\n"
	if output != expected {
		t.Errorf("Expected SRV record output:\n%q\nGot:\n%q", expected, output)
	}
}

func TestPrintHostRecords_CAARecord(t *testing.T) {
	host := &HostRecord{
		Hostname: "example.com.",
		Records: DNSRecords{
			CAA: []CAARecord{
				{
					ResourceRecord: ResourceRecord{TTL: 3600, Class: "IN"},
					Flags:          0,
					Tag:            "issue",
					Value:          "letsencrypt.org",
				},
			},
		},
	}

	output := captureOutput(func() {
		PrintHostRecords(host, "example.com.")
	})

	expected := "@\tIN\tCAA\t0 issue \"letsencrypt.org\"\n\n"
	if output != expected {
		t.Errorf("Expected CAA record output:\n%q\nGot:\n%q", expected, output)
	}
}

func TestPrintHostRecords_MultipleRecords(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	host := &HostRecord{
		Hostname: "multi.example.com.",
		Records: DNSRecords{
			A: []ARecord{
				{
					ResourceRecord: ResourceRecord{TTL: 3600, Class: "IN"},
					Address:        ip,
					Inaddr:         false,
				},
			},
			MX: []MXRecord{
				{
					ResourceRecord: ResourceRecord{TTL: 3600, Class: "IN"},
					Priority:       10,
					Mail:           "mail.example.com.",
				},
			},
			TXT: []TXTRecord{
				{
					ResourceRecord: ResourceRecord{TTL: 3600, Class: "IN"},
					Text:           "test record",
				},
			},
		},
	}

	output := captureOutput(func() {
		PrintHostRecords(host, "example.com.")
	})

	// Should contain all record types in the correct order: A, MX, TXT
	lines := strings.Split(strings.TrimSpace(output), "\n")
	
	// Remove empty lines for easier testing
	var nonEmptyLines []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			nonEmptyLines = append(nonEmptyLines, line)
		}
	}

	if len(nonEmptyLines) != 3 {
		t.Fatalf("Expected 3 record lines, got %d: %v", len(nonEmptyLines), nonEmptyLines)
	}

	if !strings.Contains(nonEmptyLines[0], "A\t192.168.1.1") {
		t.Errorf("Expected A record in first line, got: %s", nonEmptyLines[0])
	}
	if !strings.Contains(nonEmptyLines[1], "MX\t10 mail.example.com.") {
		t.Errorf("Expected MX record in second line, got: %s", nonEmptyLines[1])
	}
	if !strings.Contains(nonEmptyLines[2], "TXT\t\"test record\"") {
		t.Errorf("Expected TXT record in third line, got: %s", nonEmptyLines[2])
	}
}