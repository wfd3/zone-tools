package zoneparser

import (
	"net"
	"testing"
)

func TestParseARecord(t *testing.T) {
	parser := &Parser{origin: "example.com."}
	
	tests := []struct {
		data      []string
		comment   string
		expectErr bool
		checkAddr string
		checkInaddr bool
	}{
		{
			data:        []string{"192.168.1.1"},
			comment:     "",
			expectErr:   false,
			checkAddr:   "192.168.1.1",
			checkInaddr: false,
		},
		{
			data:        []string{"10.0.0.1"},
			comment:     "inaddr",
			expectErr:   false,
			checkAddr:   "10.0.0.1",
			checkInaddr: true,
		},
		{
			data:        []string{"192.168.1.2"},
			comment:     "in-addr",
			expectErr:   false,
			checkAddr:   "192.168.1.2",
			checkInaddr: true,
		},
		{
			data:      []string{},
			expectErr: true,
		},
		{
			data:      []string{"invalid.ip"},
			expectErr: true,
		},
		{
			data:      []string{"2001:db8::1"}, // IPv6 in A record
			expectErr: true,
		},
	}

	for i, test := range tests {
		rr := ResourceRecord{TTL: 3600, Class: "IN"}
		record, err := parser.parseARecord(test.data, test.comment, rr)
		
		if test.expectErr {
			if err == nil {
				t.Errorf("Test %d: expected error but got none", i)
			}
			continue
		}
		
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		
		if record.Address.String() != test.checkAddr {
			t.Errorf("Test %d: expected address %s, got %s", i, test.checkAddr, record.Address.String())
		}
		
		if record.Inaddr != test.checkInaddr {
			t.Errorf("Test %d: expected inaddr %v, got %v", i, test.checkInaddr, record.Inaddr)
		}
		
		if record.TTL != 3600 {
			t.Errorf("Test %d: expected TTL 3600, got %d", i, record.TTL)
		}
	}
}

func TestParseTXTRecord(t *testing.T) {
	parser := &Parser{origin: "example.com."}
	
	tests := []struct {
		data      []string
		expectErr bool
		checkText string
	}{
		{
			data:      []string{`"hello world"`},
			expectErr: false,
			checkText: "hello world",
		},
		{
			data:      []string{"unquoted", "text"},
			expectErr: false,
			checkText: "unquoted text",
		},
		{
			data:      []string{`"v=DKIM1;"`, `"k=rsa;"`, `"p=MIGfMA0..."`},
			expectErr: false,
			checkText: `"v=DKIM1;" "k=rsa;" "p=MIGfMA0..."`,
		},
		{
			data:      []string{},
			expectErr: true,
		},
	}

	for i, test := range tests {
		rr := ResourceRecord{TTL: 3600, Class: "IN"}
		record, err := parser.parseTXTRecord(test.data, "", rr)
		
		if test.expectErr {
			if err == nil {
				t.Errorf("Test %d: expected error but got none", i)
			}
			continue
		}
		
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		
		if record.Text != test.checkText {
			t.Errorf("Test %d: expected text %q, got %q", i, test.checkText, record.Text)
		}
	}
}

func TestParseSpecificRecord_A(t *testing.T) {
	parser := &Parser{origin: "example.com."}
	records := &DNSRecords{}
	rr := ResourceRecord{TTL: 3600, Class: "IN"}
	
	err := parser.parseSpecificRecord("A", []string{"192.168.1.1"}, "", records, rr)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if len(records.A) != 1 {
		t.Fatalf("Expected 1 A record, got %d", len(records.A))
	}
	
	if records.A[0].Address.String() != "192.168.1.1" {
		t.Errorf("Expected address 192.168.1.1, got %s", records.A[0].Address.String())
	}
}

func TestParseSpecificRecord_AAAA(t *testing.T) {
	parser := &Parser{origin: "example.com."}
	records := &DNSRecords{}
	rr := ResourceRecord{TTL: 3600, Class: "IN"}
	
	// Valid IPv6
	err := parser.parseSpecificRecord("AAAA", []string{"2001:db8::1"}, "", records, rr)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if len(records.AAAA) != 1 {
		t.Fatalf("Expected 1 AAAA record, got %d", len(records.AAAA))
	}
	
	expected := net.ParseIP("2001:db8::1")
	if !records.AAAA[0].Address.Equal(expected) {
		t.Errorf("Expected address %v, got %v", expected, records.AAAA[0].Address)
	}
	
	// Invalid - IPv4 in AAAA record
	records = &DNSRecords{}
	err = parser.parseSpecificRecord("AAAA", []string{"192.168.1.1"}, "", records, rr)
	if err == nil {
		t.Error("Expected error for IPv4 address in AAAA record")
	}
}

func TestParseSpecificRecord_MX(t *testing.T) {
	parser := &Parser{origin: "example.com."}
	records := &DNSRecords{}
	rr := ResourceRecord{TTL: 3600, Class: "IN"}
	
	err := parser.parseSpecificRecord("MX", []string{"10", "mail.example.com"}, "", records, rr)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if len(records.MX) != 1 {
		t.Fatalf("Expected 1 MX record, got %d", len(records.MX))
	}
	
	if records.MX[0].Priority != 10 {
		t.Errorf("Expected priority 10, got %d", records.MX[0].Priority)
	}
	
	if records.MX[0].Mail != "mail.example.com.example.com." {
		t.Errorf("Expected mail mail.example.com.example.com., got %s", records.MX[0].Mail)
	}
}

func TestParseSpecificRecord_CNAME(t *testing.T) {
	parser := &Parser{origin: "example.com."}
	records := &DNSRecords{}
	rr := ResourceRecord{TTL: 3600, Class: "IN"}
	
	err := parser.parseSpecificRecord("CNAME", []string{"target.example.com"}, "", records, rr)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if len(records.CNAME) != 1 {
		t.Fatalf("Expected 1 CNAME record, got %d", len(records.CNAME))
	}
	
	if records.CNAME[0].Target != "target.example.com.example.com." {
		t.Errorf("Expected target target.example.com.example.com., got %s", records.CNAME[0].Target)
	}
}

func TestParseSpecificRecord_SOA(t *testing.T) {
	parser := &Parser{origin: "example.com."}
	records := &DNSRecords{}
	rr := ResourceRecord{TTL: 3600, Class: "IN"}
	
	data := []string{"ns1.example.com", "admin.example.com", "2023010101", "3600", "1800", "604800", "86400"}
	err := parser.parseSpecificRecord("SOA", data, "", records, rr)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if len(records.SOA) != 1 {
		t.Fatalf("Expected 1 SOA record, got %d", len(records.SOA))
	}
	
	soa := records.SOA[0]
	if soa.PrimaryNS != "ns1.example.com.example.com." {
		t.Errorf("Expected primary NS ns1.example.com.example.com., got %s", soa.PrimaryNS)
	}
	if soa.Serial != 2023010101 {
		t.Errorf("Expected serial 2023010101, got %d", soa.Serial)
	}
	if soa.Refresh != 3600 {
		t.Errorf("Expected refresh 3600, got %d", soa.Refresh)
	}
	
	// Test with parentheses (should be cleaned)
	records = &DNSRecords{}
	data = []string{"(", "ns1.example.com", "admin.example.com", "2023010101", "3600", "1800", "604800", "86400", ")"}
	err = parser.parseSpecificRecord("SOA", data, "", records, rr)
	if err != nil {
		t.Fatalf("Unexpected error with parentheses: %v", err)
	}
	
	if len(records.SOA) != 1 {
		t.Fatalf("Expected 1 SOA record with parentheses, got %d", len(records.SOA))
	}
}

func TestParseSpecificRecord_SRV(t *testing.T) {
	parser := &Parser{origin: "example.com."}
	records := &DNSRecords{}
	rr := ResourceRecord{TTL: 3600, Class: "IN"}
	
	err := parser.parseSpecificRecord("SRV", []string{"10", "20", "443", "target.example.com"}, "", records, rr)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if len(records.SRV) != 1 {
		t.Fatalf("Expected 1 SRV record, got %d", len(records.SRV))
	}
	
	srv := records.SRV[0]
	if srv.Priority != 10 {
		t.Errorf("Expected priority 10, got %d", srv.Priority)
	}
	if srv.Weight != 20 {
		t.Errorf("Expected weight 20, got %d", srv.Weight)
	}
	if srv.Port != 443 {
		t.Errorf("Expected port 443, got %d", srv.Port)
	}
	if srv.Target != "target.example.com.example.com." {
		t.Errorf("Expected target target.example.com.example.com., got %s", srv.Target)
	}
}

func TestParseSpecificRecord_CAA(t *testing.T) {
	parser := &Parser{origin: "example.com."}
	records := &DNSRecords{}
	rr := ResourceRecord{TTL: 3600, Class: "IN"}
	
	err := parser.parseSpecificRecord("CAA", []string{"0", "issue", `"letsencrypt.org"`}, "", records, rr)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if len(records.CAA) != 1 {
		t.Fatalf("Expected 1 CAA record, got %d", len(records.CAA))
	}
	
	caa := records.CAA[0]
	if caa.Flags != 0 {
		t.Errorf("Expected flags 0, got %d", caa.Flags)
	}
	if caa.Tag != "issue" {
		t.Errorf("Expected tag issue, got %s", caa.Tag)
	}
	if caa.Value != "letsencrypt.org" {
		t.Errorf("Expected value letsencrypt.org, got %s", caa.Value)
	}
}

func TestParseSpecificRecord_NAPTR(t *testing.T) {
	parser := &Parser{origin: "example.com."}
	records := &DNSRecords{}
	rr := ResourceRecord{TTL: 3600, Class: "IN"}
	
	data := []string{"10", "20", `"s"`, `"SIP+D2U"`, `""`, "_sip._udp.example.com"}
	err := parser.parseSpecificRecord("NAPTR", data, "", records, rr)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if len(records.NAPTR) != 1 {
		t.Fatalf("Expected 1 NAPTR record, got %d", len(records.NAPTR))
	}
	
	naptr := records.NAPTR[0]
	if naptr.Order != 10 {
		t.Errorf("Expected order 10, got %d", naptr.Order)
	}
	if naptr.Preference != 20 {
		t.Errorf("Expected preference 20, got %d", naptr.Preference)
	}
	if naptr.Flags != "s" {
		t.Errorf("Expected flags s, got %s", naptr.Flags)
	}
	if naptr.Service != "SIP+D2U" {
		t.Errorf("Expected service SIP+D2U, got %s", naptr.Service)
	}
	if naptr.Regexp != "" {
		t.Errorf("Expected empty regexp, got %s", naptr.Regexp)
	}
}

func TestParseSpecificRecord_UnsupportedType(t *testing.T) {
	parser := &Parser{origin: "example.com."}
	records := &DNSRecords{}
	rr := ResourceRecord{TTL: 3600, Class: "IN"}
	
	err := parser.parseSpecificRecord("UNKNOWN", []string{"data"}, "", records, rr)
	if err == nil {
		t.Error("Expected error for unsupported record type")
	}
}

func TestParseSpecificRecord_ErrorCases(t *testing.T) {
	parser := &Parser{origin: "example.com."}
	records := &DNSRecords{}
	rr := ResourceRecord{TTL: 3600, Class: "IN"}
	
	// Test insufficient data for various record types
	tests := []struct {
		rrType string
		data   []string
	}{
		{"A", []string{}},
		{"AAAA", []string{}},
		{"CNAME", []string{}},
		{"MX", []string{"10"}},
		{"NS", []string{}},
		{"SOA", []string{"ns", "admin"}},
		{"PTR", []string{}},
		{"SRV", []string{"10", "20"}},
		{"CAA", []string{"0"}},
		{"HINFO", []string{"cpu"}},
		{"NAPTR", []string{"10", "20"}},
		{"TXT", []string{}},
	}
	
	for _, test := range tests {
		err := parser.parseSpecificRecord(test.rrType, test.data, "", records, rr)
		if err == nil {
			t.Errorf("Expected error for %s record with insufficient data %v", test.rrType, test.data)
		}
	}
}