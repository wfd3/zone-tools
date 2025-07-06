package zoneparser

import (
	"net"
	"testing"
)

func TestDNSRecords_Creation(t *testing.T) {
	records := DNSRecords{}
	
	// Test that all record slices are initialized as empty
	if len(records.A) != 0 {
		t.Errorf("Expected empty A records, got %d", len(records.A))
	}
	if len(records.AAAA) != 0 {
		t.Errorf("Expected empty AAAA records, got %d", len(records.AAAA))
	}
	if len(records.CNAME) != 0 {
		t.Errorf("Expected empty CNAME records, got %d", len(records.CNAME))
	}
	if len(records.MX) != 0 {
		t.Errorf("Expected empty MX records, got %d", len(records.MX))
	}
	if len(records.TXT) != 0 {
		t.Errorf("Expected empty TXT records, got %d", len(records.TXT))
	}
	if len(records.NS) != 0 {
		t.Errorf("Expected empty NS records, got %d", len(records.NS))
	}
	if len(records.SOA) != 0 {
		t.Errorf("Expected empty SOA records, got %d", len(records.SOA))
	}
	if len(records.PTR) != 0 {
		t.Errorf("Expected empty PTR records, got %d", len(records.PTR))
	}
	if len(records.SRV) != 0 {
		t.Errorf("Expected empty SRV records, got %d", len(records.SRV))
	}
	if len(records.CAA) != 0 {
		t.Errorf("Expected empty CAA records, got %d", len(records.CAA))
	}
	if len(records.HINFO) != 0 {
		t.Errorf("Expected empty HINFO records, got %d", len(records.HINFO))
	}
	if len(records.NAPTR) != 0 {
		t.Errorf("Expected empty NAPTR records, got %d", len(records.NAPTR))
	}
	if len(records.SPF) != 0 {
		t.Errorf("Expected empty SPF records, got %d", len(records.SPF))
	}
}

func TestARecord_Creation(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	if ip == nil {
		t.Fatal("Failed to parse test IP")
	}
	
	record := ARecord{
		ResourceRecord: ResourceRecord{
			TTL:   3600,
			Class: "IN",
		},
		Address: ip,
		Inaddr:  true,
	}
	
	if record.TTL != 3600 {
		t.Errorf("Expected TTL 3600, got %d", record.TTL)
	}
	if record.Class != "IN" {
		t.Errorf("Expected class IN, got %s", record.Class)
	}
	if !record.Address.Equal(ip) {
		t.Errorf("Expected address %v, got %v", ip, record.Address)
	}
	if !record.Inaddr {
		t.Error("Expected Inaddr to be true")
	}
}

func TestAAAARecord_Creation(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	if ip == nil {
		t.Fatal("Failed to parse test IPv6")
	}
	
	record := AAAARecord{
		ResourceRecord: ResourceRecord{
			TTL:   7200,
			Class: "IN",
		},
		Address: ip,
	}
	
	if record.TTL != 7200 {
		t.Errorf("Expected TTL 7200, got %d", record.TTL)
	}
	if record.Class != "IN" {
		t.Errorf("Expected class IN, got %s", record.Class)
	}
	if !record.Address.Equal(ip) {
		t.Errorf("Expected address %v, got %v", ip, record.Address)
	}
}

func TestMXRecord_Creation(t *testing.T) {
	record := MXRecord{
		ResourceRecord: ResourceRecord{
			TTL:   1800,
			Class: "IN",
		},
		Priority: 10,
		Mail:     "mail.example.com.",
	}
	
	if record.TTL != 1800 {
		t.Errorf("Expected TTL 1800, got %d", record.TTL)
	}
	if record.Priority != 10 {
		t.Errorf("Expected priority 10, got %d", record.Priority)
	}
	if record.Mail != "mail.example.com." {
		t.Errorf("Expected mail server mail.example.com., got %s", record.Mail)
	}
}

func TestSOARecord_Creation(t *testing.T) {
	record := SOARecord{
		ResourceRecord: ResourceRecord{
			TTL:   86400,
			Class: "IN",
		},
		PrimaryNS:  "ns1.example.com.",
		Email:      "admin.example.com.",
		Serial:     2023010101,
		Refresh:    3600,
		Retry:      1800,
		Expire:     604800,
		MinimumTTL: 86400,
	}
	
	if record.PrimaryNS != "ns1.example.com." {
		t.Errorf("Expected primary NS ns1.example.com., got %s", record.PrimaryNS)
	}
	if record.Email != "admin.example.com." {
		t.Errorf("Expected email admin.example.com., got %s", record.Email)
	}
	if record.Serial != 2023010101 {
		t.Errorf("Expected serial 2023010101, got %d", record.Serial)
	}
	if record.Refresh != 3600 {
		t.Errorf("Expected refresh 3600, got %d", record.Refresh)
	}
	if record.Retry != 1800 {
		t.Errorf("Expected retry 1800, got %d", record.Retry)
	}
	if record.Expire != 604800 {
		t.Errorf("Expected expire 604800, got %d", record.Expire)
	}
	if record.MinimumTTL != 86400 {
		t.Errorf("Expected minimum TTL 86400, got %d", record.MinimumTTL)
	}
}

func TestSRVRecord_Creation(t *testing.T) {
	record := SRVRecord{
		ResourceRecord: ResourceRecord{
			TTL:   3600,
			Class: "IN",
		},
		Priority: 5,
		Weight:   10,
		Port:     443,
		Target:   "server.example.com.",
	}
	
	if record.Priority != 5 {
		t.Errorf("Expected priority 5, got %d", record.Priority)
	}
	if record.Weight != 10 {
		t.Errorf("Expected weight 10, got %d", record.Weight)
	}
	if record.Port != 443 {
		t.Errorf("Expected port 443, got %d", record.Port)
	}
	if record.Target != "server.example.com." {
		t.Errorf("Expected target server.example.com., got %s", record.Target)
	}
}

func TestCAARecord_Creation(t *testing.T) {
	record := CAARecord{
		ResourceRecord: ResourceRecord{
			TTL:   3600,
			Class: "IN",
		},
		Flags: 0,
		Tag:   "issue",
		Value: "letsencrypt.org",
	}
	
	if record.Flags != 0 {
		t.Errorf("Expected flags 0, got %d", record.Flags)
	}
	if record.Tag != "issue" {
		t.Errorf("Expected tag issue, got %s", record.Tag)
	}
	if record.Value != "letsencrypt.org" {
		t.Errorf("Expected value letsencrypt.org, got %s", record.Value)
	}
}

func TestNAPTRRecord_Creation(t *testing.T) {
	record := NAPTRRecord{
		ResourceRecord: ResourceRecord{
			TTL:   3600,
			Class: "IN",
		},
		Order:       10,
		Preference:  20,
		Flags:       "s",
		Service:     "SIP+D2U",
		Regexp:      "",
		Replacement: "_sip._udp.example.com.",
	}
	
	if record.Order != 10 {
		t.Errorf("Expected order 10, got %d", record.Order)
	}
	if record.Preference != 20 {
		t.Errorf("Expected preference 20, got %d", record.Preference)
	}
	if record.Flags != "s" {
		t.Errorf("Expected flags s, got %s", record.Flags)
	}
	if record.Service != "SIP+D2U" {
		t.Errorf("Expected service SIP+D2U, got %s", record.Service)
	}
	if record.Replacement != "_sip._udp.example.com." {
		t.Errorf("Expected replacement _sip._udp.example.com., got %s", record.Replacement)
	}
}

func TestHostRecord_Creation(t *testing.T) {
	host := HostRecord{
		Hostname: "example.com.",
		Records:  DNSRecords{},
	}
	
	if host.Hostname != "example.com." {
		t.Errorf("Expected hostname example.com., got %s", host.Hostname)
	}
	
	// Test adding records
	ip := net.ParseIP("192.168.1.1")
	aRecord := ARecord{
		ResourceRecord: ResourceRecord{TTL: 3600, Class: "IN"},
		Address:        ip,
		Inaddr:         false,
	}
	
	host.Records.A = append(host.Records.A, aRecord)
	
	if len(host.Records.A) != 1 {
		t.Errorf("Expected 1 A record, got %d", len(host.Records.A))
	}
	if !host.Records.A[0].Address.Equal(ip) {
		t.Errorf("Expected A record address %v, got %v", ip, host.Records.A[0].Address)
	}
}