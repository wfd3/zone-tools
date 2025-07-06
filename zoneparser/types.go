package zoneparser

import "net"

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

// DNSRecords holds all types of DNS records for a hostname
type DNSRecords struct {
	A      []ARecord
	AAAA   []AAAARecord
	CNAME  []CNAMERecord
	MX     []MXRecord
	TXT    []TXTRecord
	NS     []NSRecord
	SOA    []SOARecord
	PTR    []PTRRecord
	SRV    []SRVRecord
	CAA    []CAARecord
	HINFO  []HINFORecord
	NAPTR  []NAPTRRecord
	SPF    []SPFRecord
}

// HostRecord represents all DNS records for a single hostname
type HostRecord struct {
	Hostname string
	Records  DNSRecords
}