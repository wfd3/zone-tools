package zoneparser

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// parseSpecificRecord handles parsing of individual record types
func (p *Parser) parseSpecificRecord(rrType string, data []string, comment string, records *DNSRecords, rr ResourceRecord) error {
	Log("Parsing specific record type: %s", rrType)

	switch rrType {
	case "A":
		record, err := p.parseARecord(data, comment, rr)
		if err != nil {
			return err
		}
		records.A = append(records.A, record)

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
		target := qualifyDomainName(data[0], p.origin)
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
		mail := qualifyDomainName(data[1], p.origin)
		records.MX = append(records.MX, MXRecord{
			ResourceRecord: rr,
			Priority:       uint16(priority),
			Mail:           mail,
		})

	case "TXT":
		record, err := p.parseTXTRecord(data, comment, rr)
		if err != nil {
			return err
		}
		records.TXT = append(records.TXT, record)

	case "NS":
		if len(data) < 1 {
			return fmt.Errorf("NS record missing name server")
		}
		nameServer := qualifyDomainName(data[0], p.origin)
		records.NS = append(records.NS, NSRecord{
			ResourceRecord: rr,
			NameServer:     nameServer,
		})

	case "SOA":
		// Remove parentheses from SOA data if present
		var cleanData []string
		for _, field := range data {
			cleaned := strings.Trim(field, "()")
			if cleaned != "" {
				cleanData = append(cleanData, cleaned)
			}
		}
		data = cleanData

		if len(data) < 7 {
			return fmt.Errorf("SOA record requires 7 fields")
		}

		primaryNS := qualifyDomainName(data[0], p.origin)
		email := qualifyDomainName(data[1], p.origin)

		serial, err := strconv.ParseUint(data[2], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid SOA serial: %v", err)
		}

		refresh, err := strconv.ParseUint(data[3], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid SOA refresh: %v", err)
		}

		retry, err := strconv.ParseUint(data[4], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid SOA retry: %v", err)
		}

		expire, err := strconv.ParseUint(data[5], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid SOA expire: %v", err)
		}

		minimumTTL, err := strconv.ParseUint(data[6], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid SOA minimum TTL: %v", err)
		}

		records.SOA = append(records.SOA, SOARecord{
			ResourceRecord: rr,
			PrimaryNS:      primaryNS,
			Email:          email,
			Serial:         uint32(serial),
			Refresh:        uint32(refresh),
			Retry:          uint32(retry),
			Expire:         uint32(expire),
			MinimumTTL:     uint32(minimumTTL),
		})

	case "PTR":
		if len(data) < 1 {
			return fmt.Errorf("PTR record missing pointer")
		}
		pointer := qualifyDomainName(data[0], p.origin)
		records.PTR = append(records.PTR, PTRRecord{
			ResourceRecord: rr,
			Pointer:        pointer,
		})

	case "SRV":
		if len(data) < 4 {
			return fmt.Errorf("SRV record requires 4 fields")
		}

		priority, err := strconv.ParseUint(data[0], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid SRV priority: %v", err)
		}

		weight, err := strconv.ParseUint(data[1], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid SRV weight: %v", err)
		}

		port, err := strconv.ParseUint(data[2], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid SRV port: %v", err)
		}

		target := qualifyDomainName(data[3], p.origin)

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

		flags, err := strconv.ParseUint(data[0], 10, 8)
		if err != nil {
			return fmt.Errorf("invalid CAA flags: %v", err)
		}

		tag := data[1]
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

		order, err := strconv.ParseUint(data[0], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid NAPTR order: %v", err)
		}

		preference, err := strconv.ParseUint(data[1], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid NAPTR preference: %v", err)
		}

		flags := strings.Trim(data[2], "\"")
		service := strings.Trim(data[3], "\"")
		regexp := strings.Trim(data[4], "\"")
		replacement := qualifyDomainName(data[5], p.origin)

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
		text := extractTXTContent(data)
		records.SPF = append(records.SPF, SPFRecord{
			ResourceRecord: rr,
			Text:           text,
		})

	default:
		return fmt.Errorf("unsupported record type: %s", rrType)
	}

	return nil
}

// parseARecord parses an A record with optional inaddr flag
func (p *Parser) parseARecord(data []string, comment string, rr ResourceRecord) (ARecord, error) {
	if len(data) < 1 {
		return ARecord{}, fmt.Errorf("A record missing address")
	}

	ip := net.ParseIP(data[0])
	if ip == nil {
		return ARecord{}, fmt.Errorf("invalid A record address: %s", data[0])
	}
	if ip.To4() == nil {
		return ARecord{}, fmt.Errorf("A record must be IPv4 address: %s", data[0])
	}

	// Check if this A record has an inaddr flag in the comment
	inaddr := false
	if comment != "" {
		commentLower := strings.ToLower(comment)
		if commentLower == InAddrComment || commentLower == InAddrAltComment {
			inaddr = true
		}
	}

	return ARecord{
		ResourceRecord: rr,
		Address:        ip,
		Inaddr:         inaddr,
	}, nil
}

// parseTXTRecord parses a TXT record
func (p *Parser) parseTXTRecord(data []string, comment string, rr ResourceRecord) (TXTRecord, error) {
	if len(data) < 1 {
		return TXTRecord{}, fmt.Errorf("TXT record missing text")
	}

	text := extractTXTContent(data)

	return TXTRecord{
		ResourceRecord: rr,
		Text:           text,
	}, nil
}