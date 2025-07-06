package zoneparser

import (
	"fmt"
	"strings"
)

// FormatHostname formats a hostname for zone file output
func FormatHostname(hostname, origin string) string {
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

// HasAnyRecords checks if a DNSRecords struct contains any records
func HasAnyRecords(records *DNSRecords) bool {
	return len(records.A) > 0 || len(records.AAAA) > 0 || len(records.CNAME) > 0 ||
		len(records.MX) > 0 || len(records.TXT) > 0 || len(records.NS) > 0 ||
		len(records.SOA) > 0 || len(records.PTR) > 0 || len(records.SRV) > 0 ||
		len(records.CAA) > 0 || len(records.HINFO) > 0 || len(records.NAPTR) > 0 ||
		len(records.SPF) > 0
}

// PrintHostRecords formats and prints all DNS records for a hostname
func PrintHostRecords(host *HostRecord, origin string) {
	if host == nil {
		return
	}

	// Format hostname for output
	ownerName := FormatHostname(host.Hostname, origin)
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
	if HasAnyRecords(records) {
		fmt.Println()
	}
}