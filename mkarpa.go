package main

// Generate reverse zone files from one or more forward zones

import (
	"bufio"
	"container/list"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type soa_t struct {
	authns  string
	domain  string
	contact string
	serial  uint64
	refresh uint64
	retry   uint64
	expire  uint64
	minimum uint64
	ns      []string
}

var domain string
var ttl string
var soa soa_t

var zone *list.List

// Regular expressions
var IN_A = regexp.MustCompile(`IN[\s|\t]+A`)
var IN_NS = regexp.MustCompile(`IN[\s|\t]+NS`)
var IN_SOA = regexp.MustCompile(`IN[\s|\t]+SOA`)

var splitSpace = regexp.MustCompile(`[\s+|\t+]`)
var StartsWithLetterOrNumber = regexp.MustCompile(`^\w`)
var StartsWithWhiteSpace = regexp.MustCompile(`^\s+\S`)
var commentToEndOfLine = regexp.MustCompile(`;.*`)

//
// helper functions
//

func okToShow(s string) bool {
	no_show := strings.Contains(s, ";inaddr") || strings.Contains(s, "; inaddr") || strings.Contains(s, ";in-addr") || strings.Contains(s, "; in-addr")
	return !no_show
}

func removeFirstField(s string, sep string) (string, string) {
	fields := strings.Split(s, sep)

	// Check if there are more than one field
	if len(fields) <= 1 {
		fmt.Printf("s: %s, sep: %s\n", s, sep)
		panic("Too few fields")
	}

	// Join the remaining fields with the separator
	return fields[0], strings.Join(fields[1:], sep)
}

func fqdn(host, domain string) string {
	if host[len(host)-1] == '.' {
		return host
	}

	fqdn := fmt.Sprintf("%s.%s", host, domain)
	if fqdn[len(fqdn)-1] != '.' {
		fqdn += "."
	}

	return fqdn
}

func atoui64(v string) uint64 {
	var u uint64
	var err error
	if u, err = strconv.ParseUint(v, 10, 64); err != nil {
		fmt.Fprintf(os.Stderr, "Parse Error: %s\n", err)
		os.Exit(1)
	}
	return u
}

func stripComments(line string) string {
	commentIndex := strings.IndexByte(line, ';')
	if commentIndex == -1 {
		return line
	}

	return line[:commentIndex]
}

// Save NS RR's, ensuring that each is added only once.
// This is O(n) but n should be *tiny* so there's no need for anything
// fancy here.
func saveNS(ns string) {
	for _, v := range soa.ns {
		if v == ns {
			return
		}
	}
	soa.ns = append(soa.ns, ns)
}

// Find the common domain between two different hostnames
func commonDomain(h1, h2 string) string {
	var common string

	if h1 == "" && h2 == "" {
		panic("NULL hosts")
	}
	if h1 == "" {
		return h2
	}
	if h2 == "" {
		return h1
	}

	a1 := strings.Split(strings.TrimSuffix(h1, "."), ".")
	a2 := strings.Split(strings.TrimSuffix(h2, "."), ".")
	a1len := len(a1)
	a2len := len(a2)
	for {
		if a1len == 0 || a2len == 0 {
			break
		}
		a1len--
		a2len--
		if a1[a1len] != a2[a2len] {
			break
		}
		common = a1[a1len] + "." + common
	}
	return common
}

// Convert a $GENERATE directive for A records to a $GENERATE directive for PTR records.
func ConvertGenerate(directive string) (string, error) {
	fmt.Println(directive)
	parts := strings.Fields(directive)
	if parts[0] != "$GENERATE" || (len(parts) < 6 && parts[3] == "IN" && parts[4] != "A") {
		return "", fmt.Errorf("invalid $GENERATE directive")
	}

	// Parse the range
	rangeParts := strings.Split(parts[1], "-")
	if len(rangeParts) != 2 {
		return "", fmt.Errorf("invalid range in $GENERATE directive")
	}
	start, err := strconv.Atoi(rangeParts[0])
	if err != nil {
		return "", fmt.Errorf("invalid start value in range")
	}
	stopStep := strings.Split(rangeParts[1], "/")
	stop, err := strconv.Atoi(stopStep[0])
	if err != nil {
		return "", fmt.Errorf("invalid stop value in range")
	}
	step := 1
	if len(stopStep) == 2 {
		step, err = strconv.Atoi(stopStep[1])
		if err != nil {
			return "", fmt.Errorf("invalid step value in range")
		}
	}

	// Parse LHS and RHS
	lhs := parts[2]
	rhsTemplate := parts[len(parts)-1]

	ptrDirective := fmt.Sprintf("$GENERATE %d-%d", start, stop)
	if step != 1 {
		ptrDirective += fmt.Sprintf("/%d", step)
	}

	rhsParts := strings.Split(rhsTemplate, ".")
	if len(rhsParts) != 4 {
		return "", fmt.Errorf("invalid IP address format in template")
	}

	reverseTemplate := fmt.Sprintf("%s.%s", rhsParts[3], rhsParts[2])
	ptrDirective += fmt.Sprintf(" %s IN PTR %s", reverseTemplate, fqdn(lhs, soa.domain))

	return ptrDirective, nil
}

// SOA
func (s *soa_t) String() string {
	t := fmt.Sprintf("@\tIN\tSOA\t%s\t%s.%s (\n",
		s.authns, s.contact, s.domain)
	t += fmt.Sprintf("\t\t\t\t%d\t ; Serial\n", s.serial)
	t += fmt.Sprintf("\t\t\t\t%d\t\t ; Refresh\n", s.refresh)
	t += fmt.Sprintf("\t\t\t\t%d\t\t ; Retry\n", s.retry)
	t += fmt.Sprintf("\t\t\t\t%d\t\t ; Expire\n", s.expire)
	t += fmt.Sprintf("\t\t\t\t%d )\t\t ; Minimum\n", s.minimum)
	for _, ns := range s.ns {
		t += fmt.Sprintf("\t\tIN\tNS\t%s\n", ns)
	}
	return t
}

func parseSOA(s string, r *bufio.Reader) {
	var domain string
	var contact string
	var authns string

	splits := strings.Fields(s)
	if len(splits) == 6 && splits[1] == "IN" { // No TTL in SOA
		authns = splits[3]
		contact = splits[4]
	} else { // TTL in SOA
		if ttl == "" {
			ttl = "$TTL " + splits[1]
		}
		authns = splits[4]
		contact = splits[5]
	}

	contact, domain = removeFirstField(contact, ".")
	soa.domain = commonDomain(domain, soa.domain)
	soa.contact = contact
	soa.authns = authns
	saveNS(authns)

	t, err := r.ReadString(')')
	if err != nil {
		panic(err)
	}
	t = commentToEndOfLine.ReplaceAllString(t, "")
	tlist := strings.Split(t, "\n")
	for i := range tlist {
		tlist[i] = strings.TrimSuffix(tlist[i], ")")
		tlist[i] = strings.TrimSpace(tlist[i])

	}

	soa.serial = atoui64(tlist[0])
	soa.refresh = atoui64(tlist[1])
	soa.retry = atoui64(tlist[2])
	soa.expire = atoui64(tlist[3])
	soa.minimum = atoui64(tlist[4])
}

// Zonefile parsing
func parseOneZone(r *bufio.Reader) {
	var lastHost string
	var line uint32

	for {
		line++
		s, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			fmt.Fprintf(os.Stderr, "IO Error: Line %d: %s\n", line, err)
			os.Exit(1)
		}

		s = strings.TrimSpace(s)

		if strings.HasPrefix(s, ";") || strings.HasPrefix(s, "\n") || strings.HasPrefix(s, "$ORIGIN") {
			continue
		}

		s = stripComments(s)

		if strings.HasPrefix(s, "$GENERATE") {
			s, _ := ConvertGenerate(s)
			zone.PushBack(s)
			continue
		}

		if strings.HasPrefix(s, "$INCLUDE") {
			splits := strings.Fields(s)
			zone.PushBack("\n; Processed from $INCLUDE file " + splits[1])
			parseZone(splits[1])
			continue
		}

		if strings.HasPrefix(s, "$TTL") {
			ttl = s
			continue
		}

		if IN_SOA.MatchString(s) {
			parseSOA(s, r)
			lastHost = "SOA"
			continue
		}

		// Save nameservers lists as part of SOA RR
		if IN_NS.MatchString(s) && lastHost == "SOA" {
			splits := strings.Fields(s)
			saveNS(splits[2])
			continue
		}

		// Looking at a complete A RR "host IN A 1.2.3.4"
		if StartsWithLetterOrNumber.MatchString(s) && IN_A.MatchString(s) && okToShow(s) {
			var addr string

			i := strings.IndexAny(s, ";")
			if i != -1 {
				s = s[0:i]
			}

			splits := strings.Fields(s)
			switch len(splits) {
			case 4:
				lastHost = fqdn(splits[0], soa.domain)
				addr = splits[3]
			default:
				fmt.Fprintf(os.Stderr, "Parse Error: line %d\n", line)
				fmt.Fprintf(os.Stderr, "Line: %s\n", s)
				os.Exit(1)
			}

			s := strings.Split(addr, ".")
			zone.PushBack(fmt.Sprintf("%s\t\tIN\tPTR\t\t%s", s[3], lastHost))

			continue
		}
	}
}

func parseZone(inputFile string) {

	in, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("Error opening input file: %v\n", err)
		os.Exit(1)
	}

	r := bufio.NewReader(in)
	parseOneZone(r)
	in.Close()
}

// Generate reverse zone file
func mkarpa(out *os.File, inputNames []string) {

	host, err := os.Hostname()
	if err != nil {
		host = "<unknown>"
	}

	fmt.Fprintln(out, ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;")
	fmt.Fprintf(out, "; Reverse zone file for domain '%s'\n", domain)
	fmt.Fprintf(out, ";\n")
	fmt.Fprintf(out, "; DO NOT EDIT THIS FILE; it is not manually updated\n")
	fmt.Fprintf(out, ";\n")
	fmt.Fprintf(out, "; Generated %s from:\n", time.Now().Format(time.UnixDate))
	for _, input := range inputNames {
		input, _ = filepath.Abs(input)
		fmt.Fprintf(out, ";  %s:%s\n", host, input)
	}
	fmt.Fprintln(out, ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;")
	fmt.Fprintf(out, "%s\n", ttl)
	fmt.Fprintf(out, soa.String())

	fmt.Fprintf(out, "\n$ORIGIN %s\n\n", domain)

	for e := zone.Front(); e != nil; e = e.Next() {
		fmt.Fprintln(out, e.Value)
	}
}

func main() {

	outputFile := flag.String("o", "", "The output file (optional)")
	help := flag.Bool("h", false, "Show help")

	flag.Parse()
	args := flag.Args()

	if len(args) < 2 || *help {
		fmt.Println("Usage: mkarpa [-o <output file>] <reverse_domain> <input file> [<input file> ... ]")
		fmt.Println("Generate a reverse zone file from one or more forward zone files")
		flag.PrintDefaults()
		os.Exit(1)
	}

	domain = args[0]
	args = args[1:]

	// Process all the inputs
	zone = list.New()
	for _, inputFile := range args {
		parseZone(inputFile)
	}

	// Generate output
	var outFile *os.File = os.Stdout
	var err error
	if *outputFile != "" {
		// Output to the specified file
		outFile, err = os.Create(*outputFile)
		if err != nil {
			fmt.Printf("Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	mkarpa(outFile, args)
}
