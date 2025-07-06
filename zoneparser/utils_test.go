package zoneparser

import (
	"reflect"
	"testing"
)

func TestTokenizeWithQuotes(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    `simple text`,
			expected: []string{"simple", "text"},
		},
		{
			input:    `"quoted text" unquoted`,
			expected: []string{`"quoted text"`, "unquoted"},
		},
		{
			input:    `"quoted with spaces" another "quoted string"`,
			expected: []string{`"quoted with spaces"`, "another", `"quoted string"`},
		},
		{
			input:    `"quoted;with;semicolons" unquoted;comment`,
			expected: []string{`"quoted;with;semicolons"`, "unquoted;comment"},
		},
		{
			input:    `multiple    spaces    between`,
			expected: []string{"multiple", "spaces", "between"},
		},
		{
			input:    `"empty quotes" "" more`,
			expected: []string{`"empty quotes"`, `""`, "more"},
		},
	}

	for _, test := range tests {
		result := tokenizeWithQuotes(test.input)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("tokenizeWithQuotes(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestExtractTXTContent(t *testing.T) {
	tests := []struct {
		input    []string
		expected string
	}{
		{
			input:    []string{`"hello world"`},
			expected: "hello world",
		},
		{
			input:    []string{`"multiple"`, `"quoted"`, `"strings"`},
			expected: `"multiple" "quoted" "strings"`,
		},
		{
			input:    []string{"unquoted", "text"},
			expected: "unquoted text",
		},
		{
			input:    []string{`"mixed"`, "unquoted", `"strings"`},
			expected: `"mixed" unquoted "strings"`,
		},
		{
			input:    []string{},
			expected: "",
		},
		{
			input:    []string{`""`},
			expected: "",
		},
	}

	for _, test := range tests {
		result := extractTXTContent(test.input)
		if result != test.expected {
			t.Errorf("extractTXTContent(%v) = %q, expected %q", test.input, result, test.expected)
		}
	}
}

func TestQualifyDomainName(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		expected string
	}{
		{
			name:     "@",
			origin:   "example.com.",
			expected: "example.com.",
		},
		{
			name:     "www",
			origin:   "example.com.",
			expected: "www.example.com.",
		},
		{
			name:     "mail.example.com.",
			origin:   "example.com.",
			expected: "mail.example.com.",
		},
		{
			name:     "subdomain",
			origin:   "example.com.",
			expected: "subdomain.example.com.",
		},
		{
			name:     "external.org.",
			origin:   "example.com.",
			expected: "external.org.",
		},
	}

	for _, test := range tests {
		result := qualifyDomainName(test.name, test.origin)
		if result != test.expected {
			t.Errorf("qualifyDomainName(%q, %q) = %q, expected %q", test.name, test.origin, result, test.expected)
		}
	}
}

func TestIsNumeric(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"123", true},
		{"0", true},
		{"86400", true},
		{"abc", false},
		{"12.34", false},
		{"-123", false},
		{"", false},
		{"123abc", false},
		{"4294967295", true}, // Max uint32
	}

	for _, test := range tests {
		result := isNumeric(test.input)
		if result != test.expected {
			t.Errorf("isNumeric(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestIsKnownRRType(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"A", true},
		{"AAAA", true},
		{"CNAME", true},
		{"MX", true},
		{"TXT", true},
		{"NS", true},
		{"SOA", true},
		{"PTR", true},
		{"SRV", true},
		{"CAA", true},
		{"HINFO", true},
		{"NAPTR", true},
		{"SPF", true},
		{"UNKNOWN", false},
		{"a", false}, // case sensitive
		{"", false},
		{"TYPE123", false},
	}

	for _, test := range tests {
		result := isKnownRRType(test.input)
		if result != test.expected {
			t.Errorf("isKnownRRType(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestContainsUnquotedParenthesis(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"simple text", false},
		{"text with (parentheses)", true},
		{"text with ) closing paren", true},
		{`"quoted (parentheses)" outside`, false},
		{`before "quoted (text)" after (unquoted)`, true},
		{`"all (parentheses) quoted"`, false},
		{"", false},
		{"(", true},
		{")", true},
		{`"(quoted)"`, false},
	}

	for _, test := range tests {
		result := containsUnquotedParenthesis(test.input)
		if result != test.expected {
			t.Errorf("containsUnquotedParenthesis(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestParseLineWithComments(t *testing.T) {
	tests := []struct {
		input           string
		expectedClean   string
		expectedComment string
	}{
		{
			input:           "simple line without comment",
			expectedClean:   "simple line without comment",
			expectedComment: "",
		},
		{
			input:           "line with ; comment",
			expectedClean:   "line with",
			expectedComment: "comment",
		},
		{
			input:           `"quoted ; semicolon" ; real comment`,
			expectedClean:   `"quoted ; semicolon"`,
			expectedComment: "real comment",
		},
		{
			input:           `text "quoted ; text" more ; comment`,
			expectedClean:   `text "quoted ; text" more`,
			expectedComment: "comment",
		},
		{
			input:           "; just a comment",
			expectedClean:   "",
			expectedComment: "just a comment",
		},
		{
			input:           `"all ; quoted ; text"`,
			expectedClean:   `"all ; quoted ; text"`,
			expectedComment: "",
		},
	}

	for _, test := range tests {
		clean, comment := parseLineWithComments(test.input)
		if clean != test.expectedClean {
			t.Errorf("parseLineWithComments(%q) clean = %q, expected %q", test.input, clean, test.expectedClean)
		}
		if comment != test.expectedComment {
			t.Errorf("parseLineWithComments(%q) comment = %q, expected %q", test.input, comment, test.expectedComment)
		}
	}
}

func TestFindCommentStart(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"no comment", -1},
		{"text ; comment", 5},
		{`"quoted ; text" ; comment`, 16},
		{`"all ; quoted ; text"`, -1},
		{"; starts with comment", 0},
		{`"quote at end" ;`, 15},
	}

	for _, test := range tests {
		result := findCommentStart(test.input)
		if result != test.expected {
			t.Errorf("findCommentStart(%q) = %d, expected %d", test.input, result, test.expected)
		}
	}
}

func TestValidateRecordData(t *testing.T) {
	tests := []struct {
		rrType    string
		data      []string
		minFields int
		expectErr bool
	}{
		{"A", []string{"192.168.1.1"}, 1, false},
		{"A", []string{}, 1, true},
		{"MX", []string{"10", "mail.example.com"}, 2, false},
		{"MX", []string{"10"}, 2, true},
		{"SOA", []string{"ns", "admin", "1", "2", "3", "4", "5"}, 7, false},
		{"SOA", []string{"ns", "admin", "1"}, 7, true},
	}

	for _, test := range tests {
		err := validateRecordData(test.rrType, test.data, test.minFields)
		hasErr := err != nil
		if hasErr != test.expectErr {
			t.Errorf("validateRecordData(%q, %v, %d) error = %v, expected error = %v", 
				test.rrType, test.data, test.minFields, hasErr, test.expectErr)
		}
	}
}

func TestTokenize(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    "simple words",
			expected: []string{"simple", "words"},
		},
		{
			input:    `"quoted text" normal`,
			expected: []string{`"quoted text"`, "normal"},
		},
		{
			input:    "  multiple   spaces  ",
			expected: []string{"multiple", "spaces"},
		},
		{
			input:    "",
			expected: []string{},
		},
	}

	for _, test := range tests {
		result := tokenize(test.input)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("tokenize(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestReplacePlaceholders(t *testing.T) {
	tests := []struct {
		input    string
		iter     int
		expected string
	}{
		{
			input:    "host$",
			iter:     5,
			expected: "host5",
		},
		{
			input:    "host${10,3,d}",
			iter:     5,
			expected: "host015", // 5 + 10 = 15, padded to 3 digits
		},
		{
			input:    "host${0,0,d}",
			iter:     42,
			expected: "host42",
		},
		{
			input:    "host${5,2,x}",
			iter:     10,
			expected: "host0f", // 10 + 5 = 15 = 0xf, padded to 2 chars
		},
		{
			input:    "prefix$suffix${1,3,d}end",
			iter:     7,
			expected: "prefix7suffix008end", // 7 + 1 = 8, padded to 3 digits
		},
		{
			input:    "no placeholders here",
			iter:     123,
			expected: "no placeholders here",
		},
	}

	for _, test := range tests {
		result := replacePlaceholders(test.input, test.iter)
		if result != test.expected {
			t.Errorf("replacePlaceholders(%q, %d) = %q, expected %q", 
				test.input, test.iter, result, test.expected)
		}
	}
}

func TestLog(t *testing.T) {
	// Test that Log doesn't panic when DEBUG is false
	Log("test message")
	Log("test with args: %s %d", "string", 42)
	
	// We can't easily test the output without changing the global DEBUG flag
	// but we can at least verify it doesn't crash
}