package zoneparser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Configuration constants
const (
	DEBUG = false
	
	// Record parsing constants
	MinRecordTokens    = 3
	QuoteChar          = '"'
	CommentChar        = ';'
	ParenOpen          = '('
	ParenClose         = ')'
	
	// Special comments
	InAddrComment      = "inaddr"
	InAddrAltComment   = "in-addr"
	
	// DNS class
	ClassIN            = "IN"
	
	// Quote counting for validation
	MinQuoteCount      = 2
)

// knownRRTypes defines the set of known DNS record types
var knownRRTypes = map[string]bool{
	"A":     true,
	"AAAA":  true,
	"CNAME": true,
	"MX":    true,
	"TXT":   true,
	"NS":    true,
	"SOA":   true,
	"PTR":   true,
	"SRV":   true,
	"CAA":   true,
	"HINFO": true,
	"NAPTR": true,
	"SPF":   true,
}

// Log prints debug messages if DEBUG is enabled
func Log(format string, args ...interface{}) {
	if DEBUG {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

// tokenizeWithQuotes tokenizes a string while respecting quoted sections
func tokenizeWithQuotes(s string) []string {
	var result []string
	var currentToken strings.Builder
	inQuotes := false

	// Convert multiple spaces/tabs to a single space for easier processing
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")

	for i := 0; i < len(s); i++ {
		char := s[i]

		if char == '"' {
			// Toggle quote state and add the quote character
			inQuotes = !inQuotes
			currentToken.WriteByte(char)
		} else if char == ' ' && !inQuotes {
			// End of token (when not in quotes)
			if currentToken.Len() > 0 {
				result = append(result, currentToken.String())
				currentToken.Reset()
			}
		} else {
			// Add character to current token
			currentToken.WriteByte(char)
		}
	}

	// Add the last token if exists
	if currentToken.Len() > 0 {
		result = append(result, currentToken.String())
	}

	return result
}

// extractTXTContent extracts the content from TXT record data
func extractTXTContent(data []string) string {
	if len(data) == 0 {
		return ""
	}

	// Join all data tokens into one string
	content := strings.Join(data, " ")
	
	// Only remove quotes if there's a single pair wrapping the entire content
	// and no internal quotes (which would indicate multiple quoted segments)
	if strings.HasPrefix(content, "\"") && strings.HasSuffix(content, "\"") && len(content) >= 2 {
		// Count quotes to determine if this is a single quoted string or multiple
		quoteCount := strings.Count(content, "\"")
		if quoteCount == 2 {
			// Only two quotes total, so remove the wrapping quotes
			content = content[1 : len(content)-1]
		}
		// If more than 2 quotes, preserve all quotes as they represent multiple quoted segments
	}
	
	return content
}

// qualifyDomainName ensures a domain name is fully qualified within the current origin
func qualifyDomainName(name, origin string) string {
	if name == "@" {
		return origin
	}
	
	if !strings.HasSuffix(name, ".") {
		return name + "." + origin
	}
	
	return name
}

// isNumeric checks if a string is numeric
func isNumeric(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

// isKnownRRType checks if a string is a known DNS record type
func isKnownRRType(s string) bool {
	return knownRRTypes[s]
}

// containsUnquotedParenthesis checks if a line contains unquoted parentheses
func containsUnquotedParenthesis(line string) bool {
	inQuotes := false
	for _, char := range line {
		if char == '"' {
			inQuotes = !inQuotes
		} else if !inQuotes && (char == '(' || char == ')') {
			return true
		}
	}
	return false
}

// parseLineWithComments separates a line into content and comment
func parseLineWithComments(line string) (cleanLine, comment string) {
	commentStart := findCommentStart(line)
	if commentStart == -1 {
		return line, ""
	}
	
	cleanLine = strings.TrimSpace(line[:commentStart])
	comment = strings.TrimSpace(line[commentStart+1:])
	return cleanLine, comment
}

// findCommentStart finds the start of a comment that's not inside quotes
func findCommentStart(line string) int {
	inQuotes := false
	for i, char := range line {
		if char == '"' {
			inQuotes = !inQuotes
		} else if !inQuotes && char == ';' {
			return i
		}
	}
	return -1
}

// removeCommentsRespectingQuotes removes comments while preserving semicolons inside quotes
func removeCommentsRespectingQuotes(line string) string {
	cleanLine, _ := parseLineWithComments(line)
	return cleanLine
}

// validateRecordData validates that record data has the minimum required fields
func validateRecordData(rrType string, data []string, minFields int) error {
	if len(data) < minFields {
		return fmt.Errorf("%s record requires at least %d field(s), got %d", rrType, minFields, len(data))
	}
	return nil
}

// tokenize splits a line into tokens, using quote-aware tokenization if quotes are present
func tokenize(line string) []string {
	// If line contains quotes, use quote-aware tokenization
	if strings.Contains(line, "\"") {
		return tokenizeWithQuotes(line)
	}
	
	// Otherwise use simple field splitting
	return strings.Fields(line)
}

// replacePlaceholders replaces $GENERATE placeholders with the iterator value
func replacePlaceholders(s string, iter int) string {
	result := s

	// First handle complex ${offset,width,format} placeholders
	re := regexp.MustCompile(`\$\{(\d+),(\d+),([dxX])\}`)
	matches := re.FindAllStringSubmatch(result, -1)
	
	for _, match := range matches {
		placeholder := match[0]
		offset, _ := strconv.Atoi(match[1])
		width, _ := strconv.Atoi(match[2])
		format := match[3]
		
		value := iter + offset
		var replacement string
		
		switch format {
		case "d":
			if width > 0 {
				replacement = fmt.Sprintf("%0*d", width, value)
			} else {
				replacement = strconv.Itoa(value)
			}
		case "x":
			if width > 0 {
				replacement = fmt.Sprintf("%0*x", width, value)
			} else {
				replacement = fmt.Sprintf("%x", value)
			}
		}
		
		result = strings.Replace(result, placeholder, replacement, 1)
	}

	// Then handle simple $ placeholders
	result = strings.ReplaceAll(result, "$", strconv.Itoa(iter))

	return result
}