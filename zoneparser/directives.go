package zoneparser

// EntryType represents the type of zone file entry
type EntryType int

const (
	EntryTypeRecord EntryType = iota
	EntryTypeGenerate
	EntryTypeTTL
	EntryTypeOrigin
	EntryTypeInclude
)

// GenerateDirective represents a $GENERATE directive
type GenerateDirective struct {
	Range     string
	OwnerName string
	RRType    string
	RData     string
	TTL       uint32
	Class     string
	Origin    string
}

// TTLDirective represents a $TTL directive
type TTLDirective struct {
	Value uint32
}

// OriginDirective represents an $ORIGIN directive
type OriginDirective struct {
	Domain string
}

// IncludeDirective represents an $INCLUDE directive
type IncludeDirective struct {
	Filename string
}

// ZoneEntry represents any entry in a zone file
type ZoneEntry struct {
	Type EntryType

	// Entry data - only one of these will be populated based on Type
	HostRecord *HostRecord
	Generate   *GenerateDirective
	TTL        *TTLDirective
	Origin     *OriginDirective
	Include    *IncludeDirective

	// Metadata
	RawLine    string // Raw line for debugging
	SourceFile string // Track which file this entry came from
}

// ZoneData represents all entries in a zone file
type ZoneData []ZoneEntry

// ZoneMetadata holds zone-level information
type ZoneMetadata struct {
	Origin string
	TTL    uint32
}

// Parser holds the parsing state
type Parser struct {
	origin      string
	ttl         uint32
	file        string
	zone        ZoneData
	originFound bool // track if $ORIGIN has been found
	metadata    ZoneMetadata
	ttlWritten  bool // Keep track of whether we've already written $TTL to the zone
}