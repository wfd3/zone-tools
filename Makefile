# Makefile for zone-tools project

# Go compiler
GO := go

# Binary names
BINARIES := dhcpgen mkarpa mkkea parser

# Default target
.PHONY: all
all: $(BINARIES) test

# Build individual binaries
dhcpgen: dhcpgen.go
	$(GO) build -o dhcpgen dhcpgen.go

mkkea: mkkea.go
	$(GO) build -o mkkea mkkea.go

parser: parser_example.go
	$(GO) build -o parser parser_example.go

mkarpa: mkarpa.go
	$(GO) build -o mkarpa mkarpa.go

# Run tests
.PHONY: test
test:
	$(GO) test -v ./zoneparser

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	$(GO) test -v -cover ./zoneparser

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARIES)

# Install binaries to GOPATH/bin
.PHONY: install
install: $(BINARIES)
	$(GO) install ./...

# Format all Go source files
.PHONY: fmt
fmt:
	$(GO) fmt ./...

# Vet all Go source files
.PHONY: vet
vet:
	$(GO) vet ./dhcpgen.go
	$(GO) vet ./mkarpa.go
	$(GO) vet ./mkkea.go
	$(GO) vet ./parser_example.go
	$(GO) vet ./mkarpa.go
	$(GO) vet ./zoneparser

# Run all quality checks
.PHONY: check
check: fmt vet test

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all           - Build all binaries and run tests"
	@echo "  dhcpgen       - Build DHCP configuration generator"
	@echo "  mkarpa        - Build reverse zone file generator"
	@echo "  mkkea         - Build KEA DHCP configuration generator"
	@echo "  parser        - Build zone parser example"
	@echo "  mkarpa3       - Build reverse zone generator (using zoneparser library)"
	@echo "  test          - Run all tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  clean         - Remove build artifacts"
	@echo "  install       - Install binaries to GOPATH/bin"
	@echo "  fmt           - Format all Go source files"
	@echo "  vet           - Vet all Go source files"
	@echo "  check         - Run fmt, vet, and test"
	@echo "  help          - Show this help message"