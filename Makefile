.PHONY: all build test test-db clean help check fmt vet gosec mod-tidy

# Go parameters - use goenv
GOENV_ROOT := $(HOME)/.goenv
GOENV_BIN := $(GOENV_ROOT)/shims
GOCMD := $(GOENV_BIN)/go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOCLEAN := $(GOCMD) clean
GOFMT := $(GOCMD) fmt
GOVET := $(GOCMD) vet
GOMOD := $(GOCMD) mod
GOSEC := $(GOENV_BIN)/gosec

# CGO parameters for SQLCipher with FTS5 support
export CGO_ENABLED=1
export CGO_CFLAGS=-DSQLITE_ENABLE_FTS5
export CGO_LDFLAGS=-lm

# Build tags required for go-sqlcipher FTS5 support
BUILD_TAGS=-tags fts5

# Build output
BINARY_NAME=agent-notes
BINARY_PATH=./bin/$(BINARY_NAME)

all: test build

## check: Run fmt, vet, gosec, and mod tidy (runs before every build)
check: fmt vet gosec mod-tidy

## build: Build the application binary (runs fmt/vet/mod-tidy first)
build: check
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) $(BUILD_TAGS) -o $(BINARY_PATH) ./cmd/server/

## test: Run all tests (runs fmt/vet/mod-tidy first)
test: check
	@echo "Running all tests with FTS5 support..."
	$(GOTEST) $(BUILD_TAGS) -v -count=1 ./...

## test-db: Run database layer tests only
test-db: check
	@echo "Running database layer tests with FTS5 support..."
	$(GOTEST) $(BUILD_TAGS) -v -count=1 ./internal/db/

## test-coverage: Run tests with coverage report
test-coverage: check
	@echo "Running tests with coverage..."
	$(GOTEST) $(BUILD_TAGS) -v -count=1 -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## clean: Clean build artifacts and test data
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BINARY_PATH)
	rm -rf ./data/
	rm -rf ./internal/db/testdata/
	rm -rf ./tests/e2e/testdata/
	rm -f coverage.out coverage.html

## fmt: Format Go code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

## gosec: Run security scanner
## Excludes:
##   G101 - false positives on sqlc query names containing "password"
##   G203 - template.HTML with bluemonday-sanitized content is safe
##   G407 - nonce is randomly generated but gosec can't trace dataflow
## Only fails on medium+ severity (G104 unhandled Close in error paths is low)
gosec:
	@echo "Running gosec security scan..."
	@$(GOSEC) -quiet -severity=medium -exclude=G101,G203,G407 -exclude-dir=internal/db/sessions -exclude-dir=internal/db/userdb ./...

## mod-tidy: Tidy up go.mod
mod-tidy:
	@echo "Tidying go.mod..."
	$(GOMOD) tidy

## help: Show this help message
help:
	@echo "Available targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /'
