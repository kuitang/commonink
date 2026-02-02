.PHONY: all build test test-db clean help

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean

# CGO parameters for SQLCipher with FTS5 support
export CGO_ENABLED=1
export CGO_CFLAGS=-DSQLITE_ENABLE_FTS5
export CGO_LDFLAGS=-lm
export PATH:=/usr/local/go/bin:$(PATH)

# Build output
BINARY_NAME=agent-notes
BINARY_PATH=./bin/$(BINARY_NAME)

all: test build

## build: Build the application binary
build:
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) -o $(BINARY_PATH) ./cmd/server/

## test: Run all tests
test:
	@echo "Running all tests with FTS5 support..."
	$(GOTEST) -v -count=1 ./...

## test-db: Run database layer tests only
test-db:
	@echo "Running database layer tests with FTS5 support..."
	$(GOTEST) -v -count=1 ./internal/db/

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -count=1 -coverprofile=coverage.out ./...
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
	$(GOCMD) fmt ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOCMD) vet ./...

## mod-tidy: Tidy up go.mod
mod-tidy:
	@echo "Tidying go.mod..."
	$(GOCMD) mod tidy

## help: Show this help message
help:
	@echo "Available targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /'
