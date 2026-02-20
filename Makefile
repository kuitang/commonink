# Go environment setup via goenv
export GOENV_ROOT := $(HOME)/.goenv
export PATH := $(GOENV_ROOT)/bin:$(GOENV_ROOT)/shims:$(PATH)
SHELL := /bin/bash

# CGO flags required for SQLCipher + FTS5
export CGO_ENABLED := 1
export CGO_CFLAGS := -DSQLITE_ENABLE_FTS5
export CGO_LDFLAGS := -lm

# Build tags required for go-sqlcipher FTS5 support
BUILD_TAGS := -tags fts5

# Build output
BINARY_NAME := server
BINARY_PATH := ./bin/$(BINARY_NAME)

# Identifiers and URLs (not secrets - safe to commit)
export GOOGLE_CLIENT_ID := 194850132916-dkdltj0gjc9t7inllg2cuvk30inuulen.apps.googleusercontent.com
export RESEND_FROM_EMAIL := onboarding@resend.dev
export AWS_ENDPOINT_URL_S3 :=
export AWS_REGION := auto
export BUCKET_NAME := commonink-public
export S3_PUBLIC_URL :=
export LISTEN_ADDR := :8080

# Deterministic test secrets (safe to commit - only used for local testing)
# These propagate to all child processes (go test, subprocess servers) via os.Environ().
# `make run` overrides these by sourcing secrets.sh in a subshell.
export MASTER_KEY := aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export OAUTH_HMAC_SECRET := bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
export OAUTH_SIGNING_KEY := cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

# Optional regex for go test -skip (CI-friendly filtering)
TEST_SKIP_PATTERNS ?=
BROWSER_TEST_SKIP_PATTERNS ?=
CPU_COUNT := $(shell nproc 2>/dev/null || echo 4)
GO_TEST_PARALLEL ?= $(CPU_COUNT)
GO_TEST_PACKAGE_PARALLEL ?= $(CPU_COUNT)
RAPID_CHECKS ?= 10
GO_TEST_FULL_TIMEOUT ?= 30m

.PHONY: all build run run-test run-email test test-browser test-all test-full test-fuzz test-db test-coverage fmt vet gosec mod-tidy clean deploy help

all: test build

## build: Build the server binary
build: fmt mod-tidy
	@echo "Building $(BINARY_NAME)..."
	go build $(BUILD_TAGS) -o $(BINARY_PATH) ./cmd/server/

## run: Run with ALL real services (requires secrets.sh)
run: build
	@if [ ! -f secrets.sh ]; then echo "ERROR: secrets.sh not found. Copy secrets.sh.example and fill in values."; exit 1; fi
	@bash -c 'source secrets.sh && $(BINARY_PATH)'

## run-test: Run with all mocks (deterministic test secrets from Makefile)
## Uses separate data-test/ directory to avoid key conflicts with `make run`
run-test: build
	rm -rf ./data-test/
	DATABASE_PATH=./data-test $(BINARY_PATH) --test

## run-email: Run with real email only (mock OIDC + S3)
run-email: build
	@if [ ! -f secrets.sh ]; then echo "ERROR: secrets.sh not found. Copy secrets.sh.example and fill in values."; exit 1; fi
	@bash -c 'source secrets.sh && $(BINARY_PATH) --no-oidc --no-s3'

## test: Quick tests (rapid property tests, excludes e2e conformance + browser)
test:
	go test $(BUILD_TAGS) -v -timeout 120s -p $(GO_TEST_PACKAGE_PARALLEL) -parallel $(GO_TEST_PARALLEL) \
		$$(go list ./... | grep -v 'tests/e2e/claude' | grep -v 'tests/e2e/openai' | grep -v 'tests/browser') \
		-run 'Test' -rapid.checks=$(RAPID_CHECKS) $(if $(strip $(TEST_SKIP_PATTERNS)), -skip '$(TEST_SKIP_PATTERNS)',)

## test-browser: Run browser tests (Playwright)
test-browser:
	go run github.com/playwright-community/playwright-go/cmd/playwright install --with-deps chromium
	go test -v ./tests/browser/... $(if $(strip $(BROWSER_TEST_SKIP_PATTERNS)), -skip '$(BROWSER_TEST_SKIP_PATTERNS)',)

## test-all: Run test + browser test suite
test-all:
	$(MAKE) test
	$(MAKE) test-browser

## test-full: Full tests with coverage (requires OPENAI_API_KEY, claude CLI, + Playwright)
test-full:
	@if [ -z "$$OPENAI_API_KEY" ]; then echo "ERROR: OPENAI_API_KEY required. Run: source secrets.sh"; exit 1; fi
	@if ! command -v claude >/dev/null 2>&1; then echo "ERROR: claude CLI required for Claude conformance tests. Install from https://claude.ai/claude-code"; exit 1; fi
	go run github.com/playwright-community/playwright-go/cmd/playwright install --with-deps chromium
	@mkdir -p test-results
	@set -euo pipefail; \
	run_id="$$(date -u +%Y%m%dT%H%M%S)-$$-$$RANDOM"; \
	log_path="test-results/full-test-$${run_id}.log"; \
	coverage_out="test-results/coverage-$${run_id}.out"; \
	coverage_html="test-results/coverage-$${run_id}.html"; \
	echo "Writing full test log to $$log_path"; \
	go test $(BUILD_TAGS) -v -timeout $(GO_TEST_FULL_TIMEOUT) -rapid.checks=$(RAPID_CHECKS) -p $(GO_TEST_PACKAGE_PARALLEL) -parallel $(GO_TEST_PARALLEL) -coverprofile="$$coverage_out" -coverpkg=./... \
		./... \
		2>&1 | tee "$$log_path"; \
	go tool cover -html="$$coverage_out" -o "$$coverage_html"; \
	go tool cover -func="$$coverage_out"; \
	cp "$$log_path" test-results/full-test.log; \
	cp "$$coverage_out" test-results/coverage.out; \
	cp "$$coverage_html" test-results/coverage.html; \
	ln -sfn "$$(basename "$$log_path")" test-results/full-test.latest.log; \
	ln -sfn "$$(basename "$$coverage_out")" test-results/coverage.latest.out; \
	ln -sfn "$$(basename "$$coverage_html")" test-results/coverage.latest.html

## test-fuzz: Fuzz testing (30+ min, coverage-guided)
test-fuzz:
	./scripts/fuzz.sh fuzz

## test-db: Run database layer tests only
test-db:
	@echo "Running database layer tests with FTS5 support..."
	go test $(BUILD_TAGS) -v -count=1 ./internal/db/

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	go test $(BUILD_TAGS) -v -count=1 -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## fmt: Format Go code
fmt:
	@echo "Formatting code..."
	go fmt ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...

## gosec: Run security scanner
gosec:
	@echo "Running gosec security scan..."
	@gosec -quiet -severity=medium -exclude=G101,G203,G407 -exclude-dir=internal/db/sessions -exclude-dir=internal/db/userdb ./...

## mod-tidy: Tidy up go.mod
mod-tidy:
	@echo "Tidying go.mod..."
	go mod tidy

## clean: Remove build artifacts and test data
clean:
	rm -rf bin/ test-results/
	rm -rf ./data/ ./data-test/
	rm -rf ./internal/db/testdata/
	rm -rf ./tests/e2e/testdata/
	rm -f coverage.out coverage.html

## deploy: Deploy to Fly.io
deploy:
	./scripts/deploy.sh

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
