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
export SPRITE_TOKEN ?= $(or $(shell ./scripts/resolve-sprite-token.sh 2>/dev/null),test-ci-no-flyctl)

# Optional regex for go test -skip (CI-friendly filtering)
TEST_SKIP_PATTERNS ?=
BROWSER_TEST_SKIP_PATTERNS ?=
CI_BROWSER_SKIP_PATTERNS ?= TestBrowser_NotesCRUD_Pagination|TestScreenshot_AllThemes
CPU_COUNT := $(shell nproc 2>/dev/null || echo 4)
GO_TEST_PARALLEL ?= $(CPU_COUNT)
GO_TEST_PACKAGE_PARALLEL ?= $(CPU_COUNT)
RAPID_CHECKS ?= 10
RAPID_CHECKS_FULL ?= 100
RAPID_CHECKS_CONFORMANCE ?= 3
GO_TEST_FULL_TIMEOUT ?= 30m

.PHONY: all build run run-test run-email test test-browser test-all ci test-conformance test-full test-fuzz test-db fmt vet gosec mod-tidy clean deploy help

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
	go test -v ./tests/browser/... $(if $(strip $(BROWSER_TEST_SKIP_PATTERNS)), -skip '$(BROWSER_TEST_SKIP_PATTERNS)',)

## test-all: Run test + browser test suite
test-all:
	$(MAKE) test
	$(MAKE) test-browser

## ci: CI suite (skips conformance + pagination/screenshot browser tests)
ci:
	$(MAKE) test
	$(MAKE) test-browser BROWSER_TEST_SKIP_PATTERNS='$(CI_BROWSER_SKIP_PATTERNS)'

## test-conformance: Run only conformance packages (OpenAI/Claude)
test-conformance:
	@command -v claude >/dev/null 2>&1 || { echo "ERROR: claude CLI required for Claude conformance tests. Install from https://claude.ai/claude-code"; exit 1; }
	@command -v ngrok >/dev/null 2>&1 || { echo "ERROR: ngrok CLI not found"; exit 1; }
	@mkdir -p test-results
	@set -euo pipefail; \
	if [ -f secrets.sh ]; then \
		source secrets.sh; \
	fi; \
	: "$${OPENAI_API_KEY:?ERROR: OPENAI_API_KEY required. Run: source secrets.sh}"; \
	flyctl_bin=""; \
	if command -v flyctl >/dev/null 2>&1; then \
		flyctl_bin="$$(command -v flyctl)"; \
	elif [ -x "$$HOME/.fly/bin/flyctl" ]; then \
		flyctl_bin="$$HOME/.fly/bin/flyctl"; \
	else \
		echo "ERROR: flyctl CLI required for conformance tests"; \
		exit 1; \
	fi; \
	if [ -z "$${SPRITE_TOKEN:-}" ]; then \
		SPRITE_TOKEN="$$(./scripts/resolve-sprite-token.sh)" || { echo "ERROR: resolve-sprite-token.sh failed"; exit 1; }; \
		export SPRITE_TOKEN; \
	fi; \
	echo "Fly apps snapshot (pre-conformance):"; \
	"$$flyctl_bin" apps list || true; \
	if [ -n "$${NGROK_AUTHTOKEN:-}" ]; then \
		ngrok config add-authtoken "$$NGROK_AUTHTOKEN"; \
	elif [ ! -f "$$HOME/.config/ngrok/ngrok.yml" ] || ! rg -q '^\s*authtoken\s*:' "$$HOME/.config/ngrok/ngrok.yml"; then \
		echo "ERROR: NGROK_AUTHTOKEN is not set and ngrok has no configured authtoken."; \
		echo "Run: export NGROK_AUTHTOKEN=\"<your ngrok token>\" && ngrok config add-authtoken \"$$NGROK_AUTHTOKEN\""; \
		exit 1; \
	fi; \
	test_port="$$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"; \
	ngrok_log="$$(mktemp -t ngrok-log-XXXXXX)"; \
	tunnels_json="$$(mktemp -t ngrok-tunnels-XXXXXX)"; \
	ngrok http "$$test_port" --log stdout --log-format=json >"$$ngrok_log" 2>&1 & \
	ngrok_pid="$$!"; \
	cleanup() { \
		kill "$$ngrok_pid" >/dev/null 2>&1 || true; \
		rm -f "$$ngrok_log" "$$tunnels_json"; \
	}; \
	trap cleanup EXIT; \
	public_url=""; \
	for _ in $$(seq 1 40); do \
		if curl -fsS http://127.0.0.1:4040/api/tunnels >"$$tunnels_json" 2>/dev/null; then \
			public_url="$$(python3 -c "import json,sys; data=json.load(open(sys.argv[1])); print(next((t.get('public_url','') for t in data.get('tunnels',[]) if t.get('proto')=='https'), ''))" "$$tunnels_json")"; \
			if [ -n "$$public_url" ]; then \
				break; \
			fi; \
		fi; \
		sleep 0.5; \
	done; \
	if [ -z "$$public_url" ]; then \
		echo "ERROR: failed to discover ngrok public URL"; \
		exit 1; \
	fi; \
	echo "ngrok tunnel URL: $$public_url"; \
	echo "Running conformance packages in parallel with isolated env"; \
	set +e; \
	env -u TEST_PUBLIC_URL -u TEST_LISTEN_PORT \
		go test $(BUILD_TAGS) -v -timeout $(GO_TEST_FULL_TIMEOUT) -p $(GO_TEST_PACKAGE_PARALLEL) -parallel $(GO_TEST_PARALLEL) \
		./tests/e2e/claude -rapid.checks=$(RAPID_CHECKS_CONFORMANCE) & \
	claude_pid="$$!"; \
	TEST_PUBLIC_URL="$$public_url" TEST_LISTEN_PORT="$$test_port" \
		go test $(BUILD_TAGS) -v -timeout $(GO_TEST_FULL_TIMEOUT) -p $(GO_TEST_PACKAGE_PARALLEL) -parallel $(GO_TEST_PARALLEL) \
		./tests/e2e/openai -rapid.checks=$(RAPID_CHECKS_CONFORMANCE) & \
	openai_pid="$$!"; \
	wait "$$claude_pid"; claude_rc="$$?"; \
	wait "$$openai_pid"; openai_rc="$$?"; \
	set -e; \
	if [ "$$claude_rc" -ne 0 ] || [ "$$openai_rc" -ne 0 ]; then \
		echo "ERROR: conformance failures (claude=$$claude_rc, openai=$$openai_rc)"; \
		exit 1; \
	fi; \
	echo "Fly apps snapshot (post-conformance):"; \
	"$$flyctl_bin" apps list || true

## test-full: Full tests with coverage artifacts
test-full:
	@command -v claude >/dev/null 2>&1 || { echo "ERROR: claude CLI required for Claude conformance tests. Install from https://claude.ai/claude-code"; exit 1; }
	@command -v ngrok >/dev/null 2>&1 || { echo "ERROR: ngrok CLI not found"; exit 1; }
	@mkdir -p test-results
	@set -euo pipefail; \
	if [ -f secrets.sh ]; then \
		source secrets.sh; \
	fi; \
	: "$${OPENAI_API_KEY:?ERROR: OPENAI_API_KEY required. Run: source secrets.sh}"; \
	flyctl_bin=""; \
	if command -v flyctl >/dev/null 2>&1; then \
		flyctl_bin="$$(command -v flyctl)"; \
	elif [ -x "$$HOME/.fly/bin/flyctl" ]; then \
		flyctl_bin="$$HOME/.fly/bin/flyctl"; \
	else \
		echo "ERROR: flyctl CLI required for full tests"; \
		exit 1; \
	fi; \
	if [ -z "$${SPRITE_TOKEN:-}" ]; then \
		SPRITE_TOKEN="$$(./scripts/resolve-sprite-token.sh)" || { echo "ERROR: resolve-sprite-token.sh failed"; exit 1; }; \
		export SPRITE_TOKEN; \
	fi; \
	echo "Fly apps snapshot (pre-full-test):"; \
	"$$flyctl_bin" apps list || true; \
	if [ -n "$${NGROK_AUTHTOKEN:-}" ]; then \
		ngrok config add-authtoken "$$NGROK_AUTHTOKEN"; \
	elif [ ! -f "$$HOME/.config/ngrok/ngrok.yml" ] || ! rg -q '^\s*authtoken\s*:' "$$HOME/.config/ngrok/ngrok.yml"; then \
		echo "ERROR: NGROK_AUTHTOKEN is not set and ngrok has no configured authtoken."; \
		echo "Run: export NGROK_AUTHTOKEN=\"<your ngrok token>\" && ngrok config add-authtoken \"$$NGROK_AUTHTOKEN\""; \
		exit 1; \
	fi; \
	test_port="$$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"; \
	ngrok_log="$$(mktemp -t ngrok-log-XXXXXX)"; \
	tunnels_json="$$(mktemp -t ngrok-tunnels-XXXXXX)"; \
	ngrok http "$$test_port" --log stdout --log-format=json >"$$ngrok_log" 2>&1 & \
	ngrok_pid="$$!"; \
	cleanup() { \
		kill "$$ngrok_pid" >/dev/null 2>&1 || true; \
		tail -n 200 "$$ngrok_log" || true; \
		rm -f "$$ngrok_log" "$$tunnels_json"; \
	}; \
	trap cleanup EXIT; \
	public_url=""; \
	for _ in $$(seq 1 40); do \
		if curl -fsS http://127.0.0.1:4040/api/tunnels >"$$tunnels_json" 2>/dev/null; then \
			public_url="$$(python3 -c "import json,sys; data=json.load(open(sys.argv[1])); print(next((t.get('public_url','') for t in data.get('tunnels',[]) if t.get('proto')=='https'), ''))" "$$tunnels_json")"; \
			if [ -n "$$public_url" ]; then \
				break; \
			fi; \
		fi; \
		sleep 0.5; \
	done; \
	if [ -z "$$public_url" ]; then \
		echo "ERROR: failed to discover ngrok public URL"; \
		exit 1; \
	fi; \
	echo "ngrok tunnel URL: $$public_url"; \
	export TEST_PUBLIC_URL="$$public_url"; \
	export TEST_LISTEN_PORT="$$test_port"; \
	run_id="$$(date -u +%Y%m%dT%H%M%S)-$$-$$RANDOM"; \
	log_path="test-results/full-test-$${run_id}.log"; \
	coverage_out="test-results/coverage-$${run_id}.out"; \
	coverage_html="test-results/coverage-$${run_id}.html"; \
		rapid_packages="$$(go list ./... | grep -v 'tests/e2e/claude' | grep -v 'tests/e2e/openai' | grep -v 'tests/browser')"; \
		browser_packages="$$(go list ./tests/browser/...)"; \
		echo "Writing full test log to $$log_path"; \
		{ \
			echo "Running non-conformance packages with -rapid.checks=$(RAPID_CHECKS_FULL)"; \
			go test $(BUILD_TAGS) -v -timeout $(GO_TEST_FULL_TIMEOUT) -p $(GO_TEST_PACKAGE_PARALLEL) -parallel $(GO_TEST_PARALLEL) -coverprofile="$$coverage_out" -coverpkg=./... \
				$$rapid_packages -rapid.checks=$(RAPID_CHECKS_FULL); \
			echo "Running browser packages"; \
			go test -v -timeout $(GO_TEST_FULL_TIMEOUT) -p $(GO_TEST_PACKAGE_PARALLEL) -parallel $(GO_TEST_PARALLEL) \
				$$browser_packages; \
			echo "Running conformance packages with -rapid.checks=$(RAPID_CHECKS_CONFORMANCE)"; \
			set +e; \
			env -u TEST_PUBLIC_URL -u TEST_LISTEN_PORT \
				go test $(BUILD_TAGS) -v -timeout $(GO_TEST_FULL_TIMEOUT) -p $(GO_TEST_PACKAGE_PARALLEL) -parallel $(GO_TEST_PARALLEL) \
				./tests/e2e/claude -rapid.checks=$(RAPID_CHECKS_CONFORMANCE) & \
			claude_pid="$$!"; \
			TEST_PUBLIC_URL="$$public_url" TEST_LISTEN_PORT="$$test_port" \
				go test $(BUILD_TAGS) -v -timeout $(GO_TEST_FULL_TIMEOUT) -p $(GO_TEST_PACKAGE_PARALLEL) -parallel $(GO_TEST_PARALLEL) \
				./tests/e2e/openai -rapid.checks=$(RAPID_CHECKS_CONFORMANCE) & \
			openai_pid="$$!"; \
			wait "$$claude_pid"; claude_rc="$$?"; \
			wait "$$openai_pid"; openai_rc="$$?"; \
			set -e; \
			if [ "$$claude_rc" -ne 0 ] || [ "$$openai_rc" -ne 0 ]; then \
				echo "ERROR: conformance failures (claude=$$claude_rc, openai=$$openai_rc)"; \
				exit 1; \
			fi; \
	} 2>&1 | tee "$$log_path"; \
	go tool cover -html="$$coverage_out" -o "$$coverage_html"; \
	go tool cover -func="$$coverage_out"; \
	cp "$$log_path" test-results/full-test.log; \
	cp "$$coverage_out" test-results/coverage.out; \
	cp "$$coverage_html" test-results/coverage.html; \
	ln -sfn "$$(basename "$$log_path")" test-results/full-test.latest.log; \
	ln -sfn "$$(basename "$$coverage_out")" test-results/coverage.latest.out; \
	ln -sfn "$$(basename "$$coverage_html")" test-results/coverage.latest.html; \
	echo "Fly apps snapshot (post-full-test):"; \
	"$$flyctl_bin" apps list || true

## test-fuzz: Fuzz testing (30+ min, coverage-guided)
test-fuzz:
	./scripts/fuzz.sh fuzz

## test-db: Run database layer tests only
test-db:
	@echo "Running database layer tests with FTS5 support..."
	go test $(BUILD_TAGS) -v -count=1 ./internal/db/

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
