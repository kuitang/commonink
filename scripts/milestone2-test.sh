#!/bin/bash
# Milestone 2 Test Script
# Runs all property tests and integration tests for auth + encryption

set -e

# Initialize goenv (REQUIRED per CLAUDE.md)
export GOENV_ROOT="$HOME/.goenv"
export PATH="$GOENV_ROOT/bin:$PATH"
eval "$(goenv init -)"

echo "======================================="
echo "Milestone 2 Test Suite"
echo "======================================="
echo ""

# Verify Go version
echo "Go version: $(go version)"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local name="$1"
    local cmd="$2"

    echo -e "${YELLOW}Running: $name${NC}"
    if eval "$cmd"; then
        echo -e "${GREEN}✓ PASSED: $name${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAILED: $name${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo ""
}

echo "======================================="
echo "1. Unit/Property Tests"
echo "======================================="

# Crypto tests
run_test "Crypto property tests" "go test -v ./internal/crypto/..."

# Auth tests (session, user, password)
run_test "Auth property tests" "go test -v ./internal/auth/..."

echo "======================================="
echo "2. Integration Tests"
echo "======================================="

# Integration tests (if they exist)
if [ -d "tests/auth" ]; then
    run_test "Auth integration tests" "go test -v ./tests/auth/..."
fi

echo "======================================="
echo "3. Build Verification"
echo "======================================="

run_test "Full build" "go build ./..."

echo "======================================="
echo "4. Go vet (static analysis)"
echo "======================================="

run_test "Go vet" "go vet ./..."

echo "======================================="
echo "RESULTS"
echo "======================================="
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}MILESTONE 2 TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}MILESTONE 2 TESTS PASSED${NC}"
    exit 0
fi
