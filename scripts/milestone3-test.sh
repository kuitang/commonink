#!/usr/bin/env bash
# Milestone 3 Test Script
# Runs rate limit tests, public notes tests, all unit tests with coverage
# Outputs coverage report to test-results/

set -euo pipefail

# Initialize goenv (REQUIRED per CLAUDE.md)
export GOENV_ROOT="$HOME/.goenv"
export PATH="$GOENV_ROOT/bin:$PATH"
eval "$(goenv init -)"

echo "=== Milestone 3 Test Suite ==="
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

# Create test-results directory if needed
mkdir -p test-results

run_test() {
    local name="$1"
    local cmd="$2"

    echo -e "${YELLOW}Running: $name${NC}"
    if eval "$cmd"; then
        echo -e "${GREEN}PASSED: $name${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}FAILED: $name${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo ""
}

echo "======================================="
echo "1. Build server"
echo "======================================="

run_test "Build server" "go build -o bin/server ./cmd/server"

echo "======================================="
echo "2. Run rate limit tests"
echo "======================================="

run_test "Rate limit tests" "go test -v ./internal/ratelimit/..."

echo "======================================="
echo "3. Run public notes tests"
echo "======================================="

run_test "Public notes tests" "go test -v ./internal/notes/..."

echo "======================================="
echo "4. Run all tests with coverage"
echo "======================================="

run_test "All internal tests with coverage" "go test -coverprofile=test-results/milestone3-coverage.out ./internal/..."

echo "======================================="
echo "5. Run Playwright browser tests"
echo "======================================="

# Check if Playwright is installed
if go run github.com/playwright-community/playwright-go/cmd/playwright install --dry-run chromium 2>/dev/null; then
    run_test "Playwright browser tests (auth, notes CRUD, public notes)" "go test -v ./tests/browser/..."
else
    echo -e "${YELLOW}WARNING: Playwright browsers not installed. Skipping browser tests.${NC}"
    echo "Install with: go run github.com/playwright-community/playwright-go/cmd/playwright install chromium"
fi

echo "======================================="
echo "6. Generate coverage report"
echo "======================================="

if [ -f "test-results/milestone3-coverage.out" ]; then
    go tool cover -html=test-results/milestone3-coverage.out -o test-results/milestone3-coverage.html
    echo -e "${GREEN}Coverage report generated: test-results/milestone3-coverage.html${NC}"

    # Show coverage summary
    echo ""
    echo "Coverage Summary:"
    go tool cover -func=test-results/milestone3-coverage.out | tail -1
else
    echo -e "${RED}Coverage file not found, skipping HTML report generation${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo ""
echo "======================================="
echo "RESULTS"
echo "======================================="
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}=== Milestone 3 tests FAILED ===${NC}"
    exit 1
else
    echo -e "${GREEN}=== All Milestone 3 tests passed ===${NC}"
    echo "Coverage report: test-results/milestone3-coverage.html"
    exit 0
fi
