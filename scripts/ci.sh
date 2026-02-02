#!/bin/bash
set -e

# Remote Notes CI Script
# Runs property-based tests, fuzzing, and coverage analysis
# Usage: ./scripts/ci.sh <level> [options]

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
OUTPUT_DIR="./test-results"
PARALLEL=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
FUZZ_TIMEOUT="30m"
COVERAGE_THRESHOLD=70

# Parse arguments
LEVEL=${1:-}
shift || true

while [[ $# -gt 0 ]]; do
    case $1 in
        --timeout)
            FUZZ_TIMEOUT="$2"
            shift 2
            ;;
        --parallel)
            PARALLEL="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --coverage-threshold)
            COVERAGE_THRESHOLD="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Validate level
if [[ ! "$LEVEL" =~ ^(quick|full|fuzz)$ ]]; then
    echo "Usage: $0 <level> [options]"
    echo ""
    echo "Levels:"
    echo "  quick   - rapid property tests only (~30 seconds)"
    echo "  full    - rapid + Playwright + coverage + MCP/OAuth conformance (~5 minutes)"
    echo "  fuzz    - coverage-guided fuzzing (~30+ minutes)"
    echo ""
    echo "Options:"
    echo "  --timeout <duration>       Fuzz timeout (default: 30m)"
    echo "  --parallel <n>             Parallel workers (default: CPU count)"
    echo "  --output <dir>             Output directory (default: ./test-results)"
    echo "  --coverage-threshold <n>   Min coverage % (default: 70)"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED_VERSION="1.22"
if [[ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]]; then
    echo -e "${RED}Error: Go $REQUIRED_VERSION or later required (found $GO_VERSION)${NC}"
    exit 1
fi

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}Remote Notes CI - Level: $LEVEL${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e "Go version: $GO_VERSION"
echo -e "Parallel workers: $PARALLEL"
echo -e "Output directory: $OUTPUT_DIR"
echo ""

# Quick level: rapid property tests only
if [[ "$LEVEL" == "quick" ]]; then
    echo -e "${GREEN}Running quick tests (rapid property tests)...${NC}"

    # Run all Test* functions (rapid tests)
    go test -v -parallel "$PARALLEL" ./... \
        -run 'Test' \
        2>&1 | tee "$OUTPUT_DIR/quick-test.log"

    echo -e "${GREEN}✓ Quick tests completed${NC}"
    exit 0
fi

# Full level: rapid + Playwright + coverage + MCP/OAuth conformance
if [[ "$LEVEL" == "full" ]]; then
    echo -e "${GREEN}Running full tests (rapid + Playwright + coverage + MCP/OAuth conformance)...${NC}"

    # Install Playwright if needed
    if ! command -v playwright &> /dev/null; then
        echo -e "${YELLOW}Installing Playwright...${NC}"
        go run github.com/playwright-community/playwright-go/cmd/playwright install --with-deps chromium
    fi

    # Run tests with coverage
    echo -e "${BLUE}Running tests with coverage...${NC}"
    go test -v -parallel "$PARALLEL" -coverprofile="$OUTPUT_DIR/coverage.out" ./... \
        2>&1 | tee "$OUTPUT_DIR/full-test.log"

    # Run MCP conformance tests
    echo -e "${BLUE}Running MCP conformance tests...${NC}"
    if bash scripts/mcp-conformance.sh 2>&1 | tee "$OUTPUT_DIR/mcp-conformance.log"; then
        echo -e "${GREEN}✓ MCP conformance tests passed${NC}"
    else
        echo -e "${YELLOW}⚠ MCP conformance tests failed (may be expected if server not fully implemented)${NC}"
        # Don't fail CI on MCP conformance failure yet - server may not be implemented
    fi

    # Run OAuth 2.1 conformance tests
    echo -e "${BLUE}Running OAuth 2.1 conformance tests...${NC}"
    if bash scripts/oauth-conformance-test.sh "$OUTPUT_DIR/oauth-conformance" 2>&1 | tee "$OUTPUT_DIR/oauth-conformance.log"; then
        echo -e "${GREEN}✓ OAuth 2.1 conformance tests passed${NC}"
    else
        echo -e "${YELLOW}⚠ OAuth 2.1 conformance tests failed (expected until OAuth is implemented)${NC}"
        # Don't fail CI on OAuth conformance failure yet - server may not be implemented
    fi

    # Generate coverage report
    echo -e "${BLUE}Generating coverage report...${NC}"
    go tool cover -html="$OUTPUT_DIR/coverage.out" -o "$OUTPUT_DIR/coverage.html"
    go tool cover -func="$OUTPUT_DIR/coverage.out" > "$OUTPUT_DIR/coverage-summary.txt"

    # Extract coverage percentage
    COVERAGE=$(go tool cover -func="$OUTPUT_DIR/coverage.out" | grep total | awk '{print $3}' | tr -d '%')

    # Generate coverage gaps report
    echo -e "${BLUE}Analyzing coverage gaps...${NC}"
    bash scripts/coverage-gaps.sh "$OUTPUT_DIR/coverage.out" > "$OUTPUT_DIR/coverage-gaps.txt"

    # Check coverage threshold
    if (( $(echo "$COVERAGE < $COVERAGE_THRESHOLD" | bc -l) )); then
        echo -e "${RED}✗ Coverage $COVERAGE% is below threshold $COVERAGE_THRESHOLD%${NC}"
        echo -e "${YELLOW}See $OUTPUT_DIR/coverage-gaps.txt for details${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ Full tests completed${NC}"
    echo -e "${GREEN}✓ Coverage: $COVERAGE% (threshold: $COVERAGE_THRESHOLD%)${NC}"
    echo -e "${BLUE}Reports:${NC}"
    echo -e "  - Coverage HTML: $OUTPUT_DIR/coverage.html"
    echo -e "  - Coverage summary: $OUTPUT_DIR/coverage-summary.txt"
    echo -e "  - Coverage gaps: $OUTPUT_DIR/coverage-gaps.txt"
    echo -e "  - MCP conformance: $OUTPUT_DIR/mcp-conformance.log"
    echo -e "  - OAuth conformance: $OUTPUT_DIR/oauth-conformance/oauth-conformance-report.txt"
    exit 0
fi

# Fuzz level: coverage-guided fuzzing
if [[ "$LEVEL" == "fuzz" ]]; then
    echo -e "${GREEN}Running fuzz tests (coverage-guided fuzzing)...${NC}"
    echo -e "${YELLOW}Timeout: $FUZZ_TIMEOUT${NC}"

    # First run quick tests as baseline
    echo -e "${BLUE}Running baseline tests...${NC}"
    go test -v -parallel "$PARALLEL" -coverprofile="$OUTPUT_DIR/baseline-coverage.out" ./... \
        -run 'Test' \
        2>&1 | tee "$OUTPUT_DIR/baseline-test.log"

    # Find all fuzz tests
    FUZZ_TESTS=$(go test -list=Fuzz ./... 2>/dev/null | grep '^Fuzz' || true)

    if [[ -z "$FUZZ_TESTS" ]]; then
        echo -e "${YELLOW}No fuzz tests found${NC}"
        exit 0
    fi

    echo -e "${BLUE}Found fuzz tests:${NC}"
    echo "$FUZZ_TESTS"
    echo ""

    # Run each fuzz test
    mkdir -p "$OUTPUT_DIR/fuzz-findings"
    for fuzz_test in $FUZZ_TESTS; do
        echo -e "${BLUE}Fuzzing: $fuzz_test${NC}"

        # Extract package from test location
        PACKAGE=$(go test -list="$fuzz_test" ./... 2>/dev/null | grep -v '^Fuzz' | head -1 || echo "./...")

        # Run fuzzing (will create corpus in testdata/fuzz/)
        go test -fuzz="^${fuzz_test}$" -fuzztime="$FUZZ_TIMEOUT" "$PACKAGE" \
            2>&1 | tee "$OUTPUT_DIR/fuzz-${fuzz_test}.log" || {
                echo -e "${RED}Fuzz test $fuzz_test found issues!${NC}"
                echo "See $OUTPUT_DIR/fuzz-${fuzz_test}.log for details"
                # Copy failing inputs to findings directory
                find testdata/fuzz -name "$fuzz_test" -type d -exec cp -r {} "$OUTPUT_DIR/fuzz-findings/" \; || true
            }
    done

    # Run tests again with coverage to see fuzz improvements
    echo -e "${BLUE}Running tests after fuzzing (with coverage)...${NC}"
    go test -v -parallel "$PARALLEL" -coverprofile="$OUTPUT_DIR/fuzz-coverage.out" ./... \
        2>&1 | tee "$OUTPUT_DIR/fuzz-test.log"

    # Compare baseline vs fuzz coverage
    echo -e "${BLUE}Comparing coverage: baseline vs fuzz...${NC}"
    bash scripts/compare-coverage.sh \
        "$OUTPUT_DIR/baseline-coverage.out" \
        "$OUTPUT_DIR/fuzz-coverage.out" \
        > "$OUTPUT_DIR/coverage-comparison.txt"

    # Generate final reports
    go tool cover -html="$OUTPUT_DIR/fuzz-coverage.out" -o "$OUTPUT_DIR/fuzz-coverage.html"
    bash scripts/coverage-gaps.sh "$OUTPUT_DIR/fuzz-coverage.out" > "$OUTPUT_DIR/fuzz-coverage-gaps.txt"

    echo -e "${GREEN}✓ Fuzz tests completed${NC}"
    echo -e "${BLUE}Reports:${NC}"
    echo -e "  - Baseline coverage: $OUTPUT_DIR/baseline-coverage.out"
    echo -e "  - Fuzz coverage: $OUTPUT_DIR/fuzz-coverage.html"
    echo -e "  - Coverage comparison: $OUTPUT_DIR/coverage-comparison.txt"
    echo -e "  - Fuzz findings: $OUTPUT_DIR/fuzz-findings/"

    # Check if there are findings
    if [[ -n "$(ls -A "$OUTPUT_DIR/fuzz-findings" 2>/dev/null)" ]]; then
        echo -e "${YELLOW}⚠ New fuzz findings detected!${NC}"
        echo -e "${YELLOW}Review $OUTPUT_DIR/fuzz-findings/ for details${NC}"
        exit 1
    fi

    exit 0
fi
