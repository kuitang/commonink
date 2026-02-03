#!/bin/bash
set -eo pipefail

# common.ink CI - Fuzz Testing Orchestrator
# Called by `make test-fuzz`. All env (goenv, CGO, secrets) inherited from Makefile.
#
# For quick/full tests, use make directly:
#   make test       - Quick property tests
#   make test-full  - Full tests with coverage
#   make test-fuzz  - Fuzz testing (calls this script)

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
BUILD_TAGS="-tags fts5"

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
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

if [[ "$LEVEL" != "fuzz" ]]; then
    echo "Usage: $0 fuzz [options]"
    echo ""
    echo "This script is called by \`make test-fuzz\`."
    echo "For quick/full tests: make test / make test-full"
    echo ""
    echo "Options:"
    echo "  --timeout <duration>  Fuzz timeout (default: 30m)"
    echo "  --parallel <n>        Parallel workers (default: CPU count)"
    echo "  --output <dir>        Output directory (default: ./test-results)"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}common.ink CI - Fuzz Testing${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e "Fuzz timeout: $FUZZ_TIMEOUT"
echo ""

# Step 1: Run baseline via make (inherits all env)
echo -e "${BLUE}Running baseline tests via make...${NC}"
make test 2>&1 | tee "$OUTPUT_DIR/baseline-test.log"

# Step 2: Find all fuzz tests
FUZZ_TESTS=$(go test $BUILD_TAGS -list=Fuzz ./... 2>/dev/null | grep '^Fuzz' || true)

if [[ -z "$FUZZ_TESTS" ]]; then
    echo -e "${YELLOW}No fuzz tests found${NC}"
    exit 0
fi

echo -e "${BLUE}Found fuzz tests:${NC}"
echo "$FUZZ_TESTS"
echo ""

# Step 3: Run each fuzz test
mkdir -p "$OUTPUT_DIR/fuzz-findings"
for fuzz_test in $FUZZ_TESTS; do
    echo -e "${BLUE}Fuzzing: $fuzz_test${NC}"

    PACKAGE=$(grep -r "func $fuzz_test" --include="*_test.go" . 2>/dev/null | head -1 | cut -d: -f1 | xargs dirname | sed 's|^\./|./|')
    if [[ -z "$PACKAGE" || "$PACKAGE" == "." ]]; then
        echo -e "${YELLOW}Could not find package for $fuzz_test, skipping${NC}"
        continue
    fi
    echo "  Package: $PACKAGE"

    go test $BUILD_TAGS -fuzz="^${fuzz_test}$" -fuzztime="$FUZZ_TIMEOUT" "$PACKAGE" \
        2>&1 | tee "$OUTPUT_DIR/fuzz-${fuzz_test}.log" || {
            echo -e "${RED}Fuzz test $fuzz_test found issues!${NC}"
            find testdata/fuzz -name "$fuzz_test" -type d -exec cp -r {} "$OUTPUT_DIR/fuzz-findings/" \; || true
        }
done

# Step 4: Post-fuzz coverage comparison
echo -e "${BLUE}Running post-fuzz tests with coverage...${NC}"
go test $BUILD_TAGS -v -parallel "$PARALLEL" -coverprofile="$OUTPUT_DIR/fuzz-coverage.out" ./... \
    2>&1 | tee "$OUTPUT_DIR/fuzz-test.log"

if [[ -f scripts/compare-coverage.sh && -f "$OUTPUT_DIR/baseline-coverage.out" ]]; then
    bash scripts/compare-coverage.sh \
        "$OUTPUT_DIR/baseline-coverage.out" \
        "$OUTPUT_DIR/fuzz-coverage.out" \
        > "$OUTPUT_DIR/coverage-comparison.txt" || true
fi

go tool cover -html="$OUTPUT_DIR/fuzz-coverage.out" -o "$OUTPUT_DIR/fuzz-coverage.html"
if [[ -f scripts/coverage-gaps.sh ]]; then
    bash scripts/coverage-gaps.sh "$OUTPUT_DIR/fuzz-coverage.out" > "$OUTPUT_DIR/fuzz-coverage-gaps.txt" || true
fi

echo -e "${GREEN}✓ Fuzz tests completed${NC}"
echo -e "${BLUE}Reports: $OUTPUT_DIR/${NC}"

# Fail if there are findings
if [[ -n "$(ls -A "$OUTPUT_DIR/fuzz-findings" 2>/dev/null)" ]]; then
    echo -e "${YELLOW}⚠ New fuzz findings detected! Review $OUTPUT_DIR/fuzz-findings/${NC}"
    exit 1
fi

exit 0
