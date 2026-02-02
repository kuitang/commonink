#!/bin/bash
# Analyze coverage profile and report uncovered lines
# Usage: ./scripts/coverage-gaps.sh <coverage.out>

set -e

COVERAGE_FILE=${1:-coverage.out}

if [[ ! -f "$COVERAGE_FILE" ]]; then
    echo "Error: Coverage file not found: $COVERAGE_FILE"
    exit 1
fi

echo "=== COVERAGE GAPS REPORT ==="
echo "Coverage file: $COVERAGE_FILE"
echo ""

# Parse coverage profile and find lines never hit
# Format: file.go:startLine.startCol,endLine.endCol numStmt numHit
echo "=== LINES NEVER HIT ==="
awk '
    NR > 1 {  # Skip header
        # Extract filename and line range
        split($1, parts, ":")
        file = parts[1]
        split(parts[2], range, ",")
        split(range[1], start, ".")
        split(range[2], end, ".")
        startLine = start[1]
        endLine = end[1]
        numHit = $3

        if (numHit == 0) {
            if (startLine == endLine) {
                print "  " file ":" startLine " (never executed)"
            } else {
                print "  " file ":" startLine "-" endLine " (never executed)"
            }
        }
    }
' "$COVERAGE_FILE" | sort | uniq

echo ""
echo "=== COVERAGE SUMMARY ==="
go tool cover -func="$COVERAGE_FILE" | tail -1

echo ""
echo "=== FILES WITH LOW COVERAGE (<50%) ==="
go tool cover -func="$COVERAGE_FILE" | awk '
    $3 < 50 && $1 != "total" {
        printf "  %-50s %s\n", $1, $3
    }
' | sort -t: -k2 -n

echo ""
echo "Done. Review uncovered lines to determine if they need:"
echo "  - Additional test cases"
echo "  - Documentation (if only hit by fuzz tests)"
echo "  - Removal (if dead code)"
