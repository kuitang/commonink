#!/bin/bash
# Compare two coverage profiles
# Usage: ./scripts/compare-coverage.sh <baseline.out> <new.out>

set -e

BASELINE=${1:-baseline-coverage.out}
NEW=${2:-fuzz-coverage.out}

if [[ ! -f "$BASELINE" ]] || [[ ! -f "$NEW" ]]; then
    echo "Error: Coverage files not found"
    echo "Usage: $0 <baseline.out> <new.out>"
    exit 1
fi

echo "=== COVERAGE COMPARISON ==="
echo "Baseline: $BASELINE"
echo "New: $NEW"
echo ""

# Get total coverage percentages
BASELINE_PCT=$(go tool cover -func="$BASELINE" | grep total | awk '{print $3}' | tr -d '%')
NEW_PCT=$(go tool cover -func="$NEW" | grep total | awk '{print $3}' | tr -d '%')

echo "=== OVERALL COVERAGE ==="
printf "Baseline: %.1f%%\n" "$BASELINE_PCT"
printf "New:      %.1f%%\n" "$NEW_PCT"

# Calculate improvement
IMPROVEMENT=$(echo "$NEW_PCT - $BASELINE_PCT" | bc)
printf "Change:   %+.1f%%\n" "$IMPROVEMENT"
echo ""

# Find lines hit by new but not baseline
echo "=== LINES HIT BY NEW BUT NOT BASELINE ==="
echo "(These lines were discovered by fuzzing/new tests)"

# Parse both files and compare
awk '
    FILENAME == ARGV[1] && NR > 1 {
        # Baseline coverage
        split($1, parts, ":")
        file = parts[1]
        location = parts[2]
        baseline[file ":" location] = $3
    }
    FILENAME == ARGV[2] && NR > 1 {
        # New coverage
        split($1, parts, ":")
        file = parts[1]
        location = parts[2]
        key = file ":" location
        newHit = $3

        # If new has hits but baseline didn't
        if (newHit > 0 && baseline[key] == 0) {
            split(location, range, ",")
            split(range[1], start, ".")
            print "  " file ":" start[1] " (hit " newHit " times)"
            count++
        }
    }
    END {
        if (count == 0) {
            print "  (none)"
        }
    }
' "$BASELINE" "$NEW"

echo ""
echo "=== RECOMMENDATION ==="
if (( $(echo "$IMPROVEMENT > 5" | bc -l) )); then
    echo "✓ Significant coverage improvement! Consider adding representative cases as unit tests."
elif (( $(echo "$IMPROVEMENT > 0" | bc -l) )); then
    echo "✓ Minor coverage improvement. Fuzzing is finding some edge cases."
else
    echo "⚠ No coverage improvement. Fuzzing may not be finding new paths."
fi
