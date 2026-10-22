#!/bin/bash
set -euo pipefail

# Called by make test-fuzz; Go/CGO/test-secret settings come from Makefile.
OUTPUT_DIR="${OUTPUT_DIR:-./test-results}"
PARALLEL="${PARALLEL:-$(nproc 2>/dev/null || echo 4)}"
FUZZ_TIMEOUT="${FUZZ_TIMEOUT:-30m}"
FUZZ_PACKAGES="${FUZZ_PACKAGES:-./...}"
FUZZ_PATTERN="${FUZZ_PATTERN:-^Fuzz}"
BUILD_TAGS="-tags fts5"
LEVEL=${1:-}
shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout) FUZZ_TIMEOUT="$2"; shift 2 ;;
        --parallel) PARALLEL="$2"; shift 2 ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        --packages) FUZZ_PACKAGES="$2"; shift 2 ;;
        --pattern) FUZZ_PATTERN="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done
if [[ "$LEVEL" != fuzz ]]; then
    echo 'Usage: fuzz.sh fuzz [--timeout duration] [--parallel workers] [--output directory] [--packages "./pkg ..."] [--pattern regex]' >&2
    exit 1
fi
read -r -a packages <<< "$FUZZ_PACKAGES"
mkdir -p "$OUTPUT_DIR/fuzz-findings"
printf 'Fuzz time per target: %s; workers per target: %s; packages: %s; target pattern: %s\n' "$FUZZ_TIMEOUT" "$PARALLEL" "$FUZZ_PACKAGES" "$FUZZ_PATTERN"

# Preserve the existing quick baseline. External conformance is outside make test.
make test 2>&1 | tee "$OUTPUT_DIR/baseline-test.log"

# Keep the actual package next to each target instead of guessing from source
# text. Discovery errors must stop the gate rather than masquerade as no tests.
package_list=$(go list "${packages[@]}")
targets=()
while IFS= read -r package; do
    listed=$(go test $BUILD_TAGS -list='^Fuzz' "$package")
    while IFS= read -r name; do
        [[ -n "$name" ]] && targets+=("$package $name")
    done < <(printf '%s\n' "$listed" | rg '^Fuzz' | rg -- "$FUZZ_PATTERN" || true)
done <<< "$package_list"
if [[ ${#targets[@]} -eq 0 ]]; then
    echo 'No matching fuzz targets; refusing to report an empty campaign as passed.' >&2
    exit 1
fi

failures=0
for target in "${targets[@]}"; do
    read -r package name <<< "$target"
    package_dir=$(go list -f '{{.Dir}}' "$package")
    target_label="${package//\//_}-$name"
    corpus="$package_dir/testdata/fuzz/$name"
    printf 'Fuzzing %s in %s; failure corpus: %s\n' "$name" "$package" "$corpus"
    if ! go test $BUILD_TAGS -parallel "$PARALLEL" -fuzz="^${name}$" -fuzztime="$FUZZ_TIMEOUT" "$package" \
        2>&1 | tee "$OUTPUT_DIR/fuzz-$target_label.log"; then
        failures=$((failures + 1))
        finding="$OUTPUT_DIR/fuzz-findings/$target_label"
        mkdir -p "$finding"
        printf '%s\n' "$corpus" > "$finding/corpus-path.txt"
        if [[ -d "$corpus" ]]; then
            cp -R "$corpus" "$finding/corpus"
        fi
        # A fuzz infrastructure failure is still a failed gate, even if Go did
        # not create a crash input. Preserve the full error and provenance.
        cp "$OUTPUT_DIR/fuzz-$target_label.log" "$finding/failure.log"
    fi
done

# Scoped campaigns collect coverage only for the selected packages. With no
# selector, the historical nightly ./... scope is preserved.
if ! go test $BUILD_TAGS -v -parallel "$PARALLEL" -coverprofile="$OUTPUT_DIR/fuzz-coverage.out" "${packages[@]}" \
    2>&1 | tee "$OUTPUT_DIR/fuzz-test.log"; then
    failures=$((failures + 1))
fi
if [[ -f "$OUTPUT_DIR/fuzz-coverage.out" ]]; then
    go tool cover -html="$OUTPUT_DIR/fuzz-coverage.out" -o "$OUTPUT_DIR/fuzz-coverage.html"
fi
if [[ "$failures" -ne 0 ]] || [[ -n "$(find "$OUTPUT_DIR/fuzz-findings" -mindepth 1 -print -quit)" ]]; then
    echo "Fuzz gate failed; retained findings in $OUTPUT_DIR/fuzz-findings" >&2
    exit 1
fi
printf 'Fuzz gate passed; reports: %s\n' "$OUTPUT_DIR"
