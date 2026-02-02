#!/bin/bash
# Setup git hooks for Remote Notes project
# Run: ./scripts/setup-hooks.sh

set -e

HOOK_DIR=".git/hooks"
PRE_COMMIT_HOOK="$HOOK_DIR/pre-commit"

echo "Setting up git hooks..."

# Create hooks directory if it doesn't exist
mkdir -p "$HOOK_DIR"

# Create pre-commit hook
cat > "$PRE_COMMIT_HOOK" << 'EOF'
#!/bin/bash
# Pre-commit hook for Remote Notes
# Runs go fmt and quick CI tests

set -e

echo "Running pre-commit checks..."

# Initialize goenv to use the correct Go version (1.25.6)
# CRITICAL: Do not use system Go (/usr/bin/go) - it's outdated (1.19)
export GOENV_ROOT="$HOME/.goenv"
export PATH="$GOENV_ROOT/bin:$PATH"
eval "$(goenv init -)"

# Verify Go version
GO_VERSION=$(go version 2>/dev/null | grep -o 'go1\.[0-9]*\.[0-9]*' || echo "unknown")
if [[ ! "$GO_VERSION" =~ ^go1\.25 ]]; then
    echo "WARNING: Expected Go 1.25.x but got $GO_VERSION"
    echo "Make sure goenv is properly installed with Go 1.25.6"
fi

# Get list of staged Go files
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$' || true)

if [[ -n "$STAGED_GO_FILES" ]]; then
    echo "Formatting Go files..."

    # Format each staged file
    for file in $STAGED_GO_FILES; do
        if [[ -f "$file" ]]; then
            echo "  - $file"
            go fmt "$file"
            # Re-stage the formatted file
            git add "$file"
        fi
    done

    echo "Go files formatted"
fi

# Run quick CI tests
echo "Running quick CI tests..."
if ! ./scripts/ci.sh quick; then
    echo "Quick CI tests failed!"
    echo "Fix the issues or use 'git commit --no-verify' to bypass (not recommended)"
    exit 1
fi

echo "Pre-commit checks passed"
exit 0
EOF

# Make hook executable
chmod +x "$PRE_COMMIT_HOOK"

echo "Git hooks installed successfully"
echo ""
echo "Installed hooks:"
echo "  - pre-commit: Runs go fmt + quick CI (uses goenv for Go 1.25.6)"
echo ""
echo "To bypass hooks (not recommended): git commit --no-verify"
