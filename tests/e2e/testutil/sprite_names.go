package testutil

import (
	"os"
	"strings"
)

const maxPrefixedAppNameLen = 30

// CurrentGitHubRunID returns a compact run identifier for CI-created resources.
// It uses GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT when available, otherwise "local".
func CurrentGitHubRunID() string {
	runID := sanitizeNameToken(os.Getenv("GITHUB_RUN_ID"))
	if runID == "" {
		runID = sanitizeNameToken(os.Getenv("GITHUB_RUN_NUMBER"))
	}
	if runID == "" {
		return "local"
	}

	attempt := sanitizeNameToken(os.Getenv("GITHUB_RUN_ATTEMPT"))
	if attempt == "" {
		return runID
	}

	return runID + "a" + attempt
}

// PrefixWithRunID appends a CI run identifier to an app name prefix.
// The returned prefix is bounded so browser tests can still append a long random suffix.
func PrefixWithRunID(prefix string) string {
	base := sanitizeNameToken(prefix)
	if base == "" {
		base = "app"
	}

	runID := CurrentGitHubRunID()
	combined := base + "-" + runID
	if len(combined) <= maxPrefixedAppNameLen {
		return combined
	}

	maxBaseLen := maxPrefixedAppNameLen - len(runID) - 1
	if maxBaseLen < 1 {
		maxBaseLen = 1
	}
	if len(base) > maxBaseLen {
		base = strings.Trim(base[:maxBaseLen], "-")
		if base == "" {
			base = "app"
		}
	}

	return base + "-" + runID
}

func sanitizeNameToken(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(s))
	lastDash := false

	for _, r := range s {
		isLowerAlpha := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		if isLowerAlpha || isDigit {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}

	return strings.Trim(b.String(), "-")
}
