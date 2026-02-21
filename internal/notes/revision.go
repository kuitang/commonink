package notes

import (
	"crypto/sha3"
	"encoding/hex"
	"strings"
)

// RevisionHash computes SHA3-256 for title+content.
// Runtime optimistic concurrency uses SQLite `sha3(...)` directly; this helper is for pure-Go callers.
func RevisionHash(title, content string) string {
	sum := sha3.Sum256([]byte(title + "\x00" + content))
	return hex.EncodeToString(sum[:])
}

func normalizePriorHash(hash string) (string, bool) {
	h := strings.TrimSpace(strings.ToLower(hash))
	if len(h) != 64 {
		return "", false
	}
	for _, r := range h {
		isDigit := r >= '0' && r <= '9'
		isHexLetter := r >= 'a' && r <= 'f'
		if !isDigit && !isHexLetter {
			return "", false
		}
	}
	return h, true
}
