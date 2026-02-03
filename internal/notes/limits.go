package notes

import (
	"errors"
	"fmt"
)

// StorageLimitBytes is the maximum storage for free users (100MB)
const StorageLimitBytes int64 = 100 * 1024 * 1024

// ErrStorageLimitExceeded is returned when a user exceeds their storage limit
var ErrStorageLimitExceeded = errors.New("storage limit exceeded: free tier is limited to 100MB")

// StorageUsageInfo contains information about a user's storage usage
type StorageUsageInfo struct {
	UsedBytes  int64   `json:"used_bytes"`
	LimitBytes int64   `json:"limit_bytes"`
	UsedMB     float64 `json:"used_mb"`
	LimitMB    float64 `json:"limit_mb"`
	Percentage float64 `json:"percentage"`
}

// CheckStorageLimit checks if adding newContentSize bytes to the current storage
// would exceed the free tier limit. Returns nil if within limit, or
// ErrStorageLimitExceeded if it would exceed the limit.
func CheckStorageLimit(currentSize int64, newContentSize int64) error {
	if currentSize+newContentSize > StorageLimitBytes {
		return fmt.Errorf("%w (current: %d bytes, new: %d bytes, limit: %d bytes)",
			ErrStorageLimitExceeded, currentSize, newContentSize, StorageLimitBytes)
	}
	return nil
}

// CheckStorageLimitForUpdate checks if an update operation would exceed storage limits.
// It calculates the delta between old and new content sizes and checks against the limit.
// If the new content is smaller, no check is needed (delta is negative or zero).
func CheckStorageLimitForUpdate(currentTotalSize int64, oldContentSize int64, newContentSize int64) error {
	delta := newContentSize - oldContentSize
	if delta <= 0 {
		// Content is shrinking or unchanged, always allowed
		return nil
	}
	return CheckStorageLimit(currentTotalSize, delta)
}

// NewStorageUsageInfo creates a StorageUsageInfo from the given used bytes.
func NewStorageUsageInfo(usedBytes int64) StorageUsageInfo {
	usedMB := float64(usedBytes) / (1024 * 1024)
	limitMB := float64(StorageLimitBytes) / (1024 * 1024)
	percentage := float64(0)
	if StorageLimitBytes > 0 {
		percentage = float64(usedBytes) / float64(StorageLimitBytes) * 100
	}
	if percentage > 100 {
		percentage = 100
	}
	return StorageUsageInfo{
		UsedBytes:  usedBytes,
		LimitBytes: StorageLimitBytes,
		UsedMB:     usedMB,
		LimitMB:    limitMB,
		Percentage: percentage,
	}
}
