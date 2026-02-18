package notes

import (
	"errors"
	"fmt"
)

// FreeStorageLimitBytes is the maximum storage for free users (100MB)
const FreeStorageLimitBytes int64 = 100 * 1024 * 1024

// StorageLimitForStatus returns the storage limit in bytes for a given subscription status.
// "active" subscriptions get unlimited storage (0). All other statuses get the free tier limit.
func StorageLimitForStatus(subscriptionStatus string) int64 {
	if subscriptionStatus == "active" {
		return 0 // unlimited
	}
	return FreeStorageLimitBytes
}

// ErrStorageLimitExceeded is returned when a user exceeds their storage limit
var ErrStorageLimitExceeded = errors.New("storage limit exceeded")

// StorageUsageInfo contains information about a user's storage usage
type StorageUsageInfo struct {
	UsedBytes  int64   `json:"used_bytes"`
	LimitBytes int64   `json:"limit_bytes"` // 0 means unlimited
	UsedMB     float64 `json:"used_mb"`
	LimitMB    float64 `json:"limit_mb"`   // 0 means unlimited
	Percentage float64 `json:"percentage"` // 0 if unlimited
}

// CheckStorageLimit checks if adding newContentSize bytes to the current storage
// would exceed the given limit. If storageLimit is 0, the check is skipped (unlimited).
func CheckStorageLimit(currentSize, newContentSize, storageLimit int64) error {
	if storageLimit == 0 {
		return nil // unlimited
	}
	if currentSize+newContentSize > storageLimit {
		return fmt.Errorf("%w: current %d bytes + new %d bytes exceeds limit of %d bytes",
			ErrStorageLimitExceeded, currentSize, newContentSize, storageLimit)
	}
	return nil
}

// CheckStorageLimitForUpdate checks if an update operation would exceed storage limits.
// It calculates the delta between old and new content sizes and checks against the limit.
// If the new content is smaller, no check is needed (delta is negative or zero).
func CheckStorageLimitForUpdate(currentTotalSize, oldContentSize, newContentSize, storageLimit int64) error {
	delta := newContentSize - oldContentSize
	if delta <= 0 {
		// Content is shrinking or unchanged, always allowed
		return nil
	}
	return CheckStorageLimit(currentTotalSize, delta, storageLimit)
}

// NewStorageUsageInfo creates a StorageUsageInfo from the given used bytes and limit.
// If limitBytes is 0, it means unlimited (percentage will be 0).
func NewStorageUsageInfo(usedBytes, limitBytes int64) StorageUsageInfo {
	usedMB := float64(usedBytes) / (1024 * 1024)
	limitMB := float64(limitBytes) / (1024 * 1024)
	percentage := float64(0)
	if limitBytes > 0 {
		percentage = float64(usedBytes) / float64(limitBytes) * 100
		if percentage > 100 {
			percentage = 100
		}
	}
	return StorageUsageInfo{
		UsedBytes:  usedBytes,
		LimitBytes: limitBytes,
		UsedMB:     usedMB,
		LimitMB:    limitMB,
		Percentage: percentage,
	}
}
