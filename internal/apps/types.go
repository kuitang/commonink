package apps

import "time"

// AppMetadata stores the server-side metadata for a user app/sprite binding.
type AppMetadata struct {
	Name       string    `json:"name"`
	SpriteName string    `json:"sprite_name"`
	PublicURL  string    `json:"public_url,omitempty"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AppFileEntry describes one file or directory in a Sprite app filesystem listing.
type AppFileEntry struct {
	Path       string    `json:"path"`
	Kind       string    `json:"kind"` // file | dir
	SizeBytes  int64     `json:"size_bytes"`
	ModifiedAt time.Time `json:"modified_at"`
}

// AppListFilesResult is the response payload for filesystem listing.
type AppListFilesResult struct {
	App   string         `json:"app"`
	Files []AppFileEntry `json:"files"`
}

// AppCreateAttempt captures one candidate attempted during app_create.
type AppCreateAttempt struct {
	Name              string `json:"name"`
	Accepted          bool   `json:"accepted"`
	ErrorCode         string `json:"error_code,omitempty"`
	Message           string `json:"message,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
	Suggestion        string `json:"suggestion,omitempty"`
}

// AppCreateResult is the response payload for app_create.
type AppCreateResult struct {
	Created   bool               `json:"created"`
	Name      string             `json:"name,omitempty"`
	PublicURL string             `json:"public_url,omitempty"`
	Status    string             `json:"status,omitempty"`
	Attempts  []AppCreateAttempt `json:"attempts"`
	Message   string             `json:"message,omitempty"`
}

// AppWriteFileInput is one file write request in app_write.
type AppWriteFileInput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// AppWriteFileResult reports one successfully written file.
type AppWriteFileResult struct {
	Path         string `json:"path"`
	BytesWritten int    `json:"bytes_written"`
}

// AppWriteResult is the response payload for app_write.
type AppWriteResult struct {
	App               string               `json:"app"`
	FilesWritten      []AppWriteFileResult `json:"files_written"`
	TotalBytesWritten int                  `json:"total_bytes_written"`
	TotalFilesWritten int                  `json:"total_files_written"`
}

// AppReadResult is the response payload for app_read.
type AppReadResult struct {
	App   string              `json:"app"`
	Files []AppWriteFileInput `json:"files"`
}

// AppBashResult is the response payload for app_bash.
type AppBashResult struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	ExitCode        int    `json:"exit_code"`
	RuntimeMS       int64  `json:"runtime_ms"`
	PortStatus      string `json:"port_status,omitempty"`
	PublicURL       string `json:"public_url,omitempty"`
	Warning         string `json:"warning,omitempty"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
}

// AppLogsResult is the response payload for app log tailing.
type AppLogsResult struct {
	App       string `json:"app"`
	Lines     int    `json:"lines"`
	Output    string `json:"output"`
	Stderr    string `json:"stderr,omitempty"`
	ExitCode  int    `json:"exit_code"`
	RuntimeMS int64  `json:"runtime_ms"`
}

// AppDeleteResult is the response payload for app_delete.
type AppDeleteResult struct {
	App     string `json:"app"`
	Deleted bool   `json:"deleted"`
}
