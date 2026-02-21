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

// AppWriteResult is the response payload for app_write.
type AppWriteResult struct {
	App         string `json:"app"`
	Path        string `json:"path"`
	BytesWritten int   `json:"bytes_written"`
}

// AppReadResult is the response payload for app_read.
type AppReadResult struct {
	App     string `json:"app"`
	Path    string `json:"path"`
	Content string `json:"content"`
}

// AppBashResult is the response payload for app_bash.
type AppBashResult struct {
	Stdout       string `json:"stdout"`
	Stderr       string `json:"stderr"`
	ExitCode     int    `json:"exit_code"`
	RuntimeMS    int64  `json:"runtime_ms"`
	PortStatus   string `json:"port_status,omitempty"`
	PublicURL    string `json:"public_url,omitempty"`
	Warning      string `json:"warning,omitempty"`
	TimeoutSeconds int  `json:"timeout_seconds"`
}

// AppDeleteResult is the response payload for app_delete.
type AppDeleteResult struct {
	App     string `json:"app"`
	Deleted bool   `json:"deleted"`
}

