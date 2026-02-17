package email

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// EmailService defines the interface for sending emails.
// In Milestone 2, only the mock implementation is used.
// Real implementations (e.g., Resend) will be added in Milestone 4.
type EmailService interface {
	// Send sends an email using the specified template.
	// Parameters:
	//   - to: recipient email address
	//   - templateName: name of the email template (e.g., "magic_link", "password_reset")
	//   - data: template data (varies by template)
	Send(to, templateName string, data any) error
}

// SentEmail represents a captured email for testing.
type SentEmail struct {
	To       string
	Template string
	Data     any
}

// MockEmailService is a mock implementation that captures emails for testing.
type MockEmailService struct {
	mu        sync.Mutex
	Emails    []SentEmail
	outboxDir string
	seq       uint64
}

// NewMockEmailService creates a new mock email service.
func NewMockEmailService() *MockEmailService {
	outboxDir := os.Getenv("MOCK_EMAIL_OUTBOX_DIR")
	if outboxDir == "" {
		outboxDir = filepath.Join(os.TempDir(), "commonink-mock-email-outbox")
	}
	if err := os.MkdirAll(outboxDir, 0o755); err != nil {
		log.Printf("[EMAIL] WARN: failed to create outbox dir %s: %v", outboxDir, err)
		outboxDir = ""
	}

	return &MockEmailService{
		Emails:    make([]SentEmail, 0),
		outboxDir: outboxDir,
	}
}

// Send captures the email instead of sending it and logs for manual testing.
func (m *MockEmailService) Send(to, templateName string, data any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Emails = append(m.Emails, SentEmail{
		To:       to,
		Template: templateName,
		Data:     data,
	})

	// Log email for manual testing visibility
	log.Printf("[EMAIL] To: %s | Template: %s", to, templateName)
	event := outboxEmailEvent{
		To:             to,
		Template:       templateName,
		SentAtUnixNano: time.Now().UnixNano(),
	}
	switch d := data.(type) {
	case MagicLinkData:
		log.Printf("[EMAIL] Magic Link: %s (expires in %s)", d.Link, d.ExpiresIn)
		event.Link = d.Link
		event.ExpiresIn = d.ExpiresIn
	case PasswordResetData:
		log.Printf("[EMAIL] Password Reset Link: %s (expires in %s)", d.Link, d.ExpiresIn)
		event.Link = d.Link
		event.ExpiresIn = d.ExpiresIn
	case WelcomeData:
		log.Printf("[EMAIL] Welcome %s!", d.Name)
		event.Name = d.Name
	default:
		log.Printf("[EMAIL] Data: %+v", data)
		event.RawData = fmt.Sprintf("%+v", data)
	}

	if err := m.writeOutboxEvent(event); err != nil {
		return err
	}

	return nil
}

// LastEmail returns the most recently sent email.
// Returns zero value if no emails have been sent.
func (m *MockEmailService) LastEmail() SentEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Emails) == 0 {
		return SentEmail{}
	}
	return m.Emails[len(m.Emails)-1]
}

// Clear removes all captured emails.
func (m *MockEmailService) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Emails = make([]SentEmail, 0)
}

// Count returns the number of captured emails.
func (m *MockEmailService) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Emails)
}

type outboxEmailEvent struct {
	Sequence       uint64 `json:"sequence"`
	To             string `json:"to"`
	Template       string `json:"template"`
	Link           string `json:"link,omitempty"`
	ExpiresIn      string `json:"expires_in,omitempty"`
	Name           string `json:"name,omitempty"`
	RawData        string `json:"raw_data,omitempty"`
	SentAtUnixNano int64  `json:"sent_at_unix_nano"`
}

func (m *MockEmailService) writeOutboxEvent(event outboxEmailEvent) error {
	if m.outboxDir == "" {
		return nil
	}

	m.seq++
	event.Sequence = m.seq

	fileName := fmt.Sprintf(
		"%020d-%020d-%s-%s.json",
		event.Sequence,
		event.SentAtUnixNano,
		sanitizeOutboxComponent(event.Template),
		sanitizeOutboxComponent(event.To),
	)
	finalPath := filepath.Join(m.outboxDir, fileName)
	tempPath := finalPath + ".tmp"

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal outbox event: %w", err)
	}
	if err := os.WriteFile(tempPath, payload, 0o644); err != nil {
		return fmt.Errorf("write outbox temp file: %w", err)
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("rename outbox file: %w", err)
	}
	return nil
}

var outboxSanitizePattern = regexp.MustCompile(`[^a-zA-Z0-9._@-]+`)

func sanitizeOutboxComponent(input string) string {
	safe := strings.TrimSpace(input)
	if safe == "" {
		return "unknown"
	}
	return outboxSanitizePattern.ReplaceAllString(safe, "_")
}
