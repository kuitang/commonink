package email

import (
	"log"
	"sync"
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
	mu     sync.Mutex
	Emails []SentEmail
}

// NewMockEmailService creates a new mock email service.
func NewMockEmailService() *MockEmailService {
	return &MockEmailService{
		Emails: make([]SentEmail, 0),
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
	switch d := data.(type) {
	case MagicLinkData:
		log.Printf("[EMAIL] Magic Link: %s (expires in %s)", d.Link, d.ExpiresIn)
	case PasswordResetData:
		log.Printf("[EMAIL] Password Reset Link: %s (expires in %s)", d.Link, d.ExpiresIn)
	case WelcomeData:
		log.Printf("[EMAIL] Welcome %s!", d.Name)
	default:
		log.Printf("[EMAIL] Data: %+v", data)
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
