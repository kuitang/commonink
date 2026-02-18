package billing

import (
	"context"
	"log"
)

// MockService implements BillingService for test mode (--test flag).
type MockService struct{}

// NewMockService creates a mock billing service.
func NewMockService() *MockService {
	log.Println("[BILLING] Using mock billing service (--test)")
	return &MockService{}
}

// IsMock returns true for mock service.
func (m *MockService) IsMock() bool { return true }

// PublishableKey returns empty string in mock mode.
func (m *MockService) PublishableKey() string { return "" }

// CreateCheckoutSession returns a fake client secret in mock mode.
func (m *MockService) CreateCheckoutSession(ctx context.Context, userID, email, plan, baseURL string) (string, error) {
	log.Printf("[BILLING-MOCK] CreateCheckoutSession: userID=%s, email=%s, plan=%s", userID, email, plan)
	return "mock_cs_secret_" + plan, nil
}

// CreatePortalSession returns a mock URL.
func (m *MockService) CreatePortalSession(ctx context.Context, stripeCustomerID, returnURL string) (string, error) {
	log.Printf("[BILLING-MOCK] CreatePortalSession: customer=%s", stripeCustomerID)
	return returnURL + "?mock_portal=true", nil
}

// GetSessionStatus returns mock complete status.
func (m *MockService) GetSessionStatus(ctx context.Context, sessionID string) (string, string, error) {
	log.Printf("[BILLING-MOCK] GetSessionStatus: session=%s", sessionID)
	return "complete", "mock@example.com", nil
}

// HandleWebhook is a no-op in mock mode.
func (m *MockService) HandleWebhook(payload []byte, sigHeader string) error {
	log.Println("[BILLING-MOCK] HandleWebhook: no-op")
	return nil
}
