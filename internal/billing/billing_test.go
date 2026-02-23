package billing

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kuitang/agent-notes/internal/testdb"
	"github.com/stripe/stripe-go/v82"
	stripewebhook "github.com/stripe/stripe-go/v82/webhook"
	"pgregory.net/rapid"
)

func testService_CreateCheckoutSession_InvalidPlanRejected(t *rapid.T) {
	svc := &Service{
		config: Config{
			PriceMonthly: "price_monthly",
			PriceAnnual:  "price_annual",
		},
	}

	plan := rapid.StringMatching(`[a-z0-9_-]{1,24}`).Filter(func(s string) bool {
		return s != "monthly" && s != "annual"
	}).Draw(t, "plan")
	_, err := svc.CreateCheckoutSession(context.Background(), "user-1", "user@example.com", plan, "https://example.com")
	if err == nil {
		t.Fatal("expected invalid plan error")
	}
	if !strings.Contains(err.Error(), "invalid plan") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestService_CreateCheckoutSession_InvalidPlanRejected(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testService_CreateCheckoutSession_InvalidPlanRejected)
}

func TestService_PublishableKeyAndIsMock(t *testing.T) {
	t.Parallel()
	svc := &Service{
		config: Config{
			PublishableKey: "pk_test_123",
		},
	}
	if svc.IsMock() {
		t.Fatal("real service should report IsMock=false")
	}
	if got := svc.PublishableKey(); got != "pk_test_123" {
		t.Fatalf("publishable key mismatch: got=%q want=%q", got, "pk_test_123")
	}
}

func TestService_HandleWebhook_InvalidSignatureRejected(t *testing.T) {
	t.Parallel()
	sessDB, err := testdb.NewSessionsDBInMemory()
	if err != nil {
		t.Fatalf("failed to create in-memory sessions db: %v", err)
	}
	t.Cleanup(func() { _ = sessDB.DB().Close() })

	svc := &Service{
		config: Config{
			WebhookSecret: "whsec_test_invalid",
		},
		sessDB: sessDB,
	}

	err = svc.HandleWebhook([]byte(`{"id":"evt_invalid","object":"event"}`), "bad-header")
	if err == nil {
		t.Fatal("expected signature verification failure")
	}
	if !strings.Contains(err.Error(), "verify webhook signature") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestService_HandleWebhook_IdempotentForRepeatedEventID(t *testing.T) {
	t.Parallel()
	sessDB, err := testdb.NewSessionsDBInMemory()
	if err != nil {
		t.Fatalf("failed to create in-memory sessions db: %v", err)
	}
	t.Cleanup(func() { _ = sessDB.DB().Close() })

	secret := "whsec_idempotency_test"
	svc := &Service{
		config: Config{
			WebhookSecret: secret,
		},
		sessDB: sessDB,
	}

	event := map[string]any{
		"id":          "evt_repeat_1",
		"object":      "event",
		"api_version": stripe.APIVersion,
		"type":        "test.unhandled",
		"data": map[string]any{
			"object": map[string]any{},
		},
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal test event: %v", err)
	}
	signed := stripewebhook.GenerateTestSignedPayload(&stripewebhook.UnsignedPayload{
		Payload:   payload,
		Secret:    secret,
		Timestamp: time.Now(),
	})

	if err := svc.HandleWebhook(payload, signed.Header); err != nil {
		t.Fatalf("first HandleWebhook call failed: %v", err)
	}
	if err := svc.HandleWebhook(payload, signed.Header); err != nil {
		t.Fatalf("second HandleWebhook call failed: %v", err)
	}

	var count int
	if err := sessDB.DB().QueryRow(`SELECT COUNT(*) FROM processed_webhook_events WHERE event_id = ?`, "evt_repeat_1").Scan(&count); err != nil {
		t.Fatalf("failed to query processed_webhook_events: %v", err)
	}
	if count != 1 {
		t.Fatalf("idempotency mismatch: expected 1 processed row, got %d", count)
	}
}
