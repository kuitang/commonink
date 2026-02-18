package billing

import (
	"context"
	"fmt"
	"log"

	"github.com/stripe/stripe-go/v82"
	portalsession "github.com/stripe/stripe-go/v82/billingportal/session"
	checkoutsession "github.com/stripe/stripe-go/v82/checkout/session"

	"github.com/kuitang/agent-notes/internal/crypto"
	"github.com/kuitang/agent-notes/internal/db"
)

// BillingService defines the billing operations interface.
type BillingService interface {
	CreateCheckoutSession(ctx context.Context, userID, email, plan, baseURL string) (clientSecret string, err error)
	CreatePortalSession(ctx context.Context, stripeCustomerID, returnURL string) (portalURL string, err error)
	GetSessionStatus(ctx context.Context, sessionID string) (status, customerEmail string, err error)
	HandleWebhook(payload []byte, sigHeader string) error
	PublishableKey() string
	IsMock() bool
}

// Config holds Stripe billing configuration.
type Config struct {
	SecretKey      string
	PublishableKey string
	WebhookSecret  string
	PriceMonthly   string
	PriceAnnual    string
}

// Service implements BillingService with real Stripe API calls.
type Service struct {
	config     Config
	sessDB     *db.SessionsDB
	keyManager *crypto.KeyManager
}

// NewService creates a real Stripe billing service.
func NewService(cfg Config, sessDB *db.SessionsDB, km *crypto.KeyManager) *Service {
	// Set the global Stripe API key
	stripe.Key = cfg.SecretKey
	log.Printf("[BILLING] Initialized Stripe billing service")
	return &Service{
		config:     cfg,
		sessDB:     sessDB,
		keyManager: km,
	}
}

// IsMock returns false for real service.
func (s *Service) IsMock() bool { return false }

// PublishableKey returns the Stripe publishable key for client-side JS.
func (s *Service) PublishableKey() string {
	return s.config.PublishableKey
}

// CreateCheckoutSession creates a Stripe Embedded Checkout session.
// plan must be "monthly" or "annual".
// userID may be empty for logged-out purchases.
func (s *Service) CreateCheckoutSession(ctx context.Context, userID, email, plan, baseURL string) (string, error) {
	var priceID string
	switch plan {
	case "monthly":
		priceID = s.config.PriceMonthly
	case "annual":
		priceID = s.config.PriceAnnual
	default:
		return "", fmt.Errorf("invalid plan: %s (must be 'monthly' or 'annual')", plan)
	}

	params := &stripe.CheckoutSessionParams{
		UIMode: stripe.String("embedded"),
		Mode:   stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(1),
			},
		},
		RedirectOnCompletion: stripe.String("always"),
		ReturnURL:            stripe.String(baseURL + "/billing/success?session_id={CHECKOUT_SESSION_ID}"),
	}

	if userID != "" {
		params.ClientReferenceID = stripe.String(userID)
	}
	if email != "" {
		params.CustomerEmail = stripe.String(email)
	}

	sess, err := checkoutsession.New(params)
	if err != nil {
		return "", fmt.Errorf("create checkout session: %w", err)
	}

	return sess.ClientSecret, nil
}

// CreatePortalSession creates a Stripe Customer Portal session.
func (s *Service) CreatePortalSession(ctx context.Context, stripeCustomerID, returnURL string) (string, error) {
	params := &stripe.BillingPortalSessionParams{
		Customer:  stripe.String(stripeCustomerID),
		ReturnURL: stripe.String(returnURL),
	}

	sess, err := portalsession.New(params)
	if err != nil {
		return "", fmt.Errorf("create portal session: %w", err)
	}

	return sess.URL, nil
}

// GetSessionStatus retrieves the status of a checkout session.
func (s *Service) GetSessionStatus(ctx context.Context, sessionID string) (string, string, error) {
	sess, err := checkoutsession.Get(sessionID, nil)
	if err != nil {
		return "", "", fmt.Errorf("get checkout session: %w", err)
	}

	var customerEmail string
	if sess.CustomerDetails != nil {
		customerEmail = sess.CustomerDetails.Email
	}

	return string(sess.Status), customerEmail, nil
}
