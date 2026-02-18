package billing

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/userdb"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhook"
)

// HandleWebhook processes a Stripe webhook event.
// It verifies the signature, checks idempotency, and routes to the appropriate handler.
func (s *Service) HandleWebhook(payload []byte, sigHeader string) error {
	event, err := webhook.ConstructEvent(payload, sigHeader, s.config.WebhookSecret)
	if err != nil {
		return fmt.Errorf("verify webhook signature: %w", err)
	}

	ctx := context.Background()

	// Idempotency check: look up event in processed_webhook_events table
	var existing string
	err = s.sessDB.DB().QueryRowContext(ctx,
		`SELECT event_id FROM processed_webhook_events WHERE event_id = ?`, event.ID,
	).Scan(&existing)
	if err == nil {
		// Already processed
		log.Printf("[BILLING] Webhook event %s already processed, skipping", event.ID)
		return nil
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("check webhook idempotency: %w", err)
	}

	// Route event
	switch event.Type {
	case "checkout.session.completed":
		if err := s.handleCheckoutCompleted(ctx, event); err != nil {
			return fmt.Errorf("handle checkout.session.completed: %w", err)
		}
	case "customer.subscription.updated":
		if err := s.handleSubscriptionUpdated(ctx, event); err != nil {
			return fmt.Errorf("handle customer.subscription.updated: %w", err)
		}
	case "customer.subscription.deleted":
		if err := s.handleSubscriptionDeleted(ctx, event); err != nil {
			return fmt.Errorf("handle customer.subscription.deleted: %w", err)
		}
	case "invoice.payment_failed":
		if err := s.handlePaymentFailed(ctx, event); err != nil {
			return fmt.Errorf("handle invoice.payment_failed: %w", err)
		}
	default:
		log.Printf("[BILLING] Unhandled webhook event type: %s", event.Type)
	}

	// Mark event as processed
	_, err = s.sessDB.DB().ExecContext(ctx,
		`INSERT INTO processed_webhook_events (event_id, processed_at) VALUES (?, ?)`,
		event.ID, time.Now().Unix(),
	)
	if err != nil {
		log.Printf("[BILLING] Warning: failed to mark event %s as processed: %v", event.ID, err)
	}

	return nil
}

func (s *Service) handleCheckoutCompleted(ctx context.Context, event stripe.Event) error {
	var checkoutSession stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &checkoutSession); err != nil {
		return fmt.Errorf("unmarshal checkout session: %w", err)
	}

	customerID := checkoutSession.Customer.ID
	subscriptionID := ""
	if checkoutSession.Subscription != nil {
		subscriptionID = checkoutSession.Subscription.ID
	}
	email := ""
	if checkoutSession.CustomerDetails != nil {
		email = checkoutSession.CustomerDetails.Email
	}
	userID := checkoutSession.ClientReferenceID

	log.Printf("[BILLING] Checkout completed: customer=%s, subscription=%s, email=%s, userID=%s",
		customerID, subscriptionID, email, userID)

	if userID != "" {
		// Logged-in purchase: map Stripe customer to user
		_, err := s.sessDB.DB().ExecContext(ctx,
			`INSERT OR IGNORE INTO stripe_customer_map (stripe_customer_id, user_id) VALUES (?, ?)`,
			customerID, userID,
		)
		if err != nil {
			return fmt.Errorf("create stripe customer map: %w", err)
		}
		log.Printf("[BILLING] Mapped Stripe customer %s -> user %s", customerID, userID)

		// Update user's per-user encrypted DB with subscription status
		if err := s.updateUserSubscriptionFull(ctx, userID, "active", subscriptionID, customerID); err != nil {
			return fmt.Errorf("update user subscription (checkout completed): %w", err)
		}
	} else if email != "" {
		// Logged-out purchase: store as pending subscription
		_, err := s.sessDB.DB().ExecContext(ctx,
			`INSERT OR REPLACE INTO pending_subscriptions (email, stripe_customer_id, subscription_id, subscription_status, created_at) VALUES (?, ?, ?, ?, ?)`,
			email, customerID, subscriptionID, "active", time.Now().Unix(),
		)
		if err != nil {
			return fmt.Errorf("create pending subscription: %w", err)
		}
		log.Printf("[BILLING] Created pending subscription for email %s", email)
	}

	return nil
}

func (s *Service) handleSubscriptionUpdated(ctx context.Context, event stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return fmt.Errorf("unmarshal subscription: %w", err)
	}

	customerID := sub.Customer.ID
	status := string(sub.Status)

	log.Printf("[BILLING] Subscription updated: customer=%s, status=%s", customerID, status)

	// Look up user by Stripe customer ID
	var userID string
	err := s.sessDB.DB().QueryRowContext(ctx,
		`SELECT user_id FROM stripe_customer_map WHERE stripe_customer_id = ?`, customerID,
	).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("[BILLING] No user mapping for Stripe customer %s, skipping", customerID)
			return nil
		}
		return fmt.Errorf("get stripe customer map: %w", err)
	}

	log.Printf("[BILLING] Subscription %s for user %s -> status: %s", sub.ID, userID, status)

	// Update user's per-user encrypted DB with subscription status
	if err := s.updateUserSubscription(ctx, userID, status, sub.ID); err != nil {
		return fmt.Errorf("update user subscription (subscription updated): %w", err)
	}

	return nil
}

func (s *Service) handleSubscriptionDeleted(ctx context.Context, event stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return fmt.Errorf("unmarshal subscription: %w", err)
	}

	customerID := sub.Customer.ID
	log.Printf("[BILLING] Subscription deleted: customer=%s", customerID)

	var userID string
	err := s.sessDB.DB().QueryRowContext(ctx,
		`SELECT user_id FROM stripe_customer_map WHERE stripe_customer_id = ?`, customerID,
	).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("[BILLING] No user mapping for Stripe customer %s, skipping", customerID)
			return nil
		}
		return fmt.Errorf("get stripe customer map: %w", err)
	}

	log.Printf("[BILLING] Subscription deleted for user %s, status -> free", userID)

	// Update user's per-user encrypted DB: reset to free tier
	if err := s.updateUserSubscription(ctx, userID, "free", ""); err != nil {
		return fmt.Errorf("update user subscription (subscription deleted): %w", err)
	}

	return nil
}

func (s *Service) handlePaymentFailed(ctx context.Context, event stripe.Event) error {
	var invoice stripe.Invoice
	if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
		return fmt.Errorf("unmarshal invoice: %w", err)
	}

	customerID := ""
	if invoice.Customer != nil {
		customerID = invoice.Customer.ID
	}
	log.Printf("[BILLING] Payment failed: customer=%s", customerID)

	if customerID == "" {
		return nil
	}

	// Look up user by Stripe customer ID
	var userID string
	err := s.sessDB.DB().QueryRowContext(ctx,
		`SELECT user_id FROM stripe_customer_map WHERE stripe_customer_id = ?`, customerID,
	).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("[BILLING] No user mapping for Stripe customer %s, skipping payment failure", customerID)
			return nil
		}
		return fmt.Errorf("get stripe customer map for payment failure: %w", err)
	}

	subscriptionID := ""
	if invoice.Parent != nil && invoice.Parent.SubscriptionDetails != nil && invoice.Parent.SubscriptionDetails.Subscription != nil {
		subscriptionID = invoice.Parent.SubscriptionDetails.Subscription.ID
	}

	// Update user's per-user encrypted DB: set status to past_due
	if err := s.updateUserSubscription(ctx, userID, "past_due", subscriptionID); err != nil {
		return fmt.Errorf("update user subscription (payment failed): %w", err)
	}

	log.Printf("[BILLING] Payment failed for user %s, status -> past_due", userID)
	return nil
}

// updateUserSubscription opens the user's encrypted DB and updates subscription_status and subscription_id.
func (s *Service) updateUserSubscription(ctx context.Context, userID, status, subscriptionID string) error {
	dek, err := s.keyManager.GetUserDEK(userID)
	if err != nil {
		return fmt.Errorf("get user DEK for %s: %w", userID, err)
	}

	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		return fmt.Errorf("open user DB for %s: %w", userID, err)
	}

	subID := sql.NullString{}
	if subscriptionID != "" {
		subID = sql.NullString{String: subscriptionID, Valid: true}
	}

	err = userDB.Queries().UpdateAccountSubscription(ctx, userdb.UpdateAccountSubscriptionParams{
		SubscriptionStatus: sql.NullString{String: status, Valid: true},
		SubscriptionID:     subID,
		UserID:             userID,
	})
	if err != nil {
		return fmt.Errorf("update account subscription for %s: %w", userID, err)
	}

	log.Printf("[BILLING] Updated user %s subscription: status=%s, subscription_id=%s", userID, status, subscriptionID)
	return nil
}

// updateUserSubscriptionFull opens the user's encrypted DB and updates subscription_status, subscription_id, and stripe_customer_id.
func (s *Service) updateUserSubscriptionFull(ctx context.Context, userID, status, subscriptionID, stripeCustomerID string) error {
	dek, err := s.keyManager.GetUserDEK(userID)
	if err != nil {
		return fmt.Errorf("get user DEK for %s: %w", userID, err)
	}

	userDB, err := db.OpenUserDBWithDEK(userID, dek)
	if err != nil {
		return fmt.Errorf("open user DB for %s: %w", userID, err)
	}

	subID := sql.NullString{}
	if subscriptionID != "" {
		subID = sql.NullString{String: subscriptionID, Valid: true}
	}

	custID := sql.NullString{}
	if stripeCustomerID != "" {
		custID = sql.NullString{String: stripeCustomerID, Valid: true}
	}

	err = userDB.Queries().UpdateAccountSubscriptionFull(ctx, userdb.UpdateAccountSubscriptionFullParams{
		SubscriptionStatus: sql.NullString{String: status, Valid: true},
		SubscriptionID:     subID,
		StripeCustomerID:   custID,
		UserID:             userID,
	})
	if err != nil {
		return fmt.Errorf("update account subscription full for %s: %w", userID, err)
	}

	log.Printf("[BILLING] Updated user %s subscription (full): status=%s, subscription_id=%s, stripe_customer_id=%s",
		userID, status, subscriptionID, stripeCustomerID)
	return nil
}
