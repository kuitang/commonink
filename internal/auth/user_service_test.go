package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/db/userdb"
)

func TestUserService_ProviderFirstThenPassword_NoDuplicateAccount(t *testing.T) {
	svc, _, _ := setupMagicTestService(t)
	ctx := context.Background()

	emailAddr := "provider-first@example.com"
	password := "ProviderNowHasPassword123!"

	// Provider/magic-first path: creates account row with NULL password_hash.
	user, err := svc.FindOrCreateByProvider(ctx, emailAddr)
	if err != nil {
		t.Fatalf("FindOrCreateByProvider failed: %v", err)
	}

	dek, err := svc.keyManager.GetUserDEK(user.ID)
	if err != nil {
		t.Fatalf("GetUserDEK failed: %v", err)
	}
	userDB, err := db.OpenUserDBWithDEK(user.ID, dek)
	if err != nil {
		t.Fatalf("OpenUserDBWithDEK failed: %v", err)
	}

	account, err := userDB.Queries().GetAccountByEmail(ctx, emailAddr)
	if err != nil {
		t.Fatalf("GetAccountByEmail failed: %v", err)
	}
	if account.PasswordHash.Valid {
		t.Fatalf("expected password_hash to be NULL for provider-first account")
	}

	// Add password by updating existing account row, not inserting another one.
	passwordHash, err := svc.hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	err = userDB.Queries().UpdateAccountPasswordHash(ctx, userdb.UpdateAccountPasswordHashParams{
		PasswordHash: sql.NullString{String: passwordHash, Valid: true},
		UserID:       user.ID,
	})
	if err != nil {
		t.Fatalf("UpdateAccountPasswordHash failed: %v", err)
	}

	var accountRows int
	err = userDB.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM account WHERE email = ?", emailAddr).Scan(&accountRows)
	if err != nil {
		t.Fatalf("failed to count account rows: %v", err)
	}
	if accountRows != 1 {
		t.Fatalf("expected exactly 1 account row for %s, got %d", emailAddr, accountRows)
	}

	verifiedUser, err := svc.VerifyLogin(ctx, emailAddr, password)
	if err != nil {
		t.Fatalf("VerifyLogin should succeed after password update, got: %v", err)
	}
	if verifiedUser.ID != user.ID {
		t.Fatalf("VerifyLogin returned wrong user ID: got %s want %s", verifiedUser.ID, user.ID)
	}

	_, err = svc.RegisterWithPassword(ctx, emailAddr, "AnotherPass456!")
	if !errors.Is(err, ErrAccountExists) {
		t.Fatalf("RegisterWithPassword should return ErrAccountExists for provider-first account, got: %v", err)
	}
}
