// Package e2e provides property-based e2e tests for account settings and linking.
// These tests verify the account linking flows (password + Google) via HTTP,
// using the webFormServer infrastructure which includes all web routes and
// the local mock OIDC provider.
package e2e

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

// setupWebFormServerRapid creates a webFormServer for rapid.T / fuzz tests.
// Unlike setupWebFormServer, this does not require a testing.TB.
func setupWebFormServerRapid() *webFormServer {
	webFormTestMutex.Lock()
	tempDir, err := os.MkdirTemp("", "accountlink-test-*")
	if err != nil {
		panic("Failed to create temp dir: " + err.Error())
	}
	return createWebFormServer(tempDir)
}

// =============================================================================
// HELPERS
// =============================================================================

// registerPasswordUser registers a new user via POST /auth/register and returns
// a client with a valid session cookie. The client has CheckRedirect set to
// http.ErrUseLastResponse so callers can inspect redirect responses.
func registerPasswordUser(t testFataler, ts *webFormServer, email, password string) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	form := url.Values{
		"email":            {email},
		"password":         {password},
		"confirm_password": {password},
		"terms":            {"on"},
	}
	resp, err := client.PostForm(ts.URL+"/auth/register", form)
	if err != nil {
		t.Fatalf("POST /auth/register failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected redirect from /auth/register, got %d", resp.StatusCode)
	}
	return client
}

// loginWithPassword logs in via POST /auth/login and returns a client with a
// valid session cookie. Fatals if the login does not redirect (success).
func loginWithPassword(t testFataler, ts *webFormServer, email, password string) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	form := url.Values{
		"email":    {email},
		"password": {password},
	}
	resp, err := client.PostForm(ts.URL+"/auth/login", form)
	if err != nil {
		t.Fatalf("POST /auth/login failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("password login should redirect, got %d", resp.StatusCode)
	}
	return client
}

// loginWithMockOIDC performs a full mock OIDC login and returns a client with a
// valid session cookie.
func loginWithMockOIDC(t testFataler, ts *webFormServer, email string) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := ts.Client()
	client.Jar = jar

	auth.SetSecureCookies(false)

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	doMockOIDCLogin(t, client, ts.URL, email)
	return client
}

// logoutClient performs POST /auth/logout with the given client.
func logoutClient(t testFataler, ts *webFormServer, client *http.Client) {
	resp, err := client.PostForm(ts.URL+"/auth/logout", nil)
	if err != nil {
		t.Fatalf("POST /auth/logout failed: %v", err)
	}
	resp.Body.Close()
}

// doLinkGoogle performs the full link-google flow:
// POST /settings/link-google -> follows OIDC mock consent -> callback.
// The client must already be authenticated (has session cookie).
func doLinkGoogle(t testFataler, ts *webFormServer, client *http.Client, email string) {
	// Step 1: POST /settings/link-google sets oauth_intent=link, redirects to /auth/google
	resp, err := client.PostForm(ts.URL+"/settings/link-google", nil)
	if err != nil {
		t.Fatalf("POST /settings/link-google failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect from /settings/link-google, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("no Location header from /settings/link-google")
	}

	// Make the location absolute if relative
	if !strings.HasPrefix(loc, "http") {
		loc = ts.URL + loc
	}

	// Step 2: Follow redirect to /auth/google (which redirects to mock OIDC)
	resp2, err := client.Get(loc)
	if err != nil {
		t.Fatalf("GET %s failed: %v", loc, err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /auth/google, got %d", resp2.StatusCode)
	}

	authURL := resp2.Header.Get("Location")
	if authURL == "" {
		t.Fatal("no Location header from /auth/google")
	}
	if !strings.HasPrefix(authURL, "http") {
		authURL = ts.URL + authURL
	}

	// Extract state from auth URL
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth URL %q: %v", authURL, err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("no state in auth URL")
	}

	// Step 3: GET consent form (verify it renders)
	consentResp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET consent form failed: %v", err)
	}
	consentResp.Body.Close()
	if consentResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from consent form, got %d", consentResp.StatusCode)
	}

	// Step 4: POST consent with email + state
	form := url.Values{"state": {state}, "email": {email}}
	consentPostResp, err := client.PostForm(ts.URL+"/auth/mock-oidc/authorize", form)
	if err != nil {
		t.Fatalf("POST consent failed: %v", err)
	}
	consentPostResp.Body.Close()
	if consentPostResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from consent POST, got %d", consentPostResp.StatusCode)
	}

	callbackURL := consentPostResp.Header.Get("Location")
	if callbackURL == "" {
		t.Fatal("no Location header from consent POST")
	}
	if !strings.HasPrefix(callbackURL, "http") {
		callbackURL = ts.URL + callbackURL
	}

	// Step 5: Follow callback redirect (this is the link flow completion)
	callbackResp, err := client.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	callbackResp.Body.Close()
	if callbackResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from callback (link flow), got %d", callbackResp.StatusCode)
	}

	// Should redirect to /settings/account?success=google_linked
	callbackLoc := callbackResp.Header.Get("Location")
	if !strings.Contains(callbackLoc, "google_linked") {
		t.Fatalf("expected redirect to settings with google_linked, got %q", callbackLoc)
	}
}

// getSettingsBody fetches GET /settings/account and returns the response body as a string.
func getSettingsBody(t testFataler, ts *webFormServer, client *http.Client) string {
	resp, err := client.Get(ts.URL + "/settings/account")
	if err != nil {
		t.Fatalf("GET /settings/account failed: %v", err)
	}
	defer resp.Body.Close()

	// The webFormServer uses RequireAuthWithRedirect, so a 302 to /login means
	// no session. For authenticated requests we expect 200.
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "/login") {
			t.Fatal("GET /settings/account redirected to login -- session missing or invalid")
		}
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings/account returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading settings body: %v", err)
	}
	return string(body)
}

// =============================================================================
// P1: Roundtrip -- password register -> link Google -> verify both methods work
// =============================================================================

func testAccountLinking_PasswordThenGoogle(t *rapid.T, ts *webFormServer) {
	email := testutil.EmailGenerator().Draw(t, "email")
	password := testutil.PasswordGenerator().Draw(t, "password")

	auth.SetSecureCookies(false)
	defer auth.SetSecureCookies(true)

	// 1. Register with email/password
	client := registerPasswordUser(t, ts, email, password)

	// 2. Link Google account through the full OIDC flow
	doLinkGoogle(t, ts, client, email)

	// 3. Verify settings page shows both methods
	body := getSettingsBody(t, ts, client)
	if !strings.Contains(body, "Change Password") && !strings.Contains(body, "change-password-btn") {
		t.Fatal("settings page should show Change Password (HasPassword=true)")
	}
	if !strings.Contains(body, "Google account linked") {
		t.Fatal("settings page should show Google account linked (HasGoogle=true)")
	}

	// 4. Logout, then login with password
	logoutClient(t, ts, client)
	pwClient := loginWithPassword(t, ts, email, password)

	// Verify we can reach settings after password login
	pwBody := getSettingsBody(t, ts, pwClient)
	if !strings.Contains(pwBody, "Account Settings") {
		t.Fatal("after password login, should be able to reach account settings")
	}

	// 5. Logout, then login with Google (mock OIDC)
	logoutClient(t, ts, pwClient)
	googleClient := loginWithMockOIDC(t, ts, email)

	// Verify we can reach settings after Google login
	gBody := getSettingsBody(t, ts, googleClient)
	if !strings.Contains(gBody, "Account Settings") {
		t.Fatal("after Google login, should be able to reach account settings")
	}
}

func TestAccountLinking_PasswordThenGoogle_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testAccountLinking_PasswordThenGoogle(rt, ts)
	})
}

func FuzzAccountLinking_PasswordThenGoogle(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		ts := setupWebFormServerRapid()
		defer ts.cleanup()
		testAccountLinking_PasswordThenGoogle(t, ts)
	}))
}

// =============================================================================
// P2: Roundtrip -- Google register -> set password -> verify both methods work
// =============================================================================

func testAccountLinking_GoogleThenPassword(t *rapid.T, ts *webFormServer) {
	email := testutil.EmailGenerator().Draw(t, "email")
	password := testutil.PasswordGenerator().Draw(t, "password")

	auth.SetSecureCookies(false)
	defer auth.SetSecureCookies(true)

	// 1. Sign in with Google (creates account via mock OIDC)
	client := loginWithMockOIDC(t, ts, email)

	// 2. Verify settings page shows no password but has Google
	body := getSettingsBody(t, ts, client)
	if !strings.Contains(body, "Set Password") {
		t.Fatal("settings page for Google-only user should show 'Set Password'")
	}
	if !strings.Contains(body, "Google account linked") {
		t.Fatal("settings page should show Google account linked")
	}

	// 3. POST /settings/set-password (no current_password needed for initial set)
	form := url.Values{
		"new_password":     {password},
		"confirm_password": {password},
	}
	resp, err := client.PostForm(ts.URL+"/settings/set-password", form)
	if err != nil {
		t.Fatalf("POST /settings/set-password failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect from set-password, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "password_set") {
		t.Fatalf("expected redirect to settings with password_set success, got %q", loc)
	}

	// 4. Verify settings now shows HasPassword
	body2 := getSettingsBody(t, ts, client)
	if !strings.Contains(body2, "Change Password") && !strings.Contains(body2, "change-password-btn") {
		t.Fatal("settings page should show Change Password after setting password")
	}

	// 5. Logout, then login with password
	logoutClient(t, ts, client)
	pwClient := loginWithPassword(t, ts, email, password)

	// Verify access
	pwBody := getSettingsBody(t, ts, pwClient)
	if !strings.Contains(pwBody, "Account Settings") {
		t.Fatal("after password login, should be able to reach account settings")
	}
}

func TestAccountLinking_GoogleThenPassword_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testAccountLinking_GoogleThenPassword(rt, ts)
	})
}

func FuzzAccountLinking_GoogleThenPassword(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		ts := setupWebFormServerRapid()
		defer ts.cleanup()
		testAccountLinking_GoogleThenPassword(t, ts)
	}))
}

// =============================================================================
// P3: Guard -- can't unlink last auth method
// =============================================================================

func testAccountLinking_CantUnlinkLastMethod(t *rapid.T, ts *webFormServer) {
	email := testutil.EmailGenerator().Draw(t, "email")
	password := testutil.PasswordGenerator().Draw(t, "password")

	auth.SetSecureCookies(false)
	defer auth.SetSecureCookies(true)

	// --- Case A: Google-only user cannot unlink ---
	googleClient := loginWithMockOIDC(t, ts, email)

	// Attempt to unlink Google (should fail -- no password set)
	resp, err := googleClient.PostForm(ts.URL+"/settings/unlink-google", nil)
	if err != nil {
		t.Fatalf("POST /settings/unlink-google failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect from unlink-google, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "error") {
		t.Fatalf("Google-only user: unlink-google should redirect with error, got %q", loc)
	}

	// Verify settings page still shows Google linked
	body := getSettingsBody(t, ts, googleClient)
	if !strings.Contains(body, "Google account linked") {
		t.Fatal("Google should still be linked after failed unlink")
	}

	// --- Case B: User with both methods CAN unlink Google ---
	email2 := "both" + email
	client2 := registerPasswordUser(t, ts, email2, password)
	doLinkGoogle(t, ts, client2, email2)

	// Now unlink
	resp2, err := client2.PostForm(ts.URL+"/settings/unlink-google", nil)
	if err != nil {
		t.Fatalf("POST /settings/unlink-google (with password) failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusSeeOther && resp2.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect from unlink-google, got %d", resp2.StatusCode)
	}
	loc2 := resp2.Header.Get("Location")
	if !strings.Contains(loc2, "google_unlinked") {
		t.Fatalf("user with password: unlink-google should succeed, got %q", loc2)
	}

	// Verify settings page shows Google is no longer linked
	body2 := getSettingsBody(t, ts, client2)
	if strings.Contains(body2, "Google account linked") {
		t.Fatal("Google should be unlinked after successful unlink")
	}
	if !strings.Contains(body2, "Link Google Account") {
		t.Fatal("settings page should show option to link Google after unlinking")
	}
}

func TestAccountLinking_CantUnlinkLastMethod_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testAccountLinking_CantUnlinkLastMethod(rt, ts)
	})
}

func FuzzAccountLinking_CantUnlinkLastMethod(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		ts := setupWebFormServerRapid()
		defer ts.cleanup()
		testAccountLinking_CantUnlinkLastMethod(t, ts)
	}))
}

// =============================================================================
// P4: Guard -- Google sub mismatch rejects login
// =============================================================================

// TestAccountLinking_GoogleSubMismatch verifies that logging in with Google
// using a different sub for the same email is rejected (403).
// This is a scenario test (not property-based) because it tests a specific
// security invariant with deterministic setup.
func TestAccountLinking_GoogleSubMismatch(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	auth.SetSecureCookies(false)
	defer auth.SetSecureCookies(true)

	email := "submismatch@example.com"

	// Step 1: Register with password (no Google sub yet).
	registerPasswordUser(t, ts, email, "TestPassword123!")

	// Step 2: Directly link a fake Google sub that differs from what the
	// mock OIDC provider will return ("mock-<email>").
	userID := auth.GenerateUserID(email)
	if err := ts.userService.LinkGoogleAccount(context.Background(), userID, "different-sub-12345"); err != nil {
		t.Fatalf("LinkGoogleAccount (setup): %v", err)
	}

	// Step 3: Attempt Google login -- the mock returns sub "mock-<email>"
	// but stored sub is "different-sub-12345", so it should fail with 403.
	jar2, _ := cookiejar.New(nil)
	client2 := ts.Client()
	client2.Jar = jar2
	client2.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Start OIDC flow
	resp, err := client2.Post(ts.URL+"/auth/google", "", nil)
	if err != nil {
		t.Fatalf("POST /auth/google: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from /auth/google, got %d", resp.StatusCode)
	}

	authURL := resp.Header.Get("Location")
	if !strings.HasPrefix(authURL, "http") {
		authURL = ts.URL + authURL
	}

	parsed, _ := url.Parse(authURL)
	state := parsed.Query().Get("state")

	// GET consent form
	consentResp, err := client2.Get(authURL)
	if err != nil {
		t.Fatalf("GET consent form: %v", err)
	}
	consentResp.Body.Close()

	// POST consent
	form := url.Values{"state": {state}, "email": {email}}
	consentPostResp, err := client2.PostForm(ts.URL+"/auth/mock-oidc/authorize", form)
	if err != nil {
		t.Fatalf("POST consent: %v", err)
	}
	consentPostResp.Body.Close()

	callbackURL := consentPostResp.Header.Get("Location")
	if !strings.HasPrefix(callbackURL, "http") {
		callbackURL = ts.URL + callbackURL
	}

	// Follow callback -- should get 403 due to sub mismatch
	callbackResp, err := client2.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	defer callbackResp.Body.Close()

	if callbackResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(callbackResp.Body)
		t.Fatalf("expected 403 for sub mismatch, got %d: %s", callbackResp.StatusCode, string(body))
	}
}

// =============================================================================
// P5: Set password validation
// =============================================================================

func testAccountLinking_SetPasswordValidation(t *rapid.T, ts *webFormServer) {
	email := testutil.EmailGenerator().Draw(t, "email")
	password := testutil.PasswordGenerator().Draw(t, "password")

	auth.SetSecureCookies(false)
	defer auth.SetSecureCookies(true)

	// Register with password so the user has HasPassword=true
	client := registerPasswordUser(t, ts, email, password)

	// --- Case A: Missing current_password should redirect with error ---
	newPassword := testutil.PasswordGenerator().Draw(t, "newPassword")
	form := url.Values{
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
		// current_password deliberately omitted
	}
	resp, err := client.PostForm(ts.URL+"/settings/set-password", form)
	if err != nil {
		t.Fatalf("POST /settings/set-password (no current): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "error") || !strings.Contains(loc, "urrent") {
		t.Fatalf("missing current_password should error, got redirect %q", loc)
	}

	// --- Case B: Wrong current_password should redirect with error ---
	wrongForm := url.Values{
		"current_password": {"totallyWrongPassword123"},
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
	}
	resp2, err := client.PostForm(ts.URL+"/settings/set-password", wrongForm)
	if err != nil {
		t.Fatalf("POST /settings/set-password (wrong current): %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusSeeOther && resp2.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", resp2.StatusCode)
	}
	loc2 := resp2.Header.Get("Location")
	if !strings.Contains(loc2, "error") || !strings.Contains(loc2, "ncorrect") {
		t.Fatalf("wrong current_password should error, got redirect %q", loc2)
	}

	// --- Case C: Password mismatch (new != confirm) should redirect with error ---
	mismatchForm := url.Values{
		"current_password": {password},
		"new_password":     {newPassword},
		"confirm_password": {newPassword + "extra"},
	}
	resp3, err := client.PostForm(ts.URL+"/settings/set-password", mismatchForm)
	if err != nil {
		t.Fatalf("POST /settings/set-password (mismatch): %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusSeeOther && resp3.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", resp3.StatusCode)
	}
	loc3 := resp3.Header.Get("Location")
	if !strings.Contains(loc3, "error") || !strings.Contains(loc3, "match") {
		t.Fatalf("password mismatch should error, got redirect %q", loc3)
	}

	// --- Bonus: Verify the password was NOT changed (old password still works) ---
	logoutClient(t, ts, client)
	_ = loginWithPassword(t, ts, email, password)
}

func TestAccountLinking_SetPasswordValidation_Properties(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()
	rapid.Check(t, func(rt *rapid.T) {
		testAccountLinking_SetPasswordValidation(rt, ts)
	})
}

func FuzzAccountLinking_SetPasswordValidation(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(func(t *rapid.T) {
		ts := setupWebFormServerRapid()
		defer ts.cleanup()
		testAccountLinking_SetPasswordValidation(t, ts)
	}))
}

// =============================================================================
// P6: Register email pre-fill
// =============================================================================

// TestAccountLinking_RegisterEmailPreFill verifies that GET /register?email=X
// pre-fills the email input field in the registration form.
func TestAccountLinking_RegisterEmailPreFill(t *testing.T) {
	ts := setupWebFormServer(t)
	defer ts.cleanup()

	testEmail := "prefill@example.com"

	client := ts.Client()
	resp, err := client.Get(ts.URL + "/register?email=" + url.QueryEscape(testEmail))
	if err != nil {
		t.Fatalf("GET /register?email=... failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /register, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	// The template renders value="{{.Email}}" in the email input
	if !strings.Contains(html, `value="prefill@example.com"`) {
		t.Fatalf("register page should pre-fill email input with %q, body:\n%s", testEmail, html)
	}
}
