// Package e2e provides property-based tests for auth account operations.
// Tests: register→login roundtrip, login rejects unregistered, register rejects
// duplicate, wrong password rejection, return_to redirect, and open redirect prevention.
package e2e

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/kuitang/agent-notes/tests/e2e/testutil"
)

// =============================================================================
// AUTH ACCOUNT PROPERTY TESTS
// =============================================================================

// setupAuthTestServer creates a webFormServer for auth tests running under rapid.T.
// rapid.T doesn't have TempDir(), so we use os.MkdirTemp and clean up manually.
// Returns the server and a cleanup function.
func setupAuthTestServer(rt *rapid.T) (*webFormServer, func()) {
	tempDir, err := os.MkdirTemp("", "auth-accounts-*")
	if err != nil {
		rt.Fatalf("Failed to create temp dir: %v", err)
	}
	webFormTestMutex.Lock()
	ts := createWebFormServer(tempDir)
	return ts, func() {
		ts.cleanup()
		os.RemoveAll(tempDir)
	}
}

// --- Property 1: register → login roundtrip ---

func testAuthAccounts_RegisterLoginRoundtrip(rt *rapid.T) {
	ts, cleanup := setupAuthTestServer(rt)
	defer cleanup()

	email := testutil.EmailGenerator().Draw(rt, "email")
	password := testutil.PasswordGenerator().Draw(rt, "password")

	jar, _ := cookiejar.New(nil)
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Register
	regResp, err := client.PostForm(ts.URL+"/auth/register", url.Values{
		"email":    {email},
		"password": {password},
	})
	if err != nil {
		rt.Fatalf("Register request failed: %v", err)
	}
	regResp.Body.Close()

	if regResp.StatusCode != http.StatusSeeOther && regResp.StatusCode != http.StatusFound {
		rt.Fatalf("Register should redirect, got %d", regResp.StatusCode)
	}

	// Verify session cookie was set
	regSessionFound := false
	for _, c := range regResp.Cookies() {
		if c.Name == "session_id" && c.Value != "" {
			regSessionFound = true
			break
		}
	}
	if !regSessionFound {
		rt.Fatal("Register should set session cookie")
	}

	// Login with same credentials (fresh client, no existing session)
	jar2, _ := cookiejar.New(nil)
	client2 := ts.Client()
	client2.Jar = jar2
	client2.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	loginResp, err := client2.PostForm(ts.URL+"/auth/login", url.Values{
		"email":    {email},
		"password": {password},
	})
	if err != nil {
		rt.Fatalf("Login request failed: %v", err)
	}
	loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusSeeOther && loginResp.StatusCode != http.StatusFound {
		rt.Fatalf("Login should redirect, got %d", loginResp.StatusCode)
	}

	// Verify session cookie was set
	loginSessionFound := false
	for _, c := range loginResp.Cookies() {
		if c.Name == "session_id" && c.Value != "" {
			loginSessionFound = true
			break
		}
	}
	if !loginSessionFound {
		rt.Fatal("Login should set session cookie")
	}

	// Redirect should be to /notes
	location := loginResp.Header.Get("Location")
	if !strings.Contains(location, "/notes") {
		rt.Fatalf("Login should redirect to /notes, got: %s", location)
	}
}

func TestAuthAccounts_RegisterLoginRoundtrip(t *testing.T) {
	rapid.Check(t, testAuthAccounts_RegisterLoginRoundtrip)
}

func FuzzAuthAccounts_RegisterLoginRoundtrip(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testAuthAccounts_RegisterLoginRoundtrip))
}

// --- Property 2: login rejects unregistered email ---

func testAuthAccounts_LoginRejectsUnregistered(rt *rapid.T) {
	ts, cleanup := setupAuthTestServer(rt)
	defer cleanup()

	email := testutil.EmailGenerator().Draw(rt, "email")
	password := testutil.PasswordGenerator().Draw(rt, "password")

	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Login without registering
	loginResp, err := client.PostForm(ts.URL+"/auth/login", url.Values{
		"email":    {email},
		"password": {password},
	})
	if err != nil {
		rt.Fatalf("Login request failed: %v", err)
	}
	loginResp.Body.Close()

	// Should redirect to /login with error (not to /notes)
	if loginResp.StatusCode != http.StatusSeeOther && loginResp.StatusCode != http.StatusFound {
		rt.Fatalf("Login should redirect, got %d", loginResp.StatusCode)
	}

	location := loginResp.Header.Get("Location")
	if strings.Contains(location, "/notes") {
		rt.Fatal("Login for unregistered email should NOT redirect to /notes")
	}
	if !strings.Contains(location, "/login") || !strings.Contains(location, "error") {
		rt.Fatalf("Login should redirect to /login with error, got: %s", location)
	}
}

func TestAuthAccounts_LoginRejectsUnregistered(t *testing.T) {
	rapid.Check(t, testAuthAccounts_LoginRejectsUnregistered)
}

func FuzzAuthAccounts_LoginRejectsUnregistered(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testAuthAccounts_LoginRejectsUnregistered))
}

// --- Property 3: register rejects duplicate email ---

func testAuthAccounts_RegisterRejectsDuplicate(rt *rapid.T) {
	ts, cleanup := setupAuthTestServer(rt)
	defer cleanup()

	email := testutil.EmailGenerator().Draw(rt, "email")
	password := testutil.PasswordGenerator().Draw(rt, "password")

	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// First registration should succeed
	regResp1, err := client.PostForm(ts.URL+"/auth/register", url.Values{
		"email":    {email},
		"password": {password},
	})
	if err != nil {
		rt.Fatalf("First register failed: %v", err)
	}
	regResp1.Body.Close()

	if regResp1.StatusCode != http.StatusSeeOther && regResp1.StatusCode != http.StatusFound {
		rt.Fatalf("First register should redirect, got %d", regResp1.StatusCode)
	}

	// Second registration with same email should fail
	regResp2, err := client.PostForm(ts.URL+"/auth/register", url.Values{
		"email":    {email},
		"password": {password},
	})
	if err != nil {
		rt.Fatalf("Second register failed: %v", err)
	}
	regResp2.Body.Close()

	// Should redirect to /login with account-exists error
	if regResp2.StatusCode != http.StatusSeeOther && regResp2.StatusCode != http.StatusFound {
		rt.Fatalf("Duplicate register should redirect, got %d", regResp2.StatusCode)
	}

	location := regResp2.Header.Get("Location")
	if strings.Contains(location, "/notes") {
		rt.Fatal("Duplicate register should NOT redirect to /notes")
	}
	if !strings.Contains(location, "/login") {
		rt.Fatalf("Duplicate register should redirect to /login, got: %s", location)
	}
}

func TestAuthAccounts_RegisterRejectsDuplicate(t *testing.T) {
	rapid.Check(t, testAuthAccounts_RegisterRejectsDuplicate)
}

func FuzzAuthAccounts_RegisterRejectsDuplicate(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testAuthAccounts_RegisterRejectsDuplicate))
}

// --- Property 4: login rejects wrong password ---

func testAuthAccounts_LoginRejectsWrongPassword(rt *rapid.T) {
	ts, cleanup := setupAuthTestServer(rt)
	defer cleanup()

	email := testutil.EmailGenerator().Draw(rt, "email")
	password := testutil.PasswordGenerator().Draw(rt, "password")
	wrongPassword := testutil.PasswordGenerator().Draw(rt, "wrongPassword")

	// Ensure passwords are different
	if password == wrongPassword {
		wrongPassword = password + "X"
	}

	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Register
	regResp, err := client.PostForm(ts.URL+"/auth/register", url.Values{
		"email":    {email},
		"password": {password},
	})
	if err != nil {
		rt.Fatalf("Register failed: %v", err)
	}
	regResp.Body.Close()

	// Login with wrong password
	loginResp, err := client.PostForm(ts.URL+"/auth/login", url.Values{
		"email":    {email},
		"password": {wrongPassword},
	})
	if err != nil {
		rt.Fatalf("Login request failed: %v", err)
	}
	loginResp.Body.Close()

	// Should redirect to /login with error
	if loginResp.StatusCode != http.StatusSeeOther && loginResp.StatusCode != http.StatusFound {
		rt.Fatalf("Wrong password login should redirect, got %d", loginResp.StatusCode)
	}

	location := loginResp.Header.Get("Location")
	if strings.Contains(location, "/notes") {
		rt.Fatal("Wrong password should NOT redirect to /notes")
	}
	if !strings.Contains(location, "/login") || !strings.Contains(location, "error") {
		rt.Fatalf("Wrong password should redirect to /login with error, got: %s", location)
	}

	// No session cookie should be set
	for _, c := range loginResp.Cookies() {
		if c.Name == "session_id" && c.Value != "" {
			rt.Fatal("Wrong password should NOT set session cookie")
		}
	}
}

func TestAuthAccounts_LoginRejectsWrongPassword(t *testing.T) {
	rapid.Check(t, testAuthAccounts_LoginRejectsWrongPassword)
}

func FuzzAuthAccounts_LoginRejectsWrongPassword(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testAuthAccounts_LoginRejectsWrongPassword))
}

// --- Property 5: return_to roundtrip through login ---

func testAuthAccounts_ReturnToRoundtrip(rt *rapid.T) {
	ts, cleanup := setupAuthTestServer(rt)
	defer cleanup()

	email := testutil.EmailGenerator().Draw(rt, "email")
	password := testutil.PasswordGenerator().Draw(rt, "password")

	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Register first
	regResp, err := client.PostForm(ts.URL+"/auth/register", url.Values{
		"email":    {email},
		"password": {password},
	})
	if err != nil {
		rt.Fatalf("Register failed: %v", err)
	}
	regResp.Body.Close()

	// Login with return_to
	returnTo := "/oauth/authorize?client_id=test&redirect_uri=http://localhost:3000/callback"

	jar, _ := cookiejar.New(nil)
	loginClient := ts.Client()
	loginClient.Jar = jar
	loginClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	loginResp, err := loginClient.PostForm(ts.URL+"/auth/login", url.Values{
		"email":     {email},
		"password":  {password},
		"return_to": {returnTo},
	})
	if err != nil {
		rt.Fatalf("Login request failed: %v", err)
	}
	loginResp.Body.Close()

	// Should redirect to the return_to URL, not /notes
	if loginResp.StatusCode != http.StatusSeeOther && loginResp.StatusCode != http.StatusFound {
		rt.Fatalf("Login should redirect, got %d", loginResp.StatusCode)
	}

	location := loginResp.Header.Get("Location")
	if !strings.HasPrefix(location, "/oauth/authorize") {
		rt.Fatalf("Login with return_to should redirect to return_to path, got: %s", location)
	}
}

func TestAuthAccounts_ReturnToRoundtrip(t *testing.T) {
	rapid.Check(t, testAuthAccounts_ReturnToRoundtrip)
}

func FuzzAuthAccounts_ReturnToRoundtrip(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testAuthAccounts_ReturnToRoundtrip))
}

// --- Property 6: return_to rejects external URLs ---

func testAuthAccounts_ReturnToRejectsExternal(rt *rapid.T) {
	ts, cleanup := setupAuthTestServer(rt)
	defer cleanup()

	email := testutil.EmailGenerator().Draw(rt, "email")
	password := testutil.PasswordGenerator().Draw(rt, "password")

	client := ts.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Register first
	regResp, err := client.PostForm(ts.URL+"/auth/register", url.Values{
		"email":    {email},
		"password": {password},
	})
	if err != nil {
		rt.Fatalf("Register failed: %v", err)
	}
	regResp.Body.Close()

	// Test various external/malicious return_to values
	evilURLs := []string{
		"https://evil.com",
		"http://evil.com",
		"//evil.com",
		"javascript:alert(1)",
	}

	for _, evilURL := range evilURLs {
		jar, _ := cookiejar.New(nil)
		loginClient := ts.Client()
		loginClient.Jar = jar
		loginClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		loginResp, err := loginClient.PostForm(ts.URL+"/auth/login", url.Values{
			"email":     {email},
			"password":  {password},
			"return_to": {evilURL},
		})
		if err != nil {
			rt.Fatalf("Login request failed for %q: %v", evilURL, err)
		}
		loginResp.Body.Close()

		// Should redirect to /notes (fallback), not to the evil URL
		location := loginResp.Header.Get("Location")
		if strings.Contains(location, "evil.com") || strings.Contains(location, "javascript") {
			rt.Fatalf("Login should NOT redirect to external URL %q, got: %s", evilURL, location)
		}
		if !strings.Contains(location, "/notes") {
			rt.Fatalf("Login with external return_to should redirect to /notes, got: %s (for %q)", location, evilURL)
		}
	}
}

func TestAuthAccounts_ReturnToRejectsExternal(t *testing.T) {
	rapid.Check(t, testAuthAccounts_ReturnToRejectsExternal)
}

func FuzzAuthAccounts_ReturnToRejectsExternal(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testAuthAccounts_ReturnToRejectsExternal))
}

// --- Property 7: return_to propagates through register link ---

func testAuthAccounts_ReturnToPropagatesThroughRegister(rt *rapid.T) {
	ts, cleanup := setupAuthTestServer(rt)
	defer cleanup()

	client := ts.Client()

	returnTo := "/oauth/authorize?client_id=test123"

	// GET /login with return_to
	loginResp, err := client.Get(ts.URL + "/login?return_to=" + url.QueryEscape(returnTo))
	if err != nil {
		rt.Fatalf("Login page request failed: %v", err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusOK {
		rt.Fatalf("Login page should return 200, got %d", loginResp.StatusCode)
	}

	loginBody, _ := io.ReadAll(loginResp.Body)
	loginHTML := string(loginBody)

	// The login page should contain the return_to in:
	// 1. The hidden input in the form
	if !strings.Contains(loginHTML, returnTo) {
		rt.Fatal("Login page should contain return_to value in hidden input")
	}

	// 2. The "create account" link should include return_to
	if !strings.Contains(loginHTML, "/register?return_to=") {
		rt.Fatal("Login page 'create account' link should include return_to parameter")
	}

	// GET /register with return_to
	registerResp, err := client.Get(ts.URL + "/register?return_to=" + url.QueryEscape(returnTo))
	if err != nil {
		rt.Fatalf("Register page request failed: %v", err)
	}
	defer registerResp.Body.Close()

	if registerResp.StatusCode != http.StatusOK {
		rt.Fatalf("Register page should return 200, got %d", registerResp.StatusCode)
	}

	registerBody, _ := io.ReadAll(registerResp.Body)
	registerHTML := string(registerBody)

	// The register page should contain the return_to in:
	// 1. The hidden input
	if !strings.Contains(registerHTML, returnTo) {
		rt.Fatal("Register page should contain return_to value in hidden input")
	}

	// 2. The "Sign in" link should include return_to
	if !strings.Contains(registerHTML, "/login?return_to=") {
		rt.Fatal("Register page 'Sign in' link should include return_to parameter")
	}
}

func TestAuthAccounts_ReturnToPropagatesThroughRegister(t *testing.T) {
	rapid.Check(t, testAuthAccounts_ReturnToPropagatesThroughRegister)
}

func FuzzAuthAccounts_ReturnToPropagatesThroughRegister(f *testing.F) {
	f.Add([]byte{0x00})
	f.Fuzz(rapid.MakeFuzz(testAuthAccounts_ReturnToPropagatesThroughRegister))
}
