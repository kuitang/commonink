// Package browser contains quick HTTP-based tests for template verification.
// These tests don't require Playwright and run quickly.
package browser

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestQuick_LoginPageRenders verifies the login page template renders correctly.
func TestQuick_LoginPageRenders(t *testing.T) {
	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	resp, err := http.Get(env.baseURL + "/login")
	if err != nil {
		t.Fatalf("Failed to get login page: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	bodyStr := string(body)

	// Verify expected elements
	checks := []struct {
		name     string
		expected string
	}{
		{"title", "<title>Sign In - Agent Notes</title>"},
		{"magic-email input", `id="magic-email"`},
		{"login-email input", `id="login-email"`},
		{"login-password input", `id="login-password"`},
		{"Google button", "Sign in with Google"},
	}

	for _, check := range checks {
		if !strings.Contains(bodyStr, check.expected) {
			t.Errorf("%s not found in response", check.name)
		}
	}
}

// TestQuick_RegisterPageRenders verifies the register page template renders correctly.
func TestQuick_RegisterPageRenders(t *testing.T) {
	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	resp, err := http.Get(env.baseURL + "/register")
	if err != nil {
		t.Fatalf("Failed to get register page: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	bodyStr := string(body)

	// Verify expected elements
	checks := []struct {
		name     string
		expected string
	}{
		{"title", "Create Account"},
		{"email input", `name="email"`},
		{"password input", `name="password"`},
		{"confirm password input", `name="confirm_password"`},
	}

	for _, check := range checks {
		if !strings.Contains(bodyStr, check.expected) {
			t.Errorf("%s not found in response", check.name)
		}
	}
}

// TestQuick_PasswordResetPageRenders verifies the password reset page template renders correctly.
func TestQuick_PasswordResetPageRenders(t *testing.T) {
	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	resp, err := http.Get(env.baseURL + "/password-reset")
	if err != nil {
		t.Fatalf("Failed to get password reset page: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	bodyStr := string(body)

	// Verify expected elements
	if !strings.Contains(bodyStr, "Reset") {
		t.Errorf("Reset text not found in response")
	}
}

// TestQuick_HealthEndpoint verifies the health endpoint works.
func TestQuick_HealthEndpoint(t *testing.T) {
	env, cleanup := setupAuthTestEnv(t)
	defer cleanup()

	resp, err := http.Get(env.baseURL + "/health")
	if err != nil {
		t.Fatalf("Failed to get health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}
