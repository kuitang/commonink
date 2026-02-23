package email

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestResendRenderTemplate_KnownTemplates(t *testing.T) {
	t.Parallel()
	svc := &ResendEmailService{}

	subject, html := svc.renderTemplate(TemplateMagicLink, MagicLinkData{
		Link:      "https://example.com/magic/token",
		ExpiresIn: "15 minutes",
	})
	if !strings.Contains(subject, "Sign in") {
		t.Fatalf("unexpected magic-link subject: %q", subject)
	}
	if !strings.Contains(html, "https://example.com/magic/token") {
		t.Fatalf("magic-link html missing link")
	}

	subject, html = svc.renderTemplate(TemplatePasswordReset, PasswordResetData{
		Link:      "https://example.com/reset/token",
		ExpiresIn: "1 hour",
	})
	if !strings.Contains(subject, "Reset your password") {
		t.Fatalf("unexpected password-reset subject: %q", subject)
	}
	if !strings.Contains(html, "https://example.com/reset/token") {
		t.Fatalf("password-reset html missing link")
	}

	subject, html = svc.renderTemplate(TemplateWelcome, WelcomeData{Name: "Ada"})
	if !strings.Contains(subject, "Welcome") {
		t.Fatalf("unexpected welcome subject: %q", subject)
	}
	if !strings.Contains(html, "Ada") {
		t.Fatalf("welcome html missing name")
	}
}

func testResendRenderTemplate_UnknownTemplateFallsBack(t *rapid.T) {
	svc := &ResendEmailService{}
	template := rapid.StringMatching(`[a-z0-9._-]{1,32}`).Draw(t, "template")
	data := rapid.StringMatching(`[A-Za-z0-9 _:/.-]{1,64}`).Draw(t, "data")

	subject, html := svc.renderTemplate(template, data)
	if subject == "" || html == "" {
		t.Fatalf("fallback template should return non-empty subject/html: subject=%q html=%q", subject, html)
	}
	if !strings.Contains(subject, "common.ink") {
		t.Fatalf("fallback subject mismatch: %q", subject)
	}
	if !strings.Contains(html, data) {
		t.Fatalf("fallback html should include input data: %q", html)
	}
}

func TestResendRenderTemplate_UnknownTemplateFallsBack(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testResendRenderTemplate_UnknownTemplateFallsBack)
}
