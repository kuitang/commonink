package email

import (
	"fmt"

	"github.com/resend/resend-go/v3"
)

// ResendEmailService implements EmailService using the Resend API.
type ResendEmailService struct {
	client      *resend.Client
	fromAddress string
}

// NewResendEmailService creates a new Resend email service.
// apiKey is the Resend API key.
// fromAddress is the sender email address (must be verified in Resend).
func NewResendEmailService(apiKey, fromAddress string) *ResendEmailService {
	return &ResendEmailService{
		client:      resend.NewClient(apiKey),
		fromAddress: fromAddress,
	}
}

// Send sends an email using the specified template via Resend.
func (r *ResendEmailService) Send(to, templateName string, data any) error {
	subject, html := r.renderTemplate(templateName, data)

	params := &resend.SendEmailRequest{
		From:    r.fromAddress,
		To:      []string{to},
		Subject: subject,
		Html:    html,
	}

	_, err := r.client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("resend: failed to send email: %w", err)
	}

	return nil
}

// SendMagicLink sends a magic link email to the specified recipient.
func (r *ResendEmailService) SendMagicLink(to, token string) error {
	return r.Send(to, TemplateMagicLink, MagicLinkData{
		Link:      token,
		ExpiresIn: "15 minutes",
	})
}

// SendPasswordReset sends a password reset email to the specified recipient.
func (r *ResendEmailService) SendPasswordReset(to, token string) error {
	return r.Send(to, TemplatePasswordReset, PasswordResetData{
		Link:      token,
		ExpiresIn: "1 hour",
	})
}

// SendWelcome sends a welcome email to the specified recipient.
func (r *ResendEmailService) SendWelcome(to, name string) error {
	return r.Send(to, TemplateWelcome, WelcomeData{
		Name: name,
	})
}

// renderTemplate renders the email template and returns subject and HTML body.
func (r *ResendEmailService) renderTemplate(templateName string, data any) (subject, html string) {
	switch templateName {
	case TemplateMagicLink:
		d := data.(MagicLinkData)
		subject = "Sign in to common.ink"
		html = renderMagicLinkHTML(d)
	case TemplatePasswordReset:
		d := data.(PasswordResetData)
		subject = "Reset your password - common.ink"
		html = renderPasswordResetHTML(d)
	case TemplateWelcome:
		d := data.(WelcomeData)
		subject = "Welcome to common.ink!"
		html = renderWelcomeHTML(d)
	default:
		subject = "Message from common.ink"
		html = fmt.Sprintf("<p>%+v</p>", data)
	}
	return
}

// renderMagicLinkHTML generates HTML for magic link emails.
func renderMagicLinkHTML(data MagicLinkData) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to common.ink</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">common.ink</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <h2 style="color: #333; margin-top: 0;">Sign in to your account</h2>
        <p>Click the button below to sign in to common.ink. This link will expire in <strong>%s</strong>.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="%s" style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 14px 30px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">Sign In</a>
        </div>
        <p style="color: #666; font-size: 14px;">If you didn't request this link, you can safely ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
        <p style="color: #999; font-size: 12px;">This is an automated message from common.ink. Please do not reply to this email.</p>
    </div>
</body>
</html>`, data.ExpiresIn, data.Link)
}

// renderPasswordResetHTML generates HTML for password reset emails.
func renderPasswordResetHTML(data PasswordResetData) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset your password</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">common.ink</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <h2 style="color: #333; margin-top: 0;">Reset your password</h2>
        <p>We received a request to reset your password. Click the button below to create a new password. This link will expire in <strong>%s</strong>.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="%s" style="background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%); color: white; padding: 14px 30px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">Reset Password</a>
        </div>
        <p style="color: #666; font-size: 14px;">If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
        <p style="color: #999; font-size: 12px;">This is an automated message from common.ink. Please do not reply to this email.</p>
    </div>
</body>
</html>`, data.ExpiresIn, data.Link)
}

// renderWelcomeHTML generates HTML for welcome emails.
func renderWelcomeHTML(data WelcomeData) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to common.ink!</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #11998e 0%%, #38ef7d 100%%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">common.ink</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <h2 style="color: #333; margin-top: 0;">Welcome, %s!</h2>
        <p>Thank you for joining common.ink. We're excited to have you on board!</p>
        <p>With common.ink, you can:</p>
        <ul style="color: #555;">
            <li>Create and organize your notes securely</li>
            <li>Access your notes from anywhere</li>
            <li>Use AI-powered tools via MCP integration</li>
            <li>Keep your data private with end-to-end encryption</li>
        </ul>
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://notes.example.com" style="background: linear-gradient(135deg, #11998e 0%%, #38ef7d 100%%); color: white; padding: 14px 30px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">Get Started</a>
        </div>
        <p style="color: #666; font-size: 14px;">If you have any questions, feel free to reach out to our support team.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
        <p style="color: #999; font-size: 12px;">This is an automated message from common.ink. Please do not reply to this email.</p>
    </div>
</body>
</html>`, data.Name)
}
