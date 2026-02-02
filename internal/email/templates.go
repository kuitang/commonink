package email

// Template names as constants for type safety.
const (
	TemplateMagicLink     = "magic_link"
	TemplatePasswordReset = "password_reset"
	TemplateWelcome       = "welcome"
)

// MagicLinkData contains data for magic link emails.
type MagicLinkData struct {
	Link      string
	ExpiresIn string // e.g., "15 minutes"
}

// PasswordResetData contains data for password reset emails.
type PasswordResetData struct {
	Link      string
	ExpiresIn string
}

// WelcomeData contains data for welcome emails.
type WelcomeData struct {
	Name string
}
