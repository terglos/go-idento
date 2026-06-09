package identity

import "context"

// EmailSender delivers a message to an email address. Implement it with your
// mail provider (SES, SendGrid, SMTP, …); the framework stays provider-agnostic,
// mirroring [SMSSender]. The body is whatever your callback produces (plain text
// or HTML) — the framework does not impose a format.
type EmailSender interface {
	Send(ctx context.Context, to, subject, body string) error
}

// EmailSenderFunc adapts a function to EmailSender.
type EmailSenderFunc func(ctx context.Context, to, subject, body string) error

// Send implements EmailSender.
func (f EmailSenderFunc) Send(ctx context.Context, to, subject, body string) error {
	return f(ctx, to, subject, body)
}

// WithEmailSender attaches an email sender, enabling the Send* helpers below.
// Returns the manager for chaining.
func (m *UserManagerOf[T, PT]) WithEmailSender(s EmailSender) *UserManagerOf[T, PT] {
	m.Email = s
	return m
}

// SendEmailConfirmation generates an email-confirmation token, builds the
// message body from it (so you control the link/format), and delivers it to the
// user's email via the configured [EmailSender]. Returns an error if no sender
// or token provider is configured, or the user has no email.
func (m *UserManagerOf[T, PT]) SendEmailConfirmation(ctx context.Context, u PT, subject string, body func(token string) string) error {
	return m.sendTokenEmail(ctx, u, subject, body, m.GenerateEmailConfirmationToken)
}

// SendPasswordReset generates a password-reset token, builds the message body
// from it, and delivers it to the user's email via the configured [EmailSender].
func (m *UserManagerOf[T, PT]) SendPasswordReset(ctx context.Context, u PT, subject string, body func(token string) string) error {
	return m.sendTokenEmail(ctx, u, subject, body, m.GeneratePasswordResetToken)
}

func (m *UserManagerOf[T, PT]) sendTokenEmail(ctx context.Context, u PT, subject string, body func(token string) string, gen func(PT) string) error {
	if m.Email == nil {
		return newErr("NoEmailSender", "no email sender configured")
	}
	if m.Tokens == nil {
		return newErr("NoTokenProvider", "no token provider configured")
	}
	to := u.Base().Email
	if to == "" {
		return newErr("NoEmail", "user has no email address")
	}
	return m.Email.Send(ctx, to, subject, body(gen(u)))
}
