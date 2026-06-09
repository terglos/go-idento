package identity

// Logger is a minimal structured logger used to surface non-fatal but
// security-relevant failures (e.g. a failed lockout write) that the managers
// cannot return through their result types. *slog.Logger satisfies it, so you
// can pass slog.Default() or any custom adapter. The default is a no-op.
type Logger interface {
	Warn(msg string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Warn(string, ...any) {}
