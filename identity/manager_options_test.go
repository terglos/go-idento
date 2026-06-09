package identity

import "testing"

type capturingLogger struct{ msgs []string }

func (c *capturingLogger) Warn(msg string, _ ...any) { c.msgs = append(c.msgs, msg) }

func TestManagerOptionsChain(t *testing.T) {
	lg := &capturingLogger{}
	h := NewPasswordHasher()
	m := (&UserManagerOf[User, *User]{}).
		WithLogger(lg).
		WithHasher(h).
		WithNormalizer(upperNormalizer{})

	if m.Logger != lg {
		t.Fatal("WithLogger not applied")
	}
	if m.Hasher != h {
		t.Fatal("WithHasher not applied")
	}
	if m.Normalizer == nil {
		t.Fatal("WithNormalizer not applied")
	}
	// logger() prefers the configured logger.
	m.logger().Warn("hello")
	if len(lg.msgs) != 1 || lg.msgs[0] != "hello" {
		t.Fatalf("logger() did not route to configured logger: %v", lg.msgs)
	}
}
