package identity

// Configuration helpers for UserManagerOf. They follow the same chainable
// pattern as WithTokenProvider / WithSMSSender and are meant to be called once
// at construction (managers are not designed to be reconfigured concurrently
// with use).

// WithLogger sets the logger used for non-fatal security-relevant failures.
func (m *UserManagerOf[T, PT]) WithLogger(l Logger) *UserManagerOf[T, PT] {
	m.Logger = l
	return m
}

// WithHasher swaps the password hasher (e.g. to tune PBKDF2 parameters).
func (m *UserManagerOf[T, PT]) WithHasher(h PasswordHasher) *UserManagerOf[T, PT] {
	m.Hasher = h
	return m
}

// WithNormalizer swaps the lookup normalizer (default: uppercase-invariant).
func (m *UserManagerOf[T, PT]) WithNormalizer(n Normalizer) *UserManagerOf[T, PT] {
	m.Normalizer = n
	return m
}
