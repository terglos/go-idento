package identity

import "time"

// nowFn is the package clock; tests override it for deterministic TOTP/token
// behaviour. Production code always uses the real wall clock.
var nowFn = time.Now
