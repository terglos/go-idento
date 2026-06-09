// Command totp prints the current TOTP code for an authenticator shared key.
// Handy when testing the 2FA endpoints without a phone:
//
//	go run ./demo/totp <sharedKey>
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/terglos/go-idento/identity"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: totp <sharedKey>")
		os.Exit(1)
	}
	code, err := identity.DefaultTOTP().Code(os.Args[1], time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println(code)
}
