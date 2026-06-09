package identity

import "errors"

// IdentityError is a coded, human-readable failure that managers return instead
// of panicking.
type IdentityError struct {
	Code        string
	Description string
}

func (e *IdentityError) Error() string { return e.Code + ": " + e.Description }

func newErr(code, desc string) *IdentityError { return &IdentityError{Code: code, Description: desc} }

// Common errors with stable codes.
var (
	ErrUserNotFound             = newErr("UserNotFound", "User does not exist.")
	ErrRoleNotFound             = newErr("RoleNotFound", "Role does not exist.")
	ErrDuplicateUserName        = newErr("DuplicateUserName", "User name is already taken.")
	ErrDuplicateEmail           = newErr("DuplicateEmail", "Email is already taken.")
	ErrDuplicateRoleName        = newErr("DuplicateRoleName", "Role name is already taken.")
	ErrPasswordTooShort         = newErr("PasswordTooShort", "Password does not meet length requirement.")
	ErrPasswordRequiresDigit    = newErr("PasswordRequiresDigit", "Passwords must have at least one digit.")
	ErrPasswordRequiresUpper    = newErr("PasswordRequiresUpper", "Passwords must have at least one uppercase letter.")
	ErrPasswordRequiresLower    = newErr("PasswordRequiresLower", "Passwords must have at least one lowercase letter.")
	ErrPasswordRequiresNonAlpha = newErr("PasswordRequiresNonAlphanumeric", "Passwords must have at least one non-alphanumeric character.")
	ErrPasswordRequiresUnique   = newErr("PasswordRequiresUniqueChars", "Passwords must use a minimum number of distinct characters.")
	ErrInvalidUserName          = newErr("InvalidUserName", "User name contains characters that are not allowed.")
	ErrPasswordAlreadySet       = newErr("PasswordAlreadySet", "User already has a password; use ChangePassword instead.")
	ErrLoginAlreadyUsed         = newErr("LoginAlreadyAssociated", "External login is already associated with a user.")
	ErrPasswordMismatch         = newErr("PasswordMismatch", "Incorrect password.")
	ErrUserLockedOut            = newErr("UserLockedOut", "User is locked out.")
	ErrInvalidToken             = newErr("InvalidToken", "Invalid token.")
	ErrConcurrencyFailure       = newErr("ConcurrencyFailure", "Optimistic concurrency failure, object has been modified.")
	ErrListNotSupported         = newErr("ListNotSupported", "The configured store does not support listing.")
	ErrInvalidIdentifier        = newErr("InvalidIdentifier", "A configured schema or table name is not a valid SQL identifier.")
)

// ErrNotFound is a sentinel that stores should return when a row is absent, so
// managers can distinguish "missing" from real I/O errors.
var ErrNotFound = errors.New("identity: entity not found")
