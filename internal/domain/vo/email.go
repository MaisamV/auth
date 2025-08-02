package vo

import (
	"fmt"
	"regexp"
	"strings"
)

// Email represents a validated email address
type Email struct {
	value string
}

// emailRegex is a simple regex for email validation
// Note: This is a basic validation. For production, consider using a more robust library
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// NewEmail creates a new Email value object after validation
func NewEmail(email string) (Email, error) {
	// Normalize email (trim whitespace and convert to lowercase)
	normalized := strings.ToLower(strings.TrimSpace(email))

	if normalized == "" {
		return Email{}, fmt.Errorf("email cannot be empty")
	}

	if !emailRegex.MatchString(normalized) {
		return Email{}, fmt.Errorf("invalid email format: %s", email)
	}

	return Email{value: normalized}, nil
}

// MustNewEmail creates a new Email value object and panics if invalid
// Use this only when you're certain the email is valid (e.g., in tests)
func MustNewEmail(email string) Email {
	e, err := NewEmail(email)
	if err != nil {
		panic(err)
	}
	return e
}

// String returns the email as a string
func (e Email) String() string {
	return e.value
}

// Value returns the email value for database operations
func (e Email) Value() string {
	return e.value
}

// Equals checks if two emails are equal
func (e Email) Equals(other Email) bool {
	return e.value == other.value
}
