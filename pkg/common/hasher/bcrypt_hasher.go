package hasher

import (
	"fmt"
	"github.com/auth-service/internal/application/service"
	"golang.org/x/crypto/bcrypt"
)

// BcryptHasher implements the HashingService interface using bcrypt
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher creates a new BcryptHasher with the specified cost
// Cost should be between 4 and 31. Higher cost means more secure but slower.
// Recommended cost is 12 for production.
func NewBcryptHasher(cost int) service.HashingService {
	if cost < bcrypt.MinCost {
		cost = bcrypt.DefaultCost
	}
	if cost > bcrypt.MaxCost {
		cost = bcrypt.MaxCost
	}

	return &BcryptHasher{
		cost: cost,
	}
}

// Hash generates a bcrypt hash from a plain text password
func (h *BcryptHasher) Hash(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hash), nil
}

// Verify checks if a plain text password matches the bcrypt hash
func (h *BcryptHasher) Verify(password, hash string) error {
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	if hash == "" {
		return fmt.Errorf("hash cannot be empty")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return fmt.Errorf("invalid password")
		}
		return fmt.Errorf("failed to verify password: %w", err)
	}

	return nil
}
