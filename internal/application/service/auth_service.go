package service

import (
	"time"
)

// HashingService defines the interface for password hashing operations
type HashingService interface {
	// Hash generates a hash from a plain text password
	Hash(password string) (string, error)

	// Verify checks if a plain text password matches the hash
	Verify(password, hash string) error
}

// TokenService defines the interface for JWT token operations
type TokenService interface {
	// GenerateAccessToken creates a new JWT access token
	GenerateAccessToken(userID, clientID string, scopes []string, expiresIn time.Duration) (string, error)

	// ValidateAccessToken validates a JWT access token and returns the claims
	ValidateAccessToken(token string) (*TokenClaims, error)

	// GenerateRefreshToken creates a new opaque refresh token
	GenerateRefreshToken() (string, error)

	// GenerateAuthorizationCode creates a new authorization code
	GenerateAuthorizationCode() (string, error)

	// GetPublicKey returns the public key for JWT verification
	GetPublicKey() (interface{}, error)
}

// TokenClaims represents the claims in a JWT token
type TokenClaims struct {
	UserID   string   `json:"sub"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	IssuedAt int64    `json:"iat"`
	Expiry   int64    `json:"exp"`
	TokenID  string   `json:"jti"` // JWT ID for blacklisting
}

// PKCEService defines the interface for PKCE (Proof Key for Code Exchange) operations
type PKCEService interface {
	// VerifyCodeChallenge verifies that the code verifier matches the code challenge
	VerifyCodeChallenge(codeVerifier, codeChallenge, method string) error
}

// IDGeneratorService defines the interface for generating unique IDs
type IDGeneratorService interface {
	// GenerateID generates a new unique ID
	GenerateID() string
}
