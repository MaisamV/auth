package service

import (
	"github.com/auth-service/internal/domain/entity"
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

	// GenerateSessionToken creates a JWT token for user sessions
	GenerateSessionToken(userID string, expiresIn time.Duration) (string, error)

	// ValidateSessionToken validates a session JWT token and returns user ID
	ValidateSessionToken(token string) (string, error)

	// GenerateSessionRefreshToken creates a refresh token for session renewal
	GenerateSessionRefreshToken(userID string, expiresIn time.Duration) (*entity.SessionRefreshToken, error)

	// GenerateSessionRefreshTokenJWT creates a JWT string from session refresh token data
	GenerateSessionRefreshTokenJWT(session *entity.SessionRefreshToken) (string, error)

	// ValidateSessionRefreshToken validates a session refresh token and returns user ID
	ValidateSessionRefreshToken(token string) (string, error)

	// HashToken creates a hash of a token for database storage
	HashToken(token string) (string, error)

	// GetPublicKey returns the public key for JWT verification
	GetPublicKey() (interface{}, error)

	// Configuration getters
	GetAccessTokenExpiry() time.Duration
	GetRefreshTokenExpiry() time.Duration
	GetAuthorizationCodeExpiry() time.Duration
	GetSessionTokenExpiry() time.Duration
	GetSessionRefreshTokenExpiry() time.Duration
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
