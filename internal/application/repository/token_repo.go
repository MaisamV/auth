package repository

import (
	"context"
	"github.com/auth-service/internal/domain/entity"
)

// AuthorizationCodeRepository defines the interface for authorization code persistence
type AuthorizationCodeRepository interface {
	// Save stores an authorization code
	Save(ctx context.Context, code *entity.AuthorizationCode) error

	// FindByCode retrieves an authorization code by its code value
	FindByCode(ctx context.Context, code string) (*entity.AuthorizationCode, error)

	// MarkAsUsed marks an authorization code as used
	MarkAsUsed(ctx context.Context, code string) error

	// DeleteExpired removes all expired authorization codes
	DeleteExpired(ctx context.Context) error
}

// RefreshTokenRepository defines the interface for refresh token persistence
type RefreshTokenRepository interface {
	// Save stores a refresh token
	Save(ctx context.Context, token *entity.RefreshToken) error

	// FindByToken retrieves a refresh token by its token value
	FindByToken(ctx context.Context, token string) (*entity.RefreshToken, error)

	// FindByUserID retrieves all refresh tokens for a user
	FindByUserID(ctx context.Context, userID string) ([]*entity.RefreshToken, error)

	// Revoke marks a refresh token as revoked
	Revoke(ctx context.Context, token string) error

	// RevokeAllForUser revokes all refresh tokens for a user
	RevokeAllForUser(ctx context.Context, userID string) error

	// DeleteExpired removes all expired refresh tokens
	DeleteExpired(ctx context.Context) error
}

// TokenBlacklistRepository defines the interface for token blacklist (for immediate revocation)
type TokenBlacklistRepository interface {
	// Add adds a token to the blacklist
	Add(ctx context.Context, tokenID string, expiresAt int64) error

	// IsBlacklisted checks if a token is blacklisted
	IsBlacklisted(ctx context.Context, tokenID string) (bool, error)

	// CleanExpired removes expired entries from the blacklist
	CleanExpired(ctx context.Context) error
}
