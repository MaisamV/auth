package repository

import (
	"context"

	"github.com/auth-service/internal/domain/entity"
	"github.com/auth-service/internal/domain/vo"
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

// SessionRefreshTokenRepository defines the interface for session refresh token persistence
type SessionRefreshTokenRepository interface {
	// Save stores a session refresh token
	Save(ctx context.Context, token *entity.SessionRefreshToken, tokenHash string) error

	// FindByTokenHash retrieves a session refresh token by its hash
	FindByTokenHash(ctx context.Context, tokenHash string) (*entity.SessionRefreshToken, error)

	// FindByUserID retrieves all session refresh tokens for a user
	FindByUserID(ctx context.Context, userID string) ([]*entity.SessionRefreshToken, error)

	// Update updates a session refresh token
	Update(ctx context.Context, token *entity.SessionRefreshToken) error

	// Revoke marks a session refresh token as revoked
	Revoke(ctx context.Context, tokenHash string) error

	// RevokeWithReason marks a session refresh token as revoked with a specific reason
	RevokeWithReason(ctx context.Context, tokenHash string, reason vo.RevokeReason) error

	// RevokeAllForUser revokes all session refresh tokens for a user
	RevokeAllForUser(ctx context.Context, userID string) error

	// RevokeAllForUserWithReason revokes all session refresh tokens for a user with a specific reason
	RevokeAllForUserWithReason(ctx context.Context, userID string, reason vo.RevokeReason) error

	// DeleteExpired removes all expired session refresh tokens
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
