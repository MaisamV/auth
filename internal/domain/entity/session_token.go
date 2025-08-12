package entity

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/auth-service/internal/domain/vo"
)

// SessionRefreshToken represents a session refresh token stored in the database
type SessionRefreshToken struct {
	id           string
	userID       string
	expiresAt    time.Time
	createdAt    time.Time
	issuer       string
	revoked      bool
	lastUsedAt   *time.Time
	_type        string
	salt         string // Random salt for JWT security, not stored in database
	revokeReason *vo.RevokeReason // Reason for revocation, nil if not revoked
}

// NewSessionRefreshToken creates a new session refresh token
func NewSessionRefreshToken(id, userID string, issuer string, expiresIn time.Duration) *SessionRefreshToken {
	now := time.Now()

	return &SessionRefreshToken{
		id:         id,
		userID:     userID,
		expiresAt:  now.Add(expiresIn),
		createdAt:  now,
		issuer:     issuer,
		revoked:    false,
		lastUsedAt: nil,
		_type:      "session_refresh",
	}
}

// IsExpired checks if the session refresh token has expired
func (srt *SessionRefreshToken) IsExpired() bool {
	return time.Now().After(srt.expiresAt)
}

// IsValid checks if the token is valid (not expired and not revoked)
func (srt *SessionRefreshToken) IsValid() bool {
	return !srt.IsExpired()
}

// IsRevoked checks if the session refresh token has been revoked
func (srt *SessionRefreshToken) IsRevoked() bool {
	return srt.revoked
}



// RevokeWithReason marks the session refresh token as revoked with a specific reason
func (srt *SessionRefreshToken) RevokeWithReason(reason vo.RevokeReason) {
	srt.revoked = true
	srt.revokeReason = &reason
}

// GetRevokeReason returns the revoke reason if the token is revoked
func (srt *SessionRefreshToken) GetRevokeReason() *vo.RevokeReason {
	return srt.revokeReason
}

// MarkAsUsed updates the last used timestamp
func (srt *SessionRefreshToken) MarkAsUsed() {
	now := time.Now()
	srt.lastUsedAt = &now
}

// GetExpirationDuration returns the duration until expiration from creation time
func (srt *SessionRefreshToken) GetExpirationDuration() time.Duration {
	return srt.expiresAt.Sub(srt.createdAt)
}

// ToJwt converts the SessionRefreshToken entity to a JWT string using the provided token service
func (srt *SessionRefreshToken) ToJwt(tokenService interface {
	GenerateSessionRefreshTokenJWT(session *SessionRefreshToken) (string, error)
}) (string, error) {
	// Generate a random salt for JWT security
	saltBytes := make([]byte, 32) // 32 bytes
	rand.Read(saltBytes)
	salt := base64.URLEncoding.EncodeToString(saltBytes)
	srt.salt = salt
	return tokenService.GenerateSessionRefreshTokenJWT(srt)
}

// GetID returns the token ID
func (srt *SessionRefreshToken) GetID() string {
	return srt.id
}

// GetUserID returns the user ID
func (srt *SessionRefreshToken) GetUserID() string {
	return srt.userID
}

// GetExpiresAt returns the expiration time
func (srt *SessionRefreshToken) GetExpiresAt() time.Time {
	return srt.expiresAt
}

// GetCreatedAt returns the creation time
func (srt *SessionRefreshToken) GetCreatedAt() time.Time {
	return srt.createdAt
}

// GetLastUsedAtPtr returns the last used timestamp as a pointer
func (srt *SessionRefreshToken) GetLastUsedAtPtr() *time.Time {
	return srt.lastUsedAt
}

// GetIssuer returns the issuer
func (srt *SessionRefreshToken) GetIssuer() string {
	return srt.issuer
}

// GetType returns the token type
func (srt *SessionRefreshToken) GetType() string {
	return srt._type
}

// NewSessionRefreshTokenFromDB creates a SessionRefreshToken from database fields
// This is used by the repository layer to reconstruct entities from database records
func NewSessionRefreshTokenFromDB(id, userID string, expiresAt, createdAt time.Time, revoked bool, lastUsedAt *time.Time, revokeReason *vo.RevokeReason) *SessionRefreshToken {
	return &SessionRefreshToken{
		id:           id,
		userID:       userID,
		expiresAt:    expiresAt,
		createdAt:    createdAt,
		revoked:      revoked,
		lastUsedAt:   lastUsedAt,
		revokeReason: revokeReason,
		issuer:       "",
		salt:         "",
		_type:        "session_refresh",
	}
}
