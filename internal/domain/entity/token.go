package entity

import (
	"time"
)

// AuthorizationCode represents an OAuth 2.0 authorization code
type AuthorizationCode struct {
	Code                string    `json:"code" db:"code"`
	ClientID            string    `json:"client_id" db:"client_id"`
	UserID              string    `json:"user_id" db:"user_id"`
	RedirectURI         string    `json:"redirect_uri" db:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge" db:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method" db:"code_challenge_method"`
	Scopes              []string  `json:"scopes" db:"scopes"`
	ExpiresAt           time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	Used                bool      `json:"used" db:"used"`
}

// NewAuthorizationCode creates a new authorization code
func NewAuthorizationCode(code, clientID, userID, redirectURI, codeChallenge, codeChallengeMethod string, scopes []string, expiresIn time.Duration) *AuthorizationCode {
	now := time.Now()
	return &AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scopes:              scopes,
		ExpiresAt:           now.Add(expiresIn),
		CreatedAt:           now,
		Used:                false,
	}
}

// IsExpired checks if the authorization code has expired
func (ac *AuthorizationCode) IsExpired() bool {
	return time.Now().After(ac.ExpiresAt)
}

// MarkAsUsed marks the authorization code as used
func (ac *AuthorizationCode) MarkAsUsed() {
	ac.Used = true
}

// RefreshToken represents an OAuth 2.0 refresh token
type RefreshToken struct {
	Token     string    `json:"token" db:"token"`
	ClientID  string    `json:"client_id" db:"client_id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Scopes    []string  `json:"scopes" db:"scopes"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	Revoked   bool      `json:"revoked" db:"revoked"`
}

// NewRefreshToken creates a new refresh token
func NewRefreshToken(token, clientID, userID string, scopes []string, expiresIn time.Duration) *RefreshToken {
	now := time.Now()
	return &RefreshToken{
		Token:     token,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    scopes,
		ExpiresAt: now.Add(expiresIn),
		CreatedAt: now,
		Revoked:   false,
	}
}

// IsExpired checks if the refresh token has expired
func (rt *RefreshToken) IsExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// IsValid checks if the refresh token is valid (not expired and not revoked)
func (rt *RefreshToken) IsValid() bool {
	return !rt.IsExpired() && !rt.Revoked
}

// Revoke marks the refresh token as revoked
func (rt *RefreshToken) Revoke() {
	rt.Revoked = true
}
