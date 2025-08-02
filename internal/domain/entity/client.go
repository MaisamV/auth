package entity

import (
	"time"
)

// ClientType represents the type of OAuth client
type ClientType string

const (
	ClientTypePublic       ClientType = "public"       // For SPAs, mobile apps (no client secret)
	ClientTypeConfidential ClientType = "confidential" // For backend services (has client secret)
)

// GrantType represents supported OAuth 2.0 grant types
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypePassword          GrantType = "password" // ROPC - use with caution
)

// Client represents an OAuth 2.0 client application
type Client struct {
	ID           string      `json:"id" db:"id"`
	Secret       string      `json:"-" db:"secret"` // Never expose secret in JSON
	Name         string      `json:"name" db:"name"`
	Type         ClientType  `json:"type" db:"type"`
	RedirectURIs []string    `json:"redirect_uris" db:"redirect_uris"`
	GrantTypes   []GrantType `json:"grant_types" db:"grant_types"`
	CreatedAt    time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at" db:"updated_at"`
}

// NewClient creates a new OAuth client
func NewClient(id, secret, name string, clientType ClientType, redirectURIs []string, grantTypes []GrantType) *Client {
	now := time.Now()
	return &Client{
		ID:           id,
		Secret:       secret,
		Name:         name,
		Type:         clientType,
		RedirectURIs: redirectURIs,
		GrantTypes:   grantTypes,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// IsPublic returns true if the client is a public client (no secret required)
func (c *Client) IsPublic() bool {
	return c.Type == ClientTypePublic
}

// SupportsGrantType checks if the client supports the given grant type
func (c *Client) SupportsGrantType(grantType GrantType) bool {
	for _, gt := range c.GrantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

// IsValidRedirectURI checks if the given redirect URI is valid for this client
func (c *Client) IsValidRedirectURI(redirectURI string) bool {
	for _, uri := range c.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}
