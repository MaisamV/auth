package services

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/auth-service/internal/application/service"
)

// PKCEService implements the PKCEService interface
type PKCEService struct{}

// NewPKCEService creates a new PKCEService
func NewPKCEService() service.PKCEService {
	return &PKCEService{}
}

// VerifyCodeChallenge verifies that the code verifier matches the code challenge
func (s *PKCEService) VerifyCodeChallenge(codeVerifier, codeChallenge, method string) error {
	if codeVerifier == "" {
		return fmt.Errorf("code verifier cannot be empty")
	}
	if codeChallenge == "" {
		return fmt.Errorf("code challenge cannot be empty")
	}

	switch method {
	case "plain":
		// For plain method, code verifier should equal code challenge
		if codeVerifier != codeChallenge {
			return fmt.Errorf("code verifier does not match code challenge")
		}
	case "S256":
		// For S256 method, SHA256(code_verifier) base64url-encoded should equal code challenge
		hash := sha256.Sum256([]byte(codeVerifier))
		expectedChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
		if expectedChallenge != codeChallenge {
			return fmt.Errorf("code verifier does not match code challenge")
		}
	case "":
		// If no method specified, default to plain
		if codeVerifier != codeChallenge {
			return fmt.Errorf("code verifier does not match code challenge")
		}
	default:
		return fmt.Errorf("unsupported code challenge method: %s", method)
	}

	return nil
}
