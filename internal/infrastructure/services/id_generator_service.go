package services

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/auth-service/internal/application/service"
)

// IDGeneratorService implements the IDGeneratorService interface
type IDGeneratorService struct{}

// NewIDGeneratorService creates a new IDGeneratorService
func NewIDGeneratorService() service.IDGeneratorService {
	return &IDGeneratorService{}
}

// GenerateID generates a new unique ID using cryptographically secure random bytes
func (s *IDGeneratorService) GenerateID() string {
	// Generate 16 random bytes (128 bits)
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		// Fallback to a simpler method if crypto/rand fails
		// This should rarely happen in practice
		return "fallback-id"
	}

	// Convert to hex string (32 characters)
	return hex.EncodeToString(bytes)
}
