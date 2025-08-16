package services

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/auth-service/internal/application/service"
	"github.com/auth-service/internal/domain/entity"
	"github.com/golang-jwt/jwt/v5"
)

// JWTTokenService implements the TokenService interface using JWT
type JWTTokenService struct {
	privateKey                *ecdsa.PrivateKey
	publicKey                 *ecdsa.PublicKey
	issuer                    string
	accessTokenExpiry         time.Duration
	refreshTokenExpiry        time.Duration
	authorizationCodeExpiry   time.Duration
	sessionTokenExpiry        time.Duration
	sessionRefreshTokenExpiry time.Duration
}

// NewJWTTokenService creates a new JWTTokenService
func NewJWTTokenService(privateKeyPEM, issuer string, accessTokenExpiry, refreshTokenExpiry, authorizationCodeExpiry, sessionTokenExpiry, sessionRefreshTokenExpiry time.Duration) (service.TokenService, error) {
	// Parse private key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS8 format first (recommended for ECDSA)
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try EC private key format
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		return &JWTTokenService{
			privateKey:                privateKey,
			publicKey:                 &privateKey.PublicKey,
			issuer:                    issuer,
			accessTokenExpiry:         accessTokenExpiry,
			refreshTokenExpiry:        refreshTokenExpiry,
			authorizationCodeExpiry:   authorizationCodeExpiry,
			sessionTokenExpiry:        sessionTokenExpiry,
			sessionRefreshTokenExpiry: sessionRefreshTokenExpiry,
		}, nil
	}

	privateKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ECDSA")
	}

	return &JWTTokenService{
		privateKey:                privateKey,
		publicKey:                 &privateKey.PublicKey,
		issuer:                    issuer,
		accessTokenExpiry:         accessTokenExpiry,
		refreshTokenExpiry:        refreshTokenExpiry,
		authorizationCodeExpiry:   authorizationCodeExpiry,
		sessionTokenExpiry:        sessionTokenExpiry,
		sessionRefreshTokenExpiry: sessionRefreshTokenExpiry,
	}, nil
}

// GenerateAccessToken creates a new JWT access token
func (s *JWTTokenService) GenerateAccessToken(userID, clientID string, scopes []string, expiresIn time.Duration) (string, error) {
	now := time.Now()
	expiry := now.Add(expiresIn)

	// Generate a unique token ID for blacklisting
	tokenID, err := s.generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	// Create claims
	claims := jwt.MapClaims{
		"sub":       userID,
		"client_id": clientID,
		"scopes":    scopes,
		"iat":       now.Unix(),
		"exp":       expiry.Unix(),
		"iss":       s.issuer,
		"jti":       tokenID,
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Sign token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateAccessToken validates a JWT access token and returns the claims
func (s *JWTTokenService) ValidateAccessToken(tokenString string) (*service.TokenClaims, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Convert to our TokenClaims struct
	tokenClaims := &service.TokenClaims{}

	if sub, ok := claims["sub"].(string); ok {
		tokenClaims.UserID = sub
	}

	if clientID, ok := claims["client_id"].(string); ok {
		tokenClaims.ClientID = clientID
	}

	if jti, ok := claims["jti"].(string); ok {
		tokenClaims.TokenID = jti
	}

	if iat, ok := claims["iat"].(float64); ok {
		tokenClaims.IssuedAt = int64(iat)
	}

	if exp, ok := claims["exp"].(float64); ok {
		tokenClaims.Expiry = int64(exp)
	}

	if scopes, ok := claims["scopes"].([]interface{}); ok {
		tokenClaims.Scopes = make([]string, len(scopes))
		for i, scope := range scopes {
			if s, ok := scope.(string); ok {
				tokenClaims.Scopes[i] = s
			}
		}
	}

	return tokenClaims, nil
}

// GenerateRefreshToken creates a new opaque refresh token
func (s *JWTTokenService) GenerateRefreshToken() (string, error) {
	return s.generateRandomString(64)
}

// GenerateAuthorizationCode creates a new authorization code
func (s *JWTTokenService) GenerateAuthorizationCode() (string, error) {
	return s.generateRandomString(32)
}

// GenerateSessionToken creates a JWT token for user sessions
func (s *JWTTokenService) GenerateSessionToken(userID string, expiresIn time.Duration) (string, error) {
	now := time.Now()
	expiry := now.Add(expiresIn)

	// Generate a unique token ID
	tokenID, err := s.generateRandomString(16)
	if err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	// Create session claims
	claims := jwt.MapClaims{
		"sub":  userID,
		"iat":  now.Unix(),
		"exp":  expiry.Unix(),
		"iss":  s.issuer,
		"jti":  tokenID,
		"type": "session", // Mark this as a session token
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Sign token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign session token: %w", err)
	}

	return tokenString, nil
}

// ValidateSessionToken validates a session JWT token and returns user ID
func (s *JWTTokenService) ValidateSessionToken(tokenString string) (string, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to parse session token: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid session token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid session token claims")
	}

	// Verify this is a session token
	if tokenType, ok := claims["type"].(string); !ok || tokenType != "session" {
		return "", fmt.Errorf("not a session token")
	}

	// Extract user ID
	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		return "", fmt.Errorf("invalid user ID in session token")
	}

	return userID, nil
}

// GenerateSessionRefreshToken creates a refresh token for session renewal
func (s *JWTTokenService) GenerateSessionRefreshToken(userID string, expiresIn time.Duration) (*entity.SessionRefreshToken, error) {
	// Generate a unique token ID
	tokenID, err := s.generateRandomString(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	// Create and return the entity
	return entity.NewSessionRefreshToken(tokenID, userID, s.issuer, expiresIn), nil
}

// GenerateSessionRefreshTokenJWT creates a JWT string from session refresh token data
func (s *JWTTokenService) GenerateSessionRefreshTokenJWT(session *entity.SessionRefreshToken) (string, error) {
	// Create refresh token claims
	claims := jwt.MapClaims{
		"sub":  session.GetUserID(),
		"iat":  session.GetCreatedAt().Unix(),
		"exp":  session.GetExpiresAt().Unix(),
		"iss":  session.GetIssuer(),
		"jti":  session.GetID(),
		"type": session.GetType(), // Mark this as a session refresh token
	}

	// Create token
	tokenJwt := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Sign token
	tokenString, err := tokenJwt.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign session refresh token: %w", err)
	}

	return tokenString, nil
}

// ValidateSessionRefreshToken validates a session refresh token and returns user ID
func (s *JWTTokenService) ValidateSessionRefreshToken(tokenString string) (string, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to parse session refresh token: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid session refresh token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid session refresh token claims")
	}

	// Verify this is a session refresh token
	if tokenType, ok := claims["type"].(string); !ok || tokenType != "session_refresh" {
		return "", fmt.Errorf("not a session refresh token")
	}

	// Extract user ID
	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		return "", fmt.Errorf("invalid user ID in session refresh token")
	}

	return userID, nil
}

// HashToken creates a hash of a token for database storage
func (s *JWTTokenService) HashToken(token string) (string, error) {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:]), nil
}

// GetPublicKey returns the public key for JWT verification
func (s *JWTTokenService) GetPublicKey() (interface{}, error) {
	return s.publicKey, nil
}

// generateRandomString generates a cryptographically secure random string
func (s *JWTTokenService) generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GetAccessTokenExpiry returns the configured access token expiry duration
func (s *JWTTokenService) GetAccessTokenExpiry() time.Duration {
	return s.accessTokenExpiry
}

// GetRefreshTokenExpiry returns the configured refresh token expiry duration
func (s *JWTTokenService) GetRefreshTokenExpiry() time.Duration {
	return s.refreshTokenExpiry
}

// GetAuthorizationCodeExpiry returns the configured authorization code expiry duration
func (s *JWTTokenService) GetAuthorizationCodeExpiry() time.Duration {
	return s.authorizationCodeExpiry
}

// GetSessionTokenExpiry returns the configured session token expiry duration
func (s *JWTTokenService) GetSessionTokenExpiry() time.Duration {
	return s.sessionTokenExpiry
}

// GetSessionRefreshTokenExpiry returns the configured session refresh token expiry duration
func (s *JWTTokenService) GetSessionRefreshTokenExpiry() time.Duration {
	return s.sessionRefreshTokenExpiry
}
