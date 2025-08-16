package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/auth-service/internal/application/repository"
	"github.com/auth-service/internal/application/service"
	"github.com/auth-service/internal/domain/entity"
	"github.com/auth-service/internal/domain/vo"
)

// AuthUseCase handles authentication-related business logic
type AuthUseCase struct {
	userRepo                repository.UserRepository
	clientRepo              repository.ClientRepository
	authCodeRepo            repository.AuthorizationCodeRepository
	refreshTokenRepo        repository.RefreshTokenRepository
	sessionRefreshTokenRepo repository.SessionRefreshTokenRepository
	blacklistRepo           repository.TokenBlacklistRepository
	hashingService          service.HashingService
	tokenService            service.TokenService
	pkceService             service.PKCEService
	idGenerator             service.IDGeneratorService
}

// NewAuthUseCase creates a new AuthUseCase instance
func NewAuthUseCase(
	userRepo repository.UserRepository,
	clientRepo repository.ClientRepository,
	authCodeRepo repository.AuthorizationCodeRepository,
	refreshTokenRepo repository.RefreshTokenRepository,
	sessionRefreshTokenRepo repository.SessionRefreshTokenRepository,
	blacklistRepo repository.TokenBlacklistRepository,
	hashingService service.HashingService,
	tokenService service.TokenService,
	pkceService service.PKCEService,
	idGenerator service.IDGeneratorService,
) *AuthUseCase {
	return &AuthUseCase{
		userRepo:                userRepo,
		clientRepo:              clientRepo,
		authCodeRepo:            authCodeRepo,
		refreshTokenRepo:        refreshTokenRepo,
		sessionRefreshTokenRepo: sessionRefreshTokenRepo,
		blacklistRepo:           blacklistRepo,
		hashingService:          hashingService,
		tokenService:            tokenService,
		pkceService:             pkceService,
		idGenerator:             idGenerator,
	}
}

// RegisterUserRequest represents the request to register a new user
type RegisterUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterUserResponse represents the response after user registration
type RegisterUserResponse struct {
	UserID                    string `json:"user_id"`
	Email                     string `json:"email"`
	SessionToken              string `json:"session_token"`
	SessionRefreshToken       string `json:"session_refresh_token"`
	SessionTokenExpiresAt     string `json:"session_token_expires_at"`
}

// LoginUserRequest represents the request to login a user
type LoginUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginUserResponse represents the response after user login
type LoginUserResponse struct {
	UserID                    string `json:"user_id"`
	Email                     string `json:"email"`
	SessionToken              string `json:"session_token"`
	SessionRefreshToken       string `json:"session_refresh_token"`
	SessionTokenExpiresAt     string `json:"session_token_expires_at"`
}

// LoginUser authenticates a user with email and password
func (uc *AuthUseCase) LoginUser(ctx context.Context, req LoginUserRequest) (*LoginUserResponse, error) {
	// Validate email
	email, err := vo.NewEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	// Find user by email
	user, err := uc.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Verify password
	if err := uc.hashingService.Verify(req.Password, user.Password); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate session token
	sessionToken, err := uc.tokenService.GenerateSessionToken(user.ID, uc.tokenService.GetSessionTokenExpiry())
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Generate session refresh token entity
	sessionRefreshTokenEntity, err := uc.tokenService.GenerateSessionRefreshToken(user.ID, uc.tokenService.GetSessionRefreshTokenExpiry())
	if err != nil {
		return nil, fmt.Errorf("failed to generate session refresh token: %w", err)
	}

	// Convert entity to JWT string for response
	sessionRefreshToken, err := sessionRefreshTokenEntity.ToJwt(uc.tokenService)
	if err != nil {
		return nil, fmt.Errorf("failed to convert session refresh token to JWT: %w", err)
	}

	hash, err := uc.tokenService.HashToken(sessionRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash session refresh token: %w", err)
	}

	// Save session refresh token to database
	if err := uc.sessionRefreshTokenRepo.Save(ctx, sessionRefreshTokenEntity, hash); err != nil {
		return nil, fmt.Errorf("failed to save session refresh token: %w", err)
	}

	// Calculate session token expiration time
	sessionTokenExpiresAt := time.Now().UTC().Add(uc.tokenService.GetSessionTokenExpiry())

	return &LoginUserResponse{
		UserID:                    user.ID,
		Email:                     user.Email.String(),
		SessionToken:              sessionToken,
		SessionRefreshToken:       sessionRefreshToken,
		SessionTokenExpiresAt:     sessionTokenExpiresAt.Format(time.RFC3339),
	}, nil
}

// RegisterUser creates a new user account
func (uc *AuthUseCase) RegisterUser(ctx context.Context, req RegisterUserRequest) (*RegisterUserResponse, error) {
	// Validate email
	email, err := vo.NewEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	// Check if user already exists
	exists, err := uc.userRepo.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to check user existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("user with email %s already exists", email.String())
	}

	// Hash password
	hashedPassword, err := uc.hashingService.Hash(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user entity
	user := entity.NewUser(email, hashedPassword)
	user.ID = uc.idGenerator.GenerateID()

	// Save user
	if err := uc.userRepo.Save(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	// Generate session token
	sessionToken, err := uc.tokenService.GenerateSessionToken(user.ID, uc.tokenService.GetSessionTokenExpiry())
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Generate session refresh token entity
	sessionRefreshTokenEntity, err := uc.tokenService.GenerateSessionRefreshToken(user.ID, uc.tokenService.GetSessionRefreshTokenExpiry())
	if err != nil {
		return nil, fmt.Errorf("failed to generate session refresh token: %w", err)
	}

	// Convert entity to JWT string for response
	sessionRefreshToken, err := sessionRefreshTokenEntity.ToJwt(uc.tokenService)
	if err != nil {
		return nil, fmt.Errorf("failed to convert session refresh token to JWT: %w", err)
	}

	hash, err := uc.tokenService.HashToken(sessionRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash session refresh token: %w", err)
	}

	// Save session refresh token to database
	if err := uc.sessionRefreshTokenRepo.Save(ctx, sessionRefreshTokenEntity, hash); err != nil {
		return nil, fmt.Errorf("failed to save session refresh token: %w", err)
	}

	// Calculate session token expiration time
	sessionTokenExpiresAt := time.Now().UTC().Add(uc.tokenService.GetSessionTokenExpiry())

	return &RegisterUserResponse{
		UserID:                    user.ID,
		Email:                     user.Email.String(),
		SessionToken:              sessionToken,
		SessionRefreshToken:       sessionRefreshToken,
		SessionTokenExpiresAt:     sessionTokenExpiresAt.Format(time.RFC3339),
	}, nil
}

// AuthorizeRequest represents the OAuth 2.0 authorization request
type AuthorizeRequest struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	ResponseType        string `json:"response_type"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	UserID              string `json:"user_id"` // Set after user authentication
}

// AuthorizeResponse represents the OAuth 2.0 authorization response
type AuthorizeResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// Authorize handles the OAuth 2.0 authorization request (Authorization Code flow)
func (uc *AuthUseCase) Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResponse, error) {
	// Validate response type
	if req.ResponseType != "code" {
		return nil, fmt.Errorf("unsupported response type: %s", req.ResponseType)
	}

	// Validate client
	client, err := uc.clientRepo.FindByID(ctx, req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	// Check if client supports authorization code grant
	if !client.SupportsGrantType(entity.GrantTypeAuthorizationCode) {
		return nil, fmt.Errorf("client does not support authorization code grant")
	}

	// Validate redirect URI
	if !client.IsValidRedirectURI(req.RedirectURI) {
		return nil, fmt.Errorf("invalid redirect URI")
	}

	// Validate user exists
	user, err := uc.userRepo.FindByID(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user: %w", err)
	}

	// Generate authorization code
	code, err := uc.tokenService.GenerateAuthorizationCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}

	// Parse scopes
	scopes := parseScopes(req.Scope)

	// Create authorization code entity
	authCode := entity.NewAuthorizationCode(
		code,
		client.ID,
		user.ID,
		req.RedirectURI,
		req.CodeChallenge,
		req.CodeChallengeMethod,
		scopes,
		uc.tokenService.GetAuthorizationCodeExpiry(),
	)

	// Save authorization code
	if err := uc.authCodeRepo.Save(ctx, authCode); err != nil {
		return nil, fmt.Errorf("failed to save authorization code: %w", err)
	}

	return &AuthorizeResponse{
		Code:  code,
		State: req.State,
	}, nil
}

// TokenRequest represents the OAuth 2.0 token request
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`          // For authorization_code grant
	RedirectURI  string `json:"redirect_uri"`  // For authorization_code grant
	CodeVerifier string `json:"code_verifier"` // For PKCE
	RefreshToken string `json:"refresh_token"` // For refresh_token grant
	Username     string `json:"username"`      // For password grant
	Password     string `json:"password"`      // For password grant
	Scope        string `json:"scope"`
}

// TokenResponse represents the OAuth 2.0 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Token handles OAuth 2.0 token requests for all grant types
func (uc *AuthUseCase) Token(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	switch req.GrantType {
	case string(entity.GrantTypeAuthorizationCode):
		return uc.handleAuthorizationCodeGrant(ctx, req)
	case string(entity.GrantTypeRefreshToken):
		return uc.handleRefreshTokenGrant(ctx, req)
	case string(entity.GrantTypeClientCredentials):
		return uc.handleClientCredentialsGrant(ctx, req)
	case string(entity.GrantTypePassword):
		return uc.handlePasswordGrant(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported grant type: %s", req.GrantType)
	}
}

// handleAuthorizationCodeGrant handles the authorization code grant flow
func (uc *AuthUseCase) handleAuthorizationCodeGrant(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	// Validate client
	client, err := uc.validateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	// Find authorization code
	authCode, err := uc.authCodeRepo.FindByCode(ctx, req.Code)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization code: %w", err)
	}

	// Validate authorization code
	if authCode.Used {
		return nil, fmt.Errorf("authorization code already used")
	}
	if authCode.IsExpired() {
		return nil, fmt.Errorf("authorization code expired")
	}
	if authCode.ClientID != client.ID {
		return nil, fmt.Errorf("authorization code issued to different client")
	}
	if authCode.RedirectURI != req.RedirectURI {
		return nil, fmt.Errorf("redirect URI mismatch")
	}

	// Verify PKCE if present
	if authCode.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return nil, fmt.Errorf("code verifier required for PKCE")
		}
		if err := uc.pkceService.VerifyCodeChallenge(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
			return nil, fmt.Errorf("PKCE verification failed: %w", err)
		}
	}

	// Mark authorization code as used
	if err := uc.authCodeRepo.MarkAsUsed(ctx, req.Code); err != nil {
		return nil, fmt.Errorf("failed to mark authorization code as used: %w", err)
	}

	// Generate tokens
	return uc.generateTokens(ctx, authCode.UserID, client.ID, authCode.Scopes)
}

// handleRefreshTokenGrant handles the refresh token grant flow
func (uc *AuthUseCase) handleRefreshTokenGrant(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	// Validate client
	client, err := uc.validateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	// Find refresh token
	refreshToken, err := uc.refreshTokenRepo.FindByToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Validate refresh token
	if !refreshToken.IsValid() {
		return nil, fmt.Errorf("refresh token is invalid or expired")
	}
	if refreshToken.ClientID != client.ID {
		return nil, fmt.Errorf("refresh token issued to different client")
	}

	// Generate new tokens
	return uc.generateTokens(ctx, refreshToken.UserID, client.ID, refreshToken.Scopes)
}

// handleClientCredentialsGrant handles the client credentials grant flow
func (uc *AuthUseCase) handleClientCredentialsGrant(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	// Validate client (must be confidential)
	client, err := uc.validateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	if client.IsPublic() {
		return nil, fmt.Errorf("client credentials grant not allowed for public clients")
	}

	// Parse scopes
	scopes := parseScopes(req.Scope)

	// Generate access token (no refresh token for client credentials)
	accessToken, err := uc.tokenService.GenerateAccessToken(
		"", // No user ID for client credentials
		client.ID,
		scopes,
		1*time.Hour, // Client credentials tokens typically have shorter expiry
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600, // 1 hour
		Scope:       req.Scope,
	}, nil
}

// handlePasswordGrant handles the resource owner password credentials grant flow
func (uc *AuthUseCase) handlePasswordGrant(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	// Validate client
	client, err := uc.validateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}

	// Validate email
	email, err := vo.NewEmail(req.Username)
	if err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	// Find user
	user, err := uc.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Verify password
	if err := uc.hashingService.Verify(req.Password, user.Password); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Parse scopes
	scopes := parseScopes(req.Scope)

	// Generate tokens
	return uc.generateTokens(ctx, user.ID, client.ID, scopes)
}

// validateClient validates client credentials
func (uc *AuthUseCase) validateClient(ctx context.Context, clientID, clientSecret string) (*entity.Client, error) {
	client, err := uc.clientRepo.FindByID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	// For confidential clients, verify the secret
	if !client.IsPublic() && client.Secret != clientSecret {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}

// generateTokens generates access and refresh tokens
func (uc *AuthUseCase) generateTokens(ctx context.Context, userID, clientID string, scopes []string) (*TokenResponse, error) {
	// Generate access token
	accessToken, err := uc.tokenService.GenerateAccessToken(
		userID,
		clientID,
		scopes,
		uc.tokenService.GetAccessTokenExpiry(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshTokenStr, err := uc.tokenService.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Save refresh token
	refreshToken := entity.NewRefreshToken(
		refreshTokenStr,
		clientID,
		userID,
		scopes,
		uc.tokenService.GetRefreshTokenExpiry(),
	)

	if err := uc.refreshTokenRepo.Save(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(uc.tokenService.GetAccessTokenExpiry().Seconds()),
		RefreshToken: refreshTokenStr,
		Scope:        joinScopes(scopes),
	}, nil
}

// RevokeTokenRequest represents a token revocation request
type RevokeTokenRequest struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
}

// RevokeToken revokes a refresh token
func (uc *AuthUseCase) RevokeToken(ctx context.Context, req RevokeTokenRequest) error {
	// Validate client
	_, err := uc.validateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return err
	}

	// Revoke the token (assuming it's a refresh token) with ADMIN reason for OAuth revocation
	if err := uc.refreshTokenRepo.RevokeWithReason(ctx, req.Token, vo.RevokeReasonAdmin); err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	return nil
}

// parseScopes parses a space-separated scope string into a slice
func parseScopes(scope string) []string {
	if scope == "" {
		return []string{}
	}
	// For now, just split by space. In a real implementation,
	// you might want more sophisticated scope parsing
	return []string{scope}
}

// joinScopes joins a slice of scopes into a space-separated string
func joinScopes(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	return scopes[0] // Simplified: return first scope
}

// ValidateSessionToken validates a session token and returns the user ID
func (uc *AuthUseCase) ValidateSessionToken(ctx context.Context, token string) (string, error) {
	return uc.tokenService.ValidateSessionToken(token)
}

// RefreshSessionTokenRequest represents the request to refresh a session token
type RefreshSessionTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshSessionTokenResponse represents the response after refreshing a session token
type RefreshSessionTokenResponse struct {
	SessionToken              string `json:"session_token"`
	SessionRefreshToken       string `json:"session_refresh_token"`
	SessionTokenExpiresAt     string `json:"session_token_expires_at"`
}

// RefreshSessionToken refreshes a session token using a refresh token
func (uc *AuthUseCase) RefreshSessionToken(ctx context.Context, req RefreshSessionTokenRequest) (*RefreshSessionTokenResponse, error) {
	// First validate the JWT structure and extract user ID
	userID, err := uc.tokenService.ValidateSessionRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Hash the provided token to check against database
	tokenHash, err := uc.tokenService.HashToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash refresh token: %w", err)
	}

	// Find the session refresh token in database
	sessionRefreshToken, err := uc.sessionRefreshTokenRepo.FindByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: token not found in database")
	}

	// Validate the token (check expiry, revocation, user match)
	if sessionRefreshToken.IsExpired() {
		return nil, fmt.Errorf("refresh token has expired")
	}
	if sessionRefreshToken.IsRevoked() {
		return nil, fmt.Errorf("refresh token has been revoked")
	}
	if sessionRefreshToken.GetUserID() != userID {
		return nil, fmt.Errorf("refresh token does not belong to the user")
	}

	// Mark the current token as used and revoke it with REFRESH reason
	sessionRefreshToken.MarkAsUsed()
	sessionRefreshToken.RevokeWithReason(vo.RevokeReasonRefresh)
	if err := uc.sessionRefreshTokenRepo.Update(ctx, sessionRefreshToken); err != nil {
		return nil, fmt.Errorf("failed to update session refresh token: %w", err)
	}

	// Generate new session token
	newSessionToken, err := uc.tokenService.GenerateSessionToken(userID, uc.tokenService.GetSessionTokenExpiry())
	if err != nil {
		return nil, fmt.Errorf("failed to generate new session token: %w", err)
	}

	// Generate new session refresh token entity
	newSessionRefreshTokenEntity, err := uc.tokenService.GenerateSessionRefreshToken(userID, uc.tokenService.GetSessionRefreshTokenExpiry())
	if err != nil {
		return nil, fmt.Errorf("failed to generate new session refresh token: %w", err)
	}

	// Convert entity to JWT string for response
	newSessionRefreshToken, err := newSessionRefreshTokenEntity.ToJwt(uc.tokenService)
	if err != nil {
		return nil, fmt.Errorf("failed to convert new session refresh token to JWT: %w", err)
	}

	hash, err := uc.tokenService.HashToken(newSessionRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash session refresh token: %w", err)
	}

	// Save new session refresh token to database
	if err := uc.sessionRefreshTokenRepo.Save(ctx, newSessionRefreshTokenEntity, hash); err != nil {
		return nil, fmt.Errorf("failed to save new session refresh token: %w", err)
	}

	// Calculate session token expiration time
	sessionTokenExpiresAt := time.Now().UTC().Add(uc.tokenService.GetSessionTokenExpiry())

	return &RefreshSessionTokenResponse{
		SessionToken:              newSessionToken,
		SessionRefreshToken:       newSessionRefreshToken,
		SessionTokenExpiresAt:     sessionTokenExpiresAt.Format(time.RFC3339),
	}, nil
}

// LogoutRequest represents the request to logout a user
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Logout logs out a user by revoking their session refresh token
func (uc *AuthUseCase) Logout(ctx context.Context, req LogoutRequest) error {
	if req.RefreshToken == "" {
		return nil // No token to revoke
	}

	// Hash the provided token to check against database
	tokenHash, err := uc.tokenService.HashToken(req.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to hash refresh token: %w", err)
	}

	// Revoke the session refresh token with LOGOUT reason
	if err := uc.sessionRefreshTokenRepo.RevokeWithReason(ctx, tokenHash, vo.RevokeReasonLogout); err != nil {
		// Don't return error if token not found, as it might already be revoked or expired
		return nil
	}

	return nil
}

// ChangePasswordRequest represents the request to change a user's password
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword changes a user's password and revokes all their tokens
func (uc *AuthUseCase) ChangePassword(ctx context.Context, userID string, req ChangePasswordRequest) error {
	if req.CurrentPassword == "" {
		return fmt.Errorf("current password is required")
	}
	if req.NewPassword == "" {
		return fmt.Errorf("new password is required")
	}
	if len(req.NewPassword) < 8 {
		return fmt.Errorf("new password must be at least 8 characters long")
	}

	// Get the user to verify current password
	user, err := uc.userRepo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Verify current password
	if err := uc.hashingService.Verify(req.CurrentPassword, user.Password); err != nil {
		return fmt.Errorf("current password is incorrect")
	}

	// Hash the new password
	hashedNewPassword, err := uc.hashingService.Hash(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update password in database
	if err := uc.userRepo.UpdatePassword(ctx, userID, hashedNewPassword); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Revoke all refresh tokens for this user with PASS_CHANGE reason
	if err := uc.refreshTokenRepo.RevokeAllForUserWithReason(ctx, userID, vo.RevokeReasonPassChange); err != nil {
		// Log error but don't fail the password change
		// The password has already been updated successfully
		fmt.Printf("Warning: failed to revoke OAuth refresh tokens for user %s: %v\n", userID, err)
	}

	// Revoke all session refresh tokens for this user with PASS_CHANGE reason
	if err := uc.sessionRefreshTokenRepo.RevokeAllForUserWithReason(ctx, userID, vo.RevokeReasonPassChange); err != nil {
		// Log error but don't fail the password change
		// The password has already been updated successfully
		fmt.Printf("Warning: failed to revoke session refresh tokens for user %s: %v\n", userID, err)
	}

	return nil
}



// GetPublicKey returns the public key for JWT verification
func (uc *AuthUseCase) GetPublicKey() (interface{}, error) {
	return uc.tokenService.GetPublicKey()
}
