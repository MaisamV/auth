package handler

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/auth-service/internal/application/usecase"
)

// AuthHandler handles HTTP requests for authentication endpoints
type AuthHandler struct {
	authUseCase *usecase.AuthUseCase
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(authUseCase *usecase.AuthUseCase) *AuthHandler {
	return &AuthHandler{
		authUseCase: authUseCase,
	}
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req usecase.RegisterUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	resp, err := h.authUseCase.RegisterUser(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Set secure JWT session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    resp.SessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 hour (matches JWT expiry)
	})

	// Set secure session refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_refresh_token",
		Value:    resp.SessionRefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   15552000, // 6 months (matches refresh token expiry)
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req usecase.LoginUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	resp, err := h.authUseCase.LoginUser(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Set secure JWT session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    resp.SessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 hour (matches JWT expiry)
	})

	// Set secure session refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_refresh_token",
		Value:    resp.SessionRefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   15552000, // 6 months (matches refresh token expiry)
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Authorize handles OAuth 2.0 authorization requests
func (h *AuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	req := usecase.AuthorizeRequest{
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		ResponseType:        query.Get("response_type"),
		Scope:               query.Get("scope"),
		State:               query.Get("state"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
	}

	// Check for valid session
	sessionCookie, err := r.Cookie("session_token")
	if err != nil || sessionCookie.Value == "" {
		// Redirect to login with return URL
		returnURL := r.URL.String()
		loginURL := "/auth/login?return_url=" + returnURL
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Validate session token
	userID, err := h.authUseCase.ValidateSessionToken(r.Context(), sessionCookie.Value)
	if err != nil {
		// Invalid session, redirect to login
		returnURL := r.URL.String()
		loginURL := "/auth/login?return_url=" + returnURL
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	req.UserID = userID

	resp, err := h.authUseCase.Authorize(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Redirect back to client with authorization code
	redirectURL := req.RedirectURI + "?code=" + resp.Code
	if resp.State != "" {
		redirectURL += "&state=" + resp.State
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// Token handles OAuth 2.0 token requests
func (h *AuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	req := usecase.TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		CodeVerifier: r.FormValue("code_verifier"),
		RefreshToken: r.FormValue("refresh_token"),
		Username:     r.FormValue("username"),
		Password:     r.FormValue("password"),
		Scope:        r.FormValue("scope"),
	}

	// Handle HTTP Basic Auth for client credentials
	if req.ClientID == "" || req.ClientSecret == "" {
		clientID, clientSecret, ok := r.BasicAuth()
		if ok {
			req.ClientID = clientID
			req.ClientSecret = clientSecret
		}
	}

	resp, err := h.authUseCase.Token(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

// RevokeToken handles token revocation requests
func (h *AuthHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	req := usecase.RevokeTokenRequest{
		Token:         r.FormValue("token"),
		TokenTypeHint: r.FormValue("token_type_hint"),
		ClientID:      r.FormValue("client_id"),
		ClientSecret:  r.FormValue("client_secret"),
	}

	// Handle HTTP Basic Auth for client credentials
	if req.ClientID == "" || req.ClientSecret == "" {
		clientID, clientSecret, ok := r.BasicAuth()
		if ok {
			req.ClientID = clientID
			req.ClientSecret = clientSecret
		}
	}

	err := h.authUseCase.RevokeToken(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// JWKS returns the JSON Web Key Set for token verification
func (h *AuthHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the public key from the token service
	publicKeyInterface, err := h.authUseCase.GetPublicKey()
	if err != nil {
		http.Error(w, "Failed to get public key", http.StatusInternalServerError)
		return
	}

	// Extract ECDSA public key
	publicKey, ok := publicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		http.Error(w, "Invalid public key type", http.StatusInternalServerError)
		return
	}

	// Extract x and y coordinates and encode them as base64url
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()
	
	// Pad to 32 bytes for P-256 curve
	if len(xBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(yBytes):], yBytes)
		yBytes = padded
	}

	xCoord := base64.RawURLEncoding.EncodeToString(xBytes)
	yCoord := base64.RawURLEncoding.EncodeToString(yBytes)

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "EC",
				"use": "sig",
				"kid": "1",
				"alg": "ES256",
				"crv": "P-256",
				"x":   xCoord,
				"y":   yCoord,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// RefreshSession handles session token refresh
func (h *AuthHandler) RefreshSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get refresh token from cookie
	refreshCookie, err := r.Cookie("session_refresh_token")
	if err != nil || refreshCookie.Value == "" {
		http.Error(w, "Refresh token not found", http.StatusUnauthorized)
		return
	}

	req := usecase.RefreshSessionTokenRequest{
		RefreshToken: refreshCookie.Value,
	}

	resp, err := h.authUseCase.RefreshSessionToken(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Set new session token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    resp.SessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 hour
	})

	// Set new refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_refresh_token",
		Value:    resp.SessionRefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   15552000, // 6 months
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get refresh token from cookie to revoke it
	var refreshToken string
	if refreshCookie, err := r.Cookie("session_refresh_token"); err == nil {
		refreshToken = refreshCookie.Value
	}

	// Revoke the session refresh token in the database
	if refreshToken != "" {
		req := usecase.LogoutRequest{
			RefreshToken: refreshToken,
		}
		// Ignore errors as the token might already be revoked or expired
		h.authUseCase.Logout(r.Context(), req)
	}

	// Clear the session token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete the cookie
	})

	// Clear the session refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete the cookie
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

// extractBearerToken extracts the bearer token from the Authorization header
func extractBearerToken(authHeader string) string {
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}
