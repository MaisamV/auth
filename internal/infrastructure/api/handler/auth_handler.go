package handler

import (
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
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

	// For this example, we'll assume the user is already authenticated
	// In a real implementation, you would check for a valid session
	// and redirect to login if not authenticated
	userID := r.Header.Get("X-User-ID") // Simplified for demo
	if userID == "" {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
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

	// This is a simplified JWKS response
	// In a real implementation, you would get the actual public key from the token service
	// and extract the x, y coordinates from the ECDSA public key
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "EC",
				"use": "sig",
				"kid": "1",
				"alg": "ES256",
				"crv": "P-256",
				// Example ECDSA P-256 public key coordinates (base64url encoded)
				// In production, these would be extracted from the actual public key:
				// "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGHwHitJBcBmXQ",
				// "y": "y77As5vbZdIGe4_7GGhOKcHZ9QLE9BQZ154vdTW2HGI",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
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
