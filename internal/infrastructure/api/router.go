package api

import (
	"github.com/auth-service/internal/infrastructure/api/handler"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"net/http"
)

// NewRouter creates a new HTTP router with all the routes configured
func NewRouter(authHandler *handler.AuthHandler) *chi.Mux {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	// Removed middleware.Heartbeat to use custom health endpoint below

	// CORS middleware for browser-based clients and Swagger UI
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token, X-Requested-With, Origin")
			w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	})

	// OAuth 2.0 endpoints
	r.Route("/oauth", func(r chi.Router) {
		// Authorization endpoint (RFC 6749 Section 3.1)
		r.HandleFunc("/authorize", authHandler.Authorize)

		// Token endpoint (RFC 6749 Section 3.2)
		r.HandleFunc("/token", authHandler.Token)

		// Token revocation endpoint (RFC 7009)
		r.HandleFunc("/revoke", authHandler.RevokeToken)
	})

	// JWKS endpoint for public key discovery (RFC 7517)
	r.HandleFunc("/.well-known/jwks.json", authHandler.JWKS)

	// OpenAPI specification endpoint
	r.HandleFunc("/api/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml")
		http.ServeFile(w, r, "./api/openapi.yaml")
	})

	// Swagger UI endpoint
	r.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		swaggerHTML := `<!DOCTYPE html>
<html>
<head>
  <title>OAuth 2.0 Auth Service API Documentation</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: '/api/openapi.yaml',
      dom_id: '#swagger-ui',
      presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.presets.standalone
      ]
    });
  </script>
</body>
</html>`
		w.Write([]byte(swaggerHTML))
	})

	// User management endpoints
	r.Route("/auth", func(r chi.Router) {
		// User registration
		r.HandleFunc("/register", authHandler.Register)
	})

	// Health check endpoint
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"auth-service"}`))
	})

	return r
}
