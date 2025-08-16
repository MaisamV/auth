package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"

	"github.com/auth-service/internal/application/usecase"
	"github.com/auth-service/internal/infrastructure/api"
	"github.com/auth-service/internal/infrastructure/api/handler"
	"github.com/auth-service/internal/infrastructure/repository/postgres"
	redisRepo "github.com/auth-service/internal/infrastructure/repository/redis"
	"github.com/auth-service/internal/infrastructure/services"
	"github.com/auth-service/pkg/common/hasher"
)

func main() {
	// Load configuration
	config := loadConfig()

	// Initialize database
	db, err := initDatabase(config.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize Redis
	redisClient := initRedis(config.RedisURL)
	defer redisClient.Close()

	// Load ECDSA private key from file
	privateKey, err := loadPrivateKeyFromFile("keys/jwt-private.pem")
	if err != nil {
		log.Fatalf("Failed to load private key from file: %v\nPlease run 'go run cmd/keygen/main.go' to generate keys first", err)
	}

	// Initialize repositories
	userRepo := postgres.NewUserPostgresRepository(db)
	clientRepo := postgres.NewClientPostgresRepository(db)
	authCodeRepo := postgres.NewAuthorizationCodePostgresRepository(db)
	refreshTokenRepo := postgres.NewRefreshTokenPostgresRepository(db)
	sessionRefreshTokenRepo := postgres.NewSessionRefreshTokenPostgresRepository(db)
	blacklistRepo := redisRepo.NewTokenBlacklistRedisRepository(redisClient)

	// Initialize services
	hashingService := hasher.NewBcryptHasher(12) // Cost of 12 for production
	tokenService, err := services.NewJWTTokenService(
		privateKey,
		config.Issuer,
		config.AccessTokenExpiry,
		config.RefreshTokenExpiry,
		config.AuthorizationCodeExpiry,
		config.SessionTokenExpiry,
		config.SessionRefreshTokenExpiry,
	)
	if err != nil {
		log.Fatalf("Failed to initialize token service: %v", err)
	}
	pkceService := services.NewPKCEService()
	idGenerator := services.NewIDGeneratorService()

	// Initialize use cases
	authUseCase := usecase.NewAuthUseCase(
		userRepo,
		clientRepo,
		authCodeRepo,
		refreshTokenRepo,
		sessionRefreshTokenRepo,
		blacklistRepo,
		hashingService,
		tokenService,
		pkceService,
		idGenerator,
	)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authUseCase, tokenService, config.CookieSecure)

	// Initialize router
	router := api.NewRouter(authHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting server on port %s", config.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

// Config holds the application configuration
type Config struct {
	Port                      string
	DatabaseURL               string
	RedisURL                  string
	Issuer                    string
	AccessTokenExpiry         time.Duration
	RefreshTokenExpiry        time.Duration
	AuthorizationCodeExpiry   time.Duration
	SessionTokenExpiry        time.Duration
	SessionRefreshTokenExpiry time.Duration
	CookieSecure              bool
}

// loadConfig loads configuration from environment variables and config files
func loadConfig() *Config {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")

	// Set defaults
	viper.SetDefault("port", "8080")
	viper.SetDefault("database_url", "postgres://user:password@localhost:5432/authdb?sslmode=disable")
	viper.SetDefault("redis_url", "redis://localhost:6379")
	viper.SetDefault("issuer", "https://auth.example.com")
	viper.SetDefault("access_token_expiry", "15m")
	viper.SetDefault("refresh_token_expiry", "720h")
	viper.SetDefault("authorization_code_expiry", "10m")
	viper.SetDefault("session_token_expiry", "24h")
	viper.SetDefault("session_refresh_token_expiry", "4320h")
	viper.SetDefault("cookie_secure", true)

	// Read from environment variables
	viper.AutomaticEnv()

	// Try to read config file (optional)
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("No config file found, using defaults and environment variables: %v", err)
	}

	// Parse duration strings
	accessTokenExpiry, err := time.ParseDuration(viper.GetString("access_token_expiry"))
	if err != nil {
		log.Printf("Invalid access_token_expiry format, using default: %v", err)
		accessTokenExpiry = 15 * time.Minute
	}

	refreshTokenExpiry, err := time.ParseDuration(viper.GetString("refresh_token_expiry"))
	if err != nil {
		log.Printf("Invalid refresh_token_expiry format, using default: %v", err)
		refreshTokenExpiry = 720 * time.Hour
	}

	authorizationCodeExpiry, err := time.ParseDuration(viper.GetString("authorization_code_expiry"))
	if err != nil {
		log.Printf("Invalid authorization_code_expiry format, using default: %v", err)
		authorizationCodeExpiry = 10 * time.Minute
	}

	sessionTokenExpiry, err := time.ParseDuration(viper.GetString("session_token_expiry"))
	if err != nil {
		log.Printf("Invalid session_token_expiry format, using default: %v", err)
		sessionTokenExpiry = 24 * time.Hour
	}

	sessionRefreshTokenExpiry, err := time.ParseDuration(viper.GetString("session_refresh_token_expiry"))
	if err != nil {
		log.Printf("Invalid session_refresh_token_expiry format, using default: %v", err)
		sessionRefreshTokenExpiry = 4320 * time.Hour
	}

	return &Config{
		Port:                      viper.GetString("port"),
		DatabaseURL:               viper.GetString("database_url"),
		RedisURL:                  viper.GetString("redis_url"),
		Issuer:                    viper.GetString("issuer"),
		AccessTokenExpiry:         accessTokenExpiry,
		RefreshTokenExpiry:        refreshTokenExpiry,
		AuthorizationCodeExpiry:   authorizationCodeExpiry,
		SessionTokenExpiry:        sessionTokenExpiry,
		SessionRefreshTokenExpiry: sessionRefreshTokenExpiry,
		CookieSecure:              viper.GetBool("cookie_secure"),
	}
}

// initDatabase initializes the PostgreSQL database connection
func initDatabase(databaseURL string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db, nil
}

// initRedis initializes the Redis client
func initRedis(redisURL string) *redis.Client {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		// Fallback to default Redis configuration
		opt = &redis.Options{
			Addr: "localhost:6379",
		}
	}

	client := redis.NewClient(opt)

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Printf("Warning: Failed to connect to Redis: %v", err)
	}

	return client
}

// loadPrivateKeyFromFile loads an ECDSA private key from a PEM file
func loadPrivateKeyFromFile(keyPath string) (string, error) {
	// Read the private key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key file: %w", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block from private key file")
	}

	// Verify it's a private key
	if block.Type != "PRIVATE KEY" {
		return "", fmt.Errorf("invalid key type: expected 'PRIVATE KEY', got '%s'", block.Type)
	}

	// Parse the private key to validate it
	_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	return string(keyData), nil
}
