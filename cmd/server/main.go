package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

	// Generate RSA key pair for JWT signing (in production, load from secure storage)
	privateKey, err := generateRSAKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Initialize repositories
	userRepo := postgres.NewUserPostgresRepository(db)
	clientRepo := postgres.NewClientPostgresRepository(db)
	authCodeRepo := postgres.NewAuthorizationCodePostgresRepository(db)
	refreshTokenRepo := postgres.NewRefreshTokenPostgresRepository(db)
	blacklistRepo := redisRepo.NewTokenBlacklistRedisRepository(redisClient)

	// Initialize services
	hashingService := hasher.NewBcryptHasher(12) // Cost of 12 for production
	tokenService, err := services.NewJWTTokenService(privateKey, config.Issuer)
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
		blacklistRepo,
		hashingService,
		tokenService,
		pkceService,
		idGenerator,
	)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authUseCase)

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
	Port        string
	DatabaseURL string
	RedisURL    string
	Issuer      string
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

	// Read from environment variables
	viper.AutomaticEnv()

	// Try to read config file (optional)
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("No config file found, using defaults and environment variables: %v", err)
	}

	return &Config{
		Port:        viper.GetString("port"),
		DatabaseURL: viper.GetString("database_url"),
		RedisURL:    viper.GetString("redis_url"),
		Issuer:      viper.GetString("issuer"),
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

// generateRSAKeyPair generates a new RSA key pair for JWT signing
// In production, you should load keys from secure storage
func generateRSAKeyPair() (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Convert to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), nil
}
