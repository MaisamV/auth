# OAuth 2.0 Authentication Microservice Makefile

.PHONY: help build run test clean docker-up docker-down migrate-up migrate-down deps lint

# Default target
help:
	@echo "Available commands:"
	@echo "  build        - Build the application"
	@echo "  run          - Run the application"
	@echo "  test         - Run tests"
	@echo "  test-cover   - Run tests with coverage"
	@echo "  clean        - Clean build artifacts"
	@echo "  deps         - Download dependencies"
	@echo "  lint         - Run linter"
	@echo "  docker-up    - Start Docker services"
	@echo "  docker-down  - Stop Docker services"
	@echo "  migrate-up   - Run database migrations"
	@echo "  migrate-down - Rollback database migrations"

# Build the application
build:
	@echo "Building application..."
	go build -o bin/auth-service cmd/server/main.go

# Run the application
run:
	@echo "Running application..."
	go run cmd/server/main.go

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Run tests
test:
	@echo "Running tests..."
	go test ./... -v

# Run tests with coverage
test-cover:
	@echo "Running tests with coverage..."
	go test ./... -cover -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -f coverage.out coverage.html

# Run linter (requires golangci-lint to be installed)
lint:
	@echo "Running linter..."
	golangci-lint run

# Start Docker services
docker-up:
	@echo "Starting Docker services..."
	docker-compose up -d postgres redis
	@echo "Waiting for services to be ready..."
	sleep 10

# Stop Docker services
docker-down:
	@echo "Stopping Docker services..."
	docker-compose down

# Run database migrations up
migrate-up:
	@echo "Running database migrations..."
	migrate -path migrations -database "postgres://user:password@localhost:5432/authdb?sslmode=disable" up

# Rollback database migrations
migrate-down:
	@echo "Rolling back database migrations..."
	migrate -path migrations -database "postgres://user:password@localhost:5432/authdb?sslmode=disable" down

# Development setup
dev-setup: deps docker-up migrate-up
	@echo "Development environment setup complete!"
	@echo "You can now run 'make run' to start the application"

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t auth-service:latest .

# Run application in Docker
docker-run: docker-build
	@echo "Running application in Docker..."
	docker-compose up auth-service

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	goimports -w .

# Install development tools
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest