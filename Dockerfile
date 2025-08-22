# Build stage
FROM golang:1.24-alpine AS builder

# Install git and ca-certificates (needed for go mod download)
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Create keys directory in build stage
RUN mkdir -p keys

# Build the main application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main cmd/server/main.go

# Build the keygen utility
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o keygen cmd/keygen/main.go

# Build the keygen-ed25519 utility
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o keygen-ed25519 cmd/keygen-ed25519/main.go

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN adduser -D -s /bin/sh appuser

# Set working directory
WORKDIR /app

# Copy binaries from builder stage
COPY --from=builder /app/main .
COPY --from=builder /app/keygen .
COPY --from=builder /app/keygen-ed25519 .

# Copy configuration files
COPY --from=builder /app/configs ./configs

# Copy API specification
COPY --from=builder /app/api ./api

# Copy startup script
COPY --from=builder /app/scripts ./scripts

# Copy keys folder from builder stage (includes any existing keys)
COPY --from=builder /app/keys ./keys

# Make startup script executable
RUN chmod +x scripts/start.sh

# Change ownership to appuser
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application with startup script
CMD ["./scripts/start.sh"]