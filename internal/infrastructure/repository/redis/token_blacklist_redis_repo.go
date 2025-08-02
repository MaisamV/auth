package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/auth-service/internal/application/repository"
	"github.com/redis/go-redis/v9"
)

// TokenBlacklistRedisRepository implements the TokenBlacklistRepository interface using Redis
type TokenBlacklistRedisRepository struct {
	client *redis.Client
	prefix string
}

// NewTokenBlacklistRedisRepository creates a new TokenBlacklistRedisRepository
func NewTokenBlacklistRedisRepository(client *redis.Client) repository.TokenBlacklistRepository {
	return &TokenBlacklistRedisRepository{
		client: client,
		prefix: "blacklist:",
	}
}

// Add adds a token to the blacklist
func (r *TokenBlacklistRedisRepository) Add(ctx context.Context, tokenID string, expiresAt int64) error {
	key := r.prefix + tokenID

	// Calculate TTL based on token expiration
	ttl := time.Until(time.Unix(expiresAt, 0))
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	// Set the key with TTL
	err := r.client.Set(ctx, key, "1", ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to add token to blacklist: %w", err)
	}

	return nil
}

// IsBlacklisted checks if a token is blacklisted
func (r *TokenBlacklistRedisRepository) IsBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	key := r.prefix + tokenID

	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check token blacklist: %w", err)
	}

	return exists > 0, nil
}

// CleanExpired removes expired entries from the blacklist
// Note: Redis automatically removes expired keys, so this is a no-op
// We implement it for interface compliance
func (r *TokenBlacklistRedisRepository) CleanExpired(ctx context.Context) error {
	// Redis automatically handles TTL expiration, so no manual cleanup needed
	return nil
}
