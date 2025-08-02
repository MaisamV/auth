package repository

import (
	"context"
	"github.com/auth-service/internal/domain/entity"
	"github.com/auth-service/internal/domain/vo"
)

// UserRepository defines the interface for user data persistence
type UserRepository interface {
	// Save creates a new user or updates an existing one
	Save(ctx context.Context, user *entity.User) error

	// FindByID retrieves a user by their ID
	FindByID(ctx context.Context, id string) (*entity.User, error)

	// FindByEmail retrieves a user by their email address
	FindByEmail(ctx context.Context, email vo.Email) (*entity.User, error)

	// ExistsByEmail checks if a user with the given email exists
	ExistsByEmail(ctx context.Context, email vo.Email) (bool, error)

	// Delete removes a user by their ID
	Delete(ctx context.Context, id string) error

	// UpdatePassword updates a user's password hash
	UpdatePassword(ctx context.Context, id string, hashedPassword string) error
}
