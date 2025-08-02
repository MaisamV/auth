package repository

import (
	"context"
	"github.com/auth-service/internal/domain/entity"
)

// ClientRepository defines the interface for OAuth client data persistence
type ClientRepository interface {
	// Save creates a new client or updates an existing one
	Save(ctx context.Context, client *entity.Client) error

	// FindByID retrieves a client by their ID
	FindByID(ctx context.Context, id string) (*entity.Client, error)

	// FindAll retrieves all clients
	FindAll(ctx context.Context) ([]*entity.Client, error)

	// Delete removes a client by their ID
	Delete(ctx context.Context, id string) error

	// ExistsByID checks if a client with the given ID exists
	ExistsByID(ctx context.Context, id string) (bool, error)
}
