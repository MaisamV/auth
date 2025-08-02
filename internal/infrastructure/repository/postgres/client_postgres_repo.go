package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/auth-service/internal/application/repository"
	"github.com/auth-service/internal/domain/entity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// ClientPostgresRepository implements the ClientRepository interface using PostgreSQL
type ClientPostgresRepository struct {
	db *sqlx.DB
}

// NewClientPostgresRepository creates a new ClientPostgresRepository
func NewClientPostgresRepository(db *sqlx.DB) repository.ClientRepository {
	return &ClientPostgresRepository{db: db}
}

// Save creates a new client or updates an existing one
func (r *ClientPostgresRepository) Save(ctx context.Context, client *entity.Client) error {
	query := `
		INSERT INTO clients (id, secret, name, type, redirect_uris, grant_types, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			secret = EXCLUDED.secret,
			name = EXCLUDED.name,
			type = EXCLUDED.type,
			redirect_uris = EXCLUDED.redirect_uris,
			grant_types = EXCLUDED.grant_types,
			updated_at = EXCLUDED.updated_at
	`

	// Convert slices to PostgreSQL arrays
	redirectURIs := pq.Array(client.RedirectURIs)
	grantTypes := make([]string, len(client.GrantTypes))
	for i, gt := range client.GrantTypes {
		grantTypes[i] = string(gt)
	}
	grantTypesArray := pq.Array(grantTypes)

	_, err := r.db.ExecContext(ctx, query,
		client.ID,
		client.Secret,
		client.Name,
		string(client.Type),
		redirectURIs,
		grantTypesArray,
		client.CreatedAt,
		client.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to save client: %w", err)
	}

	return nil
}

// FindByID retrieves a client by their ID
func (r *ClientPostgresRepository) FindByID(ctx context.Context, id string) (*entity.Client, error) {
	query := `
		SELECT id, secret, name, type, redirect_uris, grant_types, created_at, updated_at
		FROM clients WHERE id = $1
	`

	var client entity.Client
	var clientType string
	var redirectURIs pq.StringArray
	var grantTypes pq.StringArray

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&client.ID,
		&client.Secret,
		&client.Name,
		&clientType,
		&redirectURIs,
		&grantTypes,
		&client.CreatedAt,
		&client.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("client not found")
		}
		return nil, fmt.Errorf("failed to find client by ID: %w", err)
	}

	// Convert database types to domain types
	client.Type = entity.ClientType(clientType)
	client.RedirectURIs = []string(redirectURIs)

	client.GrantTypes = make([]entity.GrantType, len(grantTypes))
	for i, gt := range grantTypes {
		client.GrantTypes[i] = entity.GrantType(gt)
	}

	return &client, nil
}

// FindAll retrieves all clients
func (r *ClientPostgresRepository) FindAll(ctx context.Context) ([]*entity.Client, error) {
	query := `
		SELECT id, secret, name, type, redirect_uris, grant_types, created_at, updated_at
		FROM clients ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query clients: %w", err)
	}
	defer rows.Close()

	var clients []*entity.Client

	for rows.Next() {
		var client entity.Client
		var clientType string
		var redirectURIs pq.StringArray
		var grantTypes pq.StringArray

		err := rows.Scan(
			&client.ID,
			&client.Secret,
			&client.Name,
			&clientType,
			&redirectURIs,
			&grantTypes,
			&client.CreatedAt,
			&client.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan client: %w", err)
		}

		// Convert database types to domain types
		client.Type = entity.ClientType(clientType)
		client.RedirectURIs = []string(redirectURIs)

		client.GrantTypes = make([]entity.GrantType, len(grantTypes))
		for i, gt := range grantTypes {
			client.GrantTypes[i] = entity.GrantType(gt)
		}

		clients = append(clients, &client)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over clients: %w", err)
	}

	return clients, nil
}

// Delete removes a client by their ID
func (r *ClientPostgresRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM clients WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("client not found")
	}

	return nil
}

// ExistsByID checks if a client with the given ID exists
func (r *ClientPostgresRepository) ExistsByID(ctx context.Context, id string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, id).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check client existence: %w", err)
	}

	return exists, nil
}
