package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/auth-service/internal/application/repository"
	"github.com/auth-service/internal/domain/entity"
	"github.com/auth-service/internal/domain/vo"
	"github.com/jmoiron/sqlx"
)

// UserPostgresRepository implements the UserRepository interface using PostgreSQL
type UserPostgresRepository struct {
	db *sqlx.DB
}

// NewUserPostgresRepository creates a new UserPostgresRepository
func NewUserPostgresRepository(db *sqlx.DB) repository.UserRepository {
	return &UserPostgresRepository{db: db}
}

// Save creates a new user or updates an existing one
func (r *UserPostgresRepository) Save(ctx context.Context, user *entity.User) error {
	query := `
		INSERT INTO users (id, email, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			password_hash = EXCLUDED.password_hash,
			updated_at = EXCLUDED.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		user.ID,
		user.Email.String(),
		user.Password,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to save user: %w", err)
	}

	return nil
}

// FindByID retrieves a user by their ID
func (r *UserPostgresRepository) FindByID(ctx context.Context, id string) (*entity.User, error) {
	query := `SELECT id, email, password_hash, created_at, updated_at FROM users WHERE id = $1`

	var user entity.User
	var emailStr string

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&emailStr,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to find user by ID: %w", err)
	}

	// Convert email string to Email value object
	email, err := vo.NewEmail(emailStr)
	if err != nil {
		return nil, fmt.Errorf("invalid email in database: %w", err)
	}
	user.Email = email

	return &user, nil
}

// FindByEmail retrieves a user by their email address
func (r *UserPostgresRepository) FindByEmail(ctx context.Context, email vo.Email) (*entity.User, error) {
	query := `SELECT id, email, password_hash, created_at, updated_at FROM users WHERE email = $1`

	var user entity.User
	var emailStr string

	err := r.db.QueryRowContext(ctx, query, email.String()).Scan(
		&user.ID,
		&emailStr,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to find user by email: %w", err)
	}

	// Convert email string to Email value object
	emailVO, err := vo.NewEmail(emailStr)
	if err != nil {
		return nil, fmt.Errorf("invalid email in database: %w", err)
	}
	user.Email = emailVO

	return &user, nil
}

// ExistsByEmail checks if a user with the given email exists
func (r *UserPostgresRepository) ExistsByEmail(ctx context.Context, email vo.Email) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, email.String()).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return exists, nil
}

// Delete removes a user by their ID
func (r *UserPostgresRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// UpdatePassword updates a user's password hash
func (r *UserPostgresRepository) UpdatePassword(ctx context.Context, id string, hashedPassword string) error {
	query := `UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`

	result, err := r.db.ExecContext(ctx, query, hashedPassword, id)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}
