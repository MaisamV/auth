package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/auth-service/internal/application/repository"
	"github.com/auth-service/internal/domain/entity"
	"github.com/auth-service/internal/domain/vo"
	"github.com/jmoiron/sqlx"
)

// SessionRefreshTokenPostgresRepository implements the SessionRefreshTokenRepository interface using PostgreSQL
type SessionRefreshTokenPostgresRepository struct {
	db *sqlx.DB
}

// NewSessionRefreshTokenPostgresRepository creates a new SessionRefreshTokenPostgresRepository
func NewSessionRefreshTokenPostgresRepository(db *sqlx.DB) repository.SessionRefreshTokenRepository {
	return &SessionRefreshTokenPostgresRepository{db: db}
}

// Save stores a session refresh token
func (r *SessionRefreshTokenPostgresRepository) Save(ctx context.Context, token *entity.SessionRefreshToken, tokenHash string) error {
	var revokeReasonStr *string
	if reason := token.GetRevokeReason(); reason != nil {
		reasonStr := reason.String()
		revokeReasonStr = &reasonStr
	}

	query := `
		INSERT INTO session_refresh_tokens (
			id, token_hash, user_id, expires_at, created_at, revoked, last_used_at, revoke_reason
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			token_hash = EXCLUDED.token_hash,
			user_id = EXCLUDED.user_id,
			expires_at = EXCLUDED.expires_at,
			revoked = EXCLUDED.revoked,
			last_used_at = EXCLUDED.last_used_at,
			revoke_reason = EXCLUDED.revoke_reason
	`

	_, err := r.db.ExecContext(ctx, query,
		token.GetID(),
		tokenHash,
		token.GetUserID(),
		token.GetExpiresAt(),
		token.GetCreatedAt(),
		token.IsRevoked(),
		token.GetLastUsedAtPtr(),
		revokeReasonStr,
	)

	if err != nil {
		return fmt.Errorf("failed to save session refresh token: %w", err)
	}

	return nil
}

// FindByTokenHash retrieves a session refresh token by its hash
func (r *SessionRefreshTokenPostgresRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*entity.SessionRefreshToken, error) {
	query := `
		SELECT id, user_id, expires_at, created_at, revoked, last_used_at, revoke_reason
		FROM session_refresh_tokens WHERE token_hash = $1
	`

	// Scan into separate variables
	var id, userID string
	var expiresAt, createdAt time.Time
	var revoked bool
	var lastUsedAt *time.Time
	var revokeReasonStr *string

	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&id,
		&userID,
		&expiresAt,
		&createdAt,
		&revoked,
		&lastUsedAt,
		&revokeReasonStr,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session refresh token not found")
		}
		return nil, fmt.Errorf("failed to find session refresh token: %w", err)
	}

	// Convert revoke reason string to enum
	var revokeReason *vo.RevokeReason
	if revokeReasonStr != nil {
		reason := vo.RevokeReason(*revokeReasonStr)
		revokeReason = &reason
	}

	// Create entity using the factory method
	token := entity.NewSessionRefreshTokenFromDB(id, userID, expiresAt, createdAt, revoked, lastUsedAt, revokeReason)
	return token, nil
}

// FindByUserID retrieves all session refresh tokens for a user
func (r *SessionRefreshTokenPostgresRepository) FindByUserID(ctx context.Context, userID string) ([]*entity.SessionRefreshToken, error) {
	query := `
		SELECT id, user_id, expires_at, created_at, revoked, last_used_at, revoke_reason
		FROM session_refresh_tokens WHERE user_id = $1 AND revoked = false
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query session refresh tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*entity.SessionRefreshToken

	for rows.Next() {
		// Scan into separate variables
		var id, userIDDB string
		var expiresAt, createdAt time.Time
		var revoked bool
		var lastUsedAt *time.Time
		var revokeReasonStr *string

		err := rows.Scan(
			&id,
			&userIDDB,
			&expiresAt,
			&createdAt,
			&revoked,
			&lastUsedAt,
			&revokeReasonStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session refresh token: %w", err)
		}

		// Convert revoke reason string to enum
		var revokeReason *vo.RevokeReason
		if revokeReasonStr != nil {
			reason := vo.RevokeReason(*revokeReasonStr)
			revokeReason = &reason
		}

		// Create entity using the factory method
		token := entity.NewSessionRefreshTokenFromDB(id, userIDDB, expiresAt, createdAt, revoked, lastUsedAt, revokeReason)
		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over session refresh tokens: %w", err)
	}

	return tokens, nil
}

// Update updates a session refresh token
func (r *SessionRefreshTokenPostgresRepository) Update(ctx context.Context, token *entity.SessionRefreshToken) error {
	var revokeReasonStr *string
	if reason := token.GetRevokeReason(); reason != nil {
		reasonStr := reason.String()
		revokeReasonStr = &reasonStr
	}

	query := `
		UPDATE session_refresh_tokens SET
			revoked = $2,
			last_used_at = $3,
			revoke_reason = $4
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		token.GetID(),
		token.IsRevoked(),
		token.GetLastUsedAtPtr(),
		revokeReasonStr,
	)

	if err != nil {
		return fmt.Errorf("failed to update session refresh token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("session refresh token not found")
	}

	return nil
}



// RevokeWithReason marks a session refresh token as revoked with a specific reason
func (r *SessionRefreshTokenPostgresRepository) RevokeWithReason(ctx context.Context, tokenHash string, reason vo.RevokeReason) error {
	reasonStr := reason.String()
	query := `
		UPDATE session_refresh_tokens SET revoked = true, revoke_reason = $2
		WHERE token_hash = $1
	`

	result, err := r.db.ExecContext(ctx, query, tokenHash, reasonStr)
	if err != nil {
		return fmt.Errorf("failed to revoke session refresh token with reason: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("session refresh token not found")
	}

	return nil
}



// RevokeAllForUserWithReason revokes all session refresh tokens for a user with a specific reason
func (r *SessionRefreshTokenPostgresRepository) RevokeAllForUserWithReason(ctx context.Context, userID string, reason vo.RevokeReason) error {
	reasonStr := reason.String()
	query := `
		UPDATE session_refresh_tokens SET revoked = true, revoke_reason = $2
		WHERE user_id = $1 AND revoked = false
	`

	_, err := r.db.ExecContext(ctx, query, userID, reasonStr)
	if err != nil {
		return fmt.Errorf("failed to revoke all session refresh tokens for user with reason: %w", err)
	}

	return nil
}

// DeleteExpired removes all expired session refresh tokens
func (r *SessionRefreshTokenPostgresRepository) DeleteExpired(ctx context.Context) error {
	query := `
		DELETE FROM session_refresh_tokens
		WHERE expires_at < $1
	`

	_, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete expired session refresh tokens: %w", err)
	}

	return nil
}
