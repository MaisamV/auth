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

// AuthorizationCodePostgresRepository implements the AuthorizationCodeRepository interface using PostgreSQL
type AuthorizationCodePostgresRepository struct {
	db *sqlx.DB
}

// NewAuthorizationCodePostgresRepository creates a new AuthorizationCodePostgresRepository
func NewAuthorizationCodePostgresRepository(db *sqlx.DB) repository.AuthorizationCodeRepository {
	return &AuthorizationCodePostgresRepository{db: db}
}

// Save stores an authorization code
func (r *AuthorizationCodePostgresRepository) Save(ctx context.Context, code *entity.AuthorizationCode) error {
	query := `
		INSERT INTO authorization_codes (
			code, client_id, user_id, redirect_uri, code_challenge, 
			code_challenge_method, scopes, expires_at, created_at, used
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	scopes := pq.Array(code.Scopes)

	_, err := r.db.ExecContext(ctx, query,
		code.Code,
		code.ClientID,
		code.UserID,
		code.RedirectURI,
		code.CodeChallenge,
		code.CodeChallengeMethod,
		scopes,
		code.ExpiresAt,
		code.CreatedAt,
		code.Used,
	)

	if err != nil {
		return fmt.Errorf("failed to save authorization code: %w", err)
	}

	return nil
}

// FindByCode retrieves an authorization code by its code value
func (r *AuthorizationCodePostgresRepository) FindByCode(ctx context.Context, code string) (*entity.AuthorizationCode, error) {
	query := `
		SELECT code, client_id, user_id, redirect_uri, code_challenge, 
		       code_challenge_method, scopes, expires_at, created_at, used
		FROM authorization_codes WHERE code = $1
	`

	var authCode entity.AuthorizationCode
	var scopes pq.StringArray

	err := r.db.QueryRowContext(ctx, query, code).Scan(
		&authCode.Code,
		&authCode.ClientID,
		&authCode.UserID,
		&authCode.RedirectURI,
		&authCode.CodeChallenge,
		&authCode.CodeChallengeMethod,
		&scopes,
		&authCode.ExpiresAt,
		&authCode.CreatedAt,
		&authCode.Used,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("authorization code not found")
		}
		return nil, fmt.Errorf("failed to find authorization code: %w", err)
	}

	authCode.Scopes = []string(scopes)

	return &authCode, nil
}

// MarkAsUsed marks an authorization code as used
func (r *AuthorizationCodePostgresRepository) MarkAsUsed(ctx context.Context, code string) error {
	query := `UPDATE authorization_codes SET used = true WHERE code = $1`

	result, err := r.db.ExecContext(ctx, query, code)
	if err != nil {
		return fmt.Errorf("failed to mark authorization code as used: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("authorization code not found")
	}

	return nil
}

// DeleteExpired removes all expired authorization codes
func (r *AuthorizationCodePostgresRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM authorization_codes WHERE expires_at < NOW()`

	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to delete expired authorization codes: %w", err)
	}

	return nil
}

// RefreshTokenPostgresRepository implements the RefreshTokenRepository interface using PostgreSQL
type RefreshTokenPostgresRepository struct {
	db *sqlx.DB
}

// NewRefreshTokenPostgresRepository creates a new RefreshTokenPostgresRepository
func NewRefreshTokenPostgresRepository(db *sqlx.DB) repository.RefreshTokenRepository {
	return &RefreshTokenPostgresRepository{db: db}
}

// Save stores a refresh token
func (r *RefreshTokenPostgresRepository) Save(ctx context.Context, token *entity.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (
			token, client_id, user_id, scopes, expires_at, created_at, revoked
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (token) DO UPDATE SET
			client_id = EXCLUDED.client_id,
			user_id = EXCLUDED.user_id,
			scopes = EXCLUDED.scopes,
			expires_at = EXCLUDED.expires_at,
			revoked = EXCLUDED.revoked
	`

	scopes := pq.Array(token.Scopes)

	_, err := r.db.ExecContext(ctx, query,
		token.Token,
		token.ClientID,
		token.UserID,
		scopes,
		token.ExpiresAt,
		token.CreatedAt,
		token.Revoked,
	)

	if err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}

	return nil
}

// FindByToken retrieves a refresh token by its token value
func (r *RefreshTokenPostgresRepository) FindByToken(ctx context.Context, token string) (*entity.RefreshToken, error) {
	query := `
		SELECT token, client_id, user_id, scopes, expires_at, created_at, revoked
		FROM refresh_tokens WHERE token = $1
	`

	var refreshToken entity.RefreshToken
	var scopes pq.StringArray

	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&refreshToken.Token,
		&refreshToken.ClientID,
		&refreshToken.UserID,
		&scopes,
		&refreshToken.ExpiresAt,
		&refreshToken.CreatedAt,
		&refreshToken.Revoked,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("refresh token not found")
		}
		return nil, fmt.Errorf("failed to find refresh token: %w", err)
	}

	refreshToken.Scopes = []string(scopes)

	return &refreshToken, nil
}

// FindByUserID retrieves all refresh tokens for a user
func (r *RefreshTokenPostgresRepository) FindByUserID(ctx context.Context, userID string) ([]*entity.RefreshToken, error) {
	query := `
		SELECT token, client_id, user_id, scopes, expires_at, created_at, revoked
		FROM refresh_tokens WHERE user_id = $1 AND revoked = false
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query refresh tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*entity.RefreshToken

	for rows.Next() {
		var token entity.RefreshToken
		var scopes pq.StringArray

		err := rows.Scan(
			&token.Token,
			&token.ClientID,
			&token.UserID,
			&scopes,
			&token.ExpiresAt,
			&token.CreatedAt,
			&token.Revoked,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan refresh token: %w", err)
		}

		token.Scopes = []string(scopes)
		tokens = append(tokens, &token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over refresh tokens: %w", err)
	}

	return tokens, nil
}

// Revoke marks a refresh token as revoked
func (r *RefreshTokenPostgresRepository) Revoke(ctx context.Context, token string) error {
	query := `UPDATE refresh_tokens SET revoked = true WHERE token = $1`

	result, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("refresh token not found")
	}

	return nil
}

// RevokeAllForUser revokes all refresh tokens for a user
func (r *RefreshTokenPostgresRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	query := `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all refresh tokens for user: %w", err)
	}

	return nil
}

// DeleteExpired removes all expired refresh tokens
func (r *RefreshTokenPostgresRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < NOW()`

	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to delete expired refresh tokens: %w", err)
	}

	return nil
}
