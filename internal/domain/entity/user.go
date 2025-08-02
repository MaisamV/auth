package entity

import (
	"github.com/auth-service/internal/domain/vo"
	"time"
)

// User represents a user in the system
type User struct {
	ID        string    `json:"id" db:"id"`
	Email     vo.Email  `json:"email" db:"email"`
	Password  string    `json:"-" db:"password_hash"` // Never expose password in JSON
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// NewUser creates a new user with the given email and hashed password
func NewUser(email vo.Email, hashedPassword string) *User {
	now := time.Now()
	return &User{
		Email:     email,
		Password:  hashedPassword,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// UpdatePassword updates the user's password hash
func (u *User) UpdatePassword(hashedPassword string) {
	u.Password = hashedPassword
	u.UpdatedAt = time.Now()
}
