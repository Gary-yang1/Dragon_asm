package auth

import "time"

// User status values.
const (
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"
)

// User is the domain representation of an application user. It uses Go-native
// types (no DB driver types) so the service layer and its tests stay
// storage-agnostic. PasswordHash carries a bcrypt hash and is never serialised
// to API responses (there is no json tag exposing it — handlers map to DTOs).
type User struct {
	ID           uint64
	TenantID     string
	OrgID        string
	Username     string
	DisplayName  string
	PasswordHash string
	Status       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// IsActive reports whether the user may authenticate. Disabled users are
// rejected at login even with a correct password.
func (u *User) IsActive() bool { return u.Status == UserStatusActive }
