package vo

// RevokeReason represents the reason why a session refresh token was revoked
type RevokeReason string

const (
	// RevokeReasonRefresh indicates the token was revoked due to refresh operation
	RevokeReasonRefresh RevokeReason = "REFRESH"
	
	// RevokeReasonLogout indicates the token was revoked due to user logout
	RevokeReasonLogout RevokeReason = "LOGOUT"
	
	// RevokeReasonPassChange indicates the token was revoked due to password change
	RevokeReasonPassChange RevokeReason = "PASS_CHANGE"
	
	// RevokeReasonSuspect indicates the token was revoked due to suspicious activity
	RevokeReasonSuspect RevokeReason = "SUSPECT"
	
	// RevokeReasonAdmin indicates the token was revoked by administrator
	RevokeReasonAdmin RevokeReason = "ADMIN"
)

// String returns the string representation of the revoke reason
func (r RevokeReason) String() string {
	return string(r)
}

// IsValid checks if the revoke reason is valid
func (r RevokeReason) IsValid() bool {
	switch r {
	case RevokeReasonRefresh, RevokeReasonLogout, RevokeReasonPassChange, RevokeReasonSuspect, RevokeReasonAdmin:
		return true
	default:
		return false
	}
}