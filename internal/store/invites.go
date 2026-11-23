package store

import "time"

// Invite is a pending administrator invitation. The account is only created
// when the recipient opens the link and chooses a username and password.
type Invite struct {
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	RoleID    int64     `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateInvite stores a single-use invitation, replacing any earlier pending
// invitation for the same address so only the newest link works.
func (s *Store) CreateInvite(tokenHash, email, firstName, lastName string, roleID int64, expires time.Time) error {
	if _, err := s.db.Exec(`DELETE FROM invites WHERE lower(email) = lower(?) AND (? = 0 OR site_id = ?)`,
		email, s.site, s.site); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO invites(token_hash, site_id, email, first_name, last_name, role_id, created_at, expires_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		tokenHash, s.site, email, firstName, lastName, roleID, stamp(time.Now()), stamp(expires))
	return err
}

// InviteByToken resolves a live invitation. It is not consumed until the
// recipient has created the account.
func (s *Store) InviteByToken(tokenHash string) (*Invite, bool) {
	var inv Invite
	var expires string
	err := s.db.QueryRow(`SELECT email, first_name, last_name, role_id, expires_at FROM invites
		WHERE token_hash = ? AND expires_at > ? AND (? = 0 OR site_id = ?)`,
		tokenHash, stamp(time.Now()), s.site, s.site).Scan(&inv.Email, &inv.FirstName, &inv.LastName, &inv.RoleID, &expires)
	if err != nil {
		return nil, false
	}
	inv.ExpiresAt = parseStamp(expires)
	return &inv, true
}

// DeleteInvite spends an invitation once its account exists.
func (s *Store) DeleteInvite(tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM invites WHERE token_hash = ?`, tokenHash)
	return err
}

// EmailInUse reports whether an administrator already uses the address, so an
// invitation cannot duplicate an account.
func (s *Store) EmailInUse(email string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE lower(email) = lower(?) AND (? = 0 OR site_id = ?)`,
		email, s.site, s.site).Scan(&n)
	return n > 0, err
}
