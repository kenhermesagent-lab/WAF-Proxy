package store

import "time"

// TrustedDevice is one remembered browser. TokenHash is only an opaque row id:
// the cookie carries the token the digest was made from.
type TrustedDevice struct {
	TokenHash string    `json:"id"`
	UA        string    `json:"ua"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Current marks the browser making the listing request.
	Current bool `json:"current"`
}

// CreateTrustedDevice remembers a browser that already passed the authenticator
// check. Only the digest is stored: the cookie carries the token itself.
func (s *Store) CreateTrustedDevice(tokenHash string, userID int64, ua, ip string, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO trusted_devices(token_hash, user_id, site_id, ua, ip, created_at, expires_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)`, tokenHash, userID, s.site, ua, ip, stamp(time.Now()), stamp(expires))
	return err
}

// TrustedDeviceUser reports the administrator a live device token belongs to.
func (s *Store) TrustedDeviceUser(tokenHash string) (int64, bool) {
	var userID int64
	err := s.db.QueryRow(`SELECT user_id FROM trusted_devices
		WHERE token_hash = ? AND expires_at > ? AND (? = 0 OR site_id = ?)`,
		tokenHash, stamp(time.Now()), s.site, s.site).Scan(&userID)
	return userID, err == nil
}

// ListUserTrustedDevices returns the live remembered browsers of one account,
// newest first.
func (s *Store) ListUserTrustedDevices(userID int64) ([]TrustedDevice, error) {
	rows, err := s.db.Query(`SELECT token_hash, ua, ip, created_at, expires_at
		FROM trusted_devices WHERE user_id = ? AND expires_at > ? AND (? = 0 OR site_id = ?)
		ORDER BY created_at DESC`, userID, stamp(time.Now()), s.site, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrustedDevice{}
	for rows.Next() {
		var d TrustedDevice
		var created, expires string
		if err := rows.Scan(&d.TokenHash, &d.UA, &d.IP, &created, &expires); err != nil {
			return nil, err
		}
		d.CreatedAt = parseStamp(created)
		d.ExpiresAt = parseStamp(expires)
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteUserTrustedDevice forgets one remembered browser of an account.
func (s *Store) DeleteUserTrustedDevice(userID int64, tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM trusted_devices WHERE user_id = ? AND token_hash = ? AND (? = 0 OR site_id = ?)`,
		userID, tokenHash, s.site, s.site)
	return err
}

// DeleteUserTrustedDevices forgets every remembered browser for a user, used
// after a password or authenticator change.
func (s *Store) DeleteUserTrustedDevices(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM trusted_devices WHERE user_id = ? AND (? = 0 OR site_id = ?)`,
		userID, s.site, s.site)
	return err
}

// CreatePasswordReset stores one single-use reset token, replacing any earlier
// token for the same user so only the newest email link works.
func (s *Store) CreatePasswordReset(tokenHash string, userID int64, expires time.Time) error {
	if err := s.DeleteUserPasswordResets(userID); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO password_resets(token_hash, user_id, site_id, created_at, expires_at)
		VALUES(?, ?, ?, ?, ?)`, tokenHash, userID, s.site, stamp(time.Now()), stamp(expires))
	return err
}

// DeleteUserPasswordResets drops the pending reset tokens for a user.
func (s *Store) DeleteUserPasswordResets(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM password_resets WHERE user_id = ? AND (? = 0 OR site_id = ?)`,
		userID, s.site, s.site)
	return err
}

// ConsumePasswordReset spends a reset token and returns its administrator.
func (s *Store) ConsumePasswordReset(tokenHash string) (int64, bool) {
	var userID int64
	err := s.db.QueryRow(`SELECT user_id FROM password_resets
		WHERE token_hash = ? AND expires_at > ? AND (? = 0 OR site_id = ?)`,
		tokenHash, stamp(time.Now()), s.site, s.site).Scan(&userID)
	if err != nil {
		return 0, false
	}
	if _, err := s.db.Exec(`DELETE FROM password_resets WHERE token_hash = ?`, tokenHash); err != nil {
		return 0, false
	}
	return userID, true
}
