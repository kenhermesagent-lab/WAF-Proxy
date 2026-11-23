package store

import "time"

// TrustedDevice remembers a browser that already passed the authenticator
// check. Only the digest is stored: the cookie carries the token itself.
func (s *Store) CreateTrustedDevice(tokenHash string, userID int64, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO trusted_devices(token_hash, user_id, site_id, created_at, expires_at)
		VALUES(?, ?, ?, ?, ?)`, tokenHash, userID, s.site, stamp(time.Now()), stamp(expires))
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
