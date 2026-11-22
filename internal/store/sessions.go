package store

import "time"

// DeleteUserSessions removes every administrator session for a user, including
// the caller's session when it belongs to that user.
func (s *Store) DeleteUserSessions(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// DeleteOtherSessions removes every session for a user except keepID, used
// after a credential rotation so other browsers must sign in again while the
// current tab stays usable.
func (s *Store) DeleteOtherSessions(userID int64, keepID string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ? AND id <> ?`, userID, s.sessionID(keepID))
	return err
}

// CountUserSessions reports how many live sessions a user has.
func (s *Store) CountUserSessions(userID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id = ? AND expires_at > ?`,
		userID, stamp(time.Now())).Scan(&n)
	return n, err
}
