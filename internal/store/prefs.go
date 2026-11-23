package store

import "time"

// Prefs returns one administrator's console preferences. They live in the
// site database next to the user they belong to, so a tenant's admin never sees
// another tenant's UI state.
func (s *Store) Prefs(userID int64) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM admin_prefs WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		out[key] = value
	}
	return out, rows.Err()
}

// SetPref stores one preference, or clears it when the value is empty.
func (s *Store) SetPref(userID int64, key, value string) error {
	if value == "" {
		_, err := s.db.Exec(`DELETE FROM admin_prefs WHERE user_id = ? AND key = ?`, userID, key)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO admin_prefs(user_id, key, value, updated_at) VALUES(?, ?, ?, ?)
		ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		userID, key, value, stamp(time.Now()))
	return err
}
