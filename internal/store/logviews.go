package store

import (
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// ListLogViews returns every saved log view, newest edit first among names.
func (s *Store) ListLogViews() ([]model.LogView, error) {
	rows, err := s.db.Query(`SELECT name, query, updated_by, updated_at FROM log_views ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.LogView{}
	for rows.Next() {
		var v model.LogView
		var updated string
		if err := rows.Scan(&v.Name, &v.Query, &v.UpdatedBy, &updated); err != nil {
			return nil, err
		}
		v.UpdatedAt = parseStamp(updated)
		out = append(out, v)
	}
	return out, rows.Err()
}

// SaveLogView stores a view under its name. Saving an existing name replaces
// its filters, so two operators refining the same view do not create duplicates.
func (s *Store) SaveLogView(name, query, by string) error {
	_, err := s.db.Exec(`INSERT INTO log_views(name, query, updated_by, updated_at) VALUES(?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET query = excluded.query, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`, name, query, by, stamp(time.Now()))
	return err
}

// DeleteLogView removes a view, reporting a name that does not exist.
func (s *Store) DeleteLogView(name string) error {
	res, err := s.db.Exec(`DELETE FROM log_views WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}
