package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

const anomalyColumns = `id, kind, proxy_id, proxy_host, window_start, window_seconds, value, baseline,
	detail, state, created_at, last_seen, acknowledged_by, acknowledged_at`

func scanAnomaly(row interface{ Scan(...any) error }) (*model.AnomalyEvent, error) {
	var e model.AnomalyEvent
	var start, created, seen string
	var ackAt sql.NullString
	err := row.Scan(&e.ID, &e.Kind, &e.ProxyID, &e.ProxyHost, &start, &e.WindowSeconds, &e.Value,
		&e.Baseline, &e.Detail, &e.State, &created, &seen, &e.AcknowledgedBy, &ackAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	e.WindowStart, e.CreatedAt, e.LastSeen = parseStamp(start), parseStamp(created), parseStamp(seen)
	if ackAt.Valid {
		t := parseStamp(ackAt.String)
		e.AcknowledgedAt = &t
	}
	return &e, nil
}

// CreateAnomalyEvent stores one detection.
func (s *Store) CreateAnomalyEvent(e *model.AnomalyEvent) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO anomaly_events(kind, proxy_id, proxy_host, window_start,
		window_seconds, value, baseline, detail, state, created_at, last_seen)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`,
		e.Kind, e.ProxyID, e.ProxyHost, stamp(e.WindowStart), e.WindowSeconds, e.Value, e.Baseline,
		e.Detail, stamp(time.Now()), stamp(time.Now()))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListAnomalyEvents returns the most recent detections.
func (s *Store) ListAnomalyEvents(limit int) ([]model.AnomalyEvent, error) {
	rows, err := s.db.Query(`SELECT `+anomalyColumns+` FROM anomaly_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AnomalyEvent{}
	for rows.Next() {
		e, err := scanAnomaly(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// GetAnomalyEvent loads one event.
func (s *Store) GetAnomalyEvent(id int64) (*model.AnomalyEvent, error) {
	return scanAnomaly(s.db.QueryRow(`SELECT `+anomalyColumns+` FROM anomaly_events WHERE id = ?`, id))
}

// OpenAnomalyEvent finds a still-open event of the same kind for the same host,
// so a condition that lasts ten minutes is reported once.
func (s *Store) OpenAnomalyEvent(kind string, proxyID int64, since time.Time) (*model.AnomalyEvent, bool, error) {
	row := s.db.QueryRow(`SELECT `+anomalyColumns+` FROM anomaly_events
		WHERE kind = ? AND proxy_id = ? AND state = 'open' AND last_seen > ? ORDER BY id DESC LIMIT 1`,
		kind, proxyID, stamp(since))
	e, err := scanAnomaly(row)
	if errors.Is(err, ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return e, true, nil
}

// TouchAnomalyEvent refreshes the value and last-seen of an ongoing event.
func (s *Store) TouchAnomalyEvent(id int64, value float64) error {
	_, err := s.db.Exec(`UPDATE anomaly_events SET value = ?, last_seen = ? WHERE id = ?`,
		value, stamp(time.Now()), id)
	return err
}

// AcknowledgeAnomalyEvent marks an event as seen by an admin.
func (s *Store) AcknowledgeAnomalyEvent(id int64, user string) error {
	_, err := s.db.Exec(`UPDATE anomaly_events SET state = 'acknowledged', acknowledged_by = ?, acknowledged_at = ?
		WHERE id = ? AND state = 'open'`, truncate(user, 64), stamp(time.Now()), id)
	return err
}

// GateFailuresSince counts failed gate logins per proxy inside a window.
func (s *Store) GateFailuresSince(since time.Time) (map[int64]int, error) {
	rows, err := s.db.Query(`SELECT proxy_id, COUNT(*) FROM gate_failures WHERE ts > ? GROUP BY proxy_id`,
		stamp(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}
