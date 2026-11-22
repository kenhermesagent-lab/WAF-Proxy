package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

const deliveryColumns = `id, link_id, event_id, kind, body, state, attempts, next_attempt_at,
	last_status, last_error, created_at, delivered_at`

func scanDelivery(row interface{ Scan(...any) error }) (*model.Delivery, error) {
	var d model.Delivery
	var next, created string
	var delivered sql.NullString
	err := row.Scan(&d.ID, &d.LinkID, &d.EventID, &d.Kind, &d.Body, &d.State, &d.Attempts, &next,
		&d.LastStatus, &d.LastError, &created, &delivered)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.NextAttemptAt = parseStamp(next)
	d.CreatedAt = parseStamp(created)
	d.DeliveredAt = parseStampPtr(delivered)
	return &d, nil
}

// MaxPendingPerLink caps the durable queue of one agent link. A detector firing
// against a dead agent would otherwise grow the table, and the database file,
// without bound on a device that may be an SD card.
const MaxPendingPerLink = 1000

// EnqueueDelivery stores a webhook payload. It is written before any network
// call so a restart, crash or slow agent cannot lose the event. The oldest
// pending rows of that link are dropped to stay inside MaxPendingPerLink; the
// count is returned so the caller can say so once instead of per event.
func (s *Store) EnqueueDelivery(linkID, eventID int64, kind, body string) (int64, int, error) {
	now := stamp(time.Now())
	res, err := s.db.Exec(`INSERT INTO agent_deliveries(link_id, event_id, kind, body, state,
		attempts, next_attempt_at, created_at) VALUES(?, ?, ?, ?, 'pending', 0, ?, ?)`,
		linkID, eventID, kind, body, now, now)
	if err != nil {
		return 0, 0, err
	}
	trim, err := s.db.Exec(`DELETE FROM agent_deliveries WHERE state = 'pending' AND link_id = ? AND id NOT IN
		(SELECT id FROM agent_deliveries WHERE state = 'pending' AND link_id = ? ORDER BY id DESC LIMIT ?)`,
		linkID, linkID, MaxPendingPerLink)
	if err != nil {
		return 0, 0, err
	}
	id, err := res.LastInsertId()
	dropped, _ := trim.RowsAffected()
	return id, int(dropped), err
}

// DueDeliveries returns pending payloads whose backoff has elapsed.
func (s *Store) DueDeliveries(limit int) ([]model.Delivery, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(`SELECT `+deliveryColumns+` FROM agent_deliveries
		WHERE state = 'pending' AND next_attempt_at <= ? ORDER BY id LIMIT ?`, stamp(time.Now()), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Delivery{}
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// MarkDelivered records a successful handoff.
func (s *Store) MarkDelivered(id int64, status int) error {
	now := stamp(time.Now())
	_, err := s.db.Exec(`UPDATE agent_deliveries SET state = 'delivered', attempts = attempts + 1,
		last_status = ?, last_error = '', delivered_at = ? WHERE id = ?`, status, now, id)
	return err
}

// MarkDeliverySuppressed marks a queued payload whose event class is muted. It
// is not retried while the mute stands, but the row stays for inspection.
func (s *Store) MarkDeliverySuppressed(id int64, reason string) error {
	_, err := s.db.Exec(`UPDATE agent_deliveries SET state = 'suppressed', last_error = ?
		WHERE id = ?`, reason, id)
	return err
}

// MarkDeliveryAttempt records a failed attempt with its next try time. When
// next is nil the delivery is final and marked failed.
func (s *Store) MarkDeliveryAttempt(id int64, status int, errText string, next *time.Time) error {
	if next == nil {
		_, err := s.db.Exec(`UPDATE agent_deliveries SET state = 'failed', attempts = attempts + 1,
			last_status = ?, last_error = ? WHERE id = ?`, status, errText, id)
		return err
	}
	_, err := s.db.Exec(`UPDATE agent_deliveries SET attempts = attempts + 1, last_status = ?,
		last_error = ?, next_attempt_at = ? WHERE id = ?`, status, errText, stamp(*next), id)
	return err
}

// RetryDelivery puts a finished delivery back in the queue immediately.
func (s *Store) RetryDelivery(id int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE agent_deliveries SET state = 'pending', attempts = 0,
		next_attempt_at = ? WHERE id = ?`, stamp(time.Now()), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// LastDeliveries returns the newest delivery per enabled link, keyed by link.
func (s *Store) LastDeliveries() (map[int64]model.Delivery, error) {
	rows, err := s.db.Query(`SELECT ` + deliveryColumns + ` FROM agent_deliveries d
		WHERE d.id = (SELECT MAX(id) FROM agent_deliveries WHERE link_id = d.link_id)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]model.Delivery{}
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out[d.LinkID] = *d
	}
	return out, rows.Err()
}

// DeliveriesForLink returns recent payloads for one link, newest first.
func (s *Store) DeliveriesForLink(linkID int64, limit int) ([]model.Delivery, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := s.db.Query(`SELECT `+deliveryColumns+` FROM agent_deliveries
		WHERE link_id = ? ORDER BY id DESC LIMIT ?`, linkID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Delivery{}
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// PruneDeliveries drops delivery rows that are delivered or suppressed and older than a day,
// and caps the history so a chatty detector cannot grow the table forever.
func (s *Store) PruneDeliveries() error {
	cutoff := stamp(time.Now().Add(-24 * time.Hour))
	if _, err := s.db.Exec(`DELETE FROM agent_deliveries WHERE state IN ('delivered','suppressed') AND created_at < ?`, cutoff); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM agent_deliveries WHERE state IN ('delivered','suppressed') AND id NOT IN
		(SELECT id FROM agent_deliveries WHERE state IN ('delivered','suppressed') ORDER BY id DESC LIMIT 200)`); err != nil {
		return err
	}
	// Abandoned deliveries are kept longer for diagnosis, then dropped so a
	// permanently dead agent cannot fill the table.
	old := stamp(time.Now().Add(-30 * 24 * time.Hour))
	_, err := s.db.Exec(`DELETE FROM agent_deliveries WHERE state = 'failed' AND created_at < ?`, old)
	return err
}

// DeliveryByID loads one queued payload.
func (s *Store) DeliveryByID(id int64) (*model.Delivery, error) {
	return scanDelivery(s.db.QueryRow(`SELECT `+deliveryColumns+` FROM agent_deliveries WHERE id = ?`, id))
}
