package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// The outbox is the row-level half of replication. Configuration travels as a
// whole snapshot; the per-record state in the streamed class (sessions, bans,
// audit, ...) is captured as one row per change and replayed in order by the
// standby. Every capture happens in the same transaction as the change itself,
// so a write can never be acknowledged without its outbox row.
//
// capture is off unless a node id is installed: a standalone install, the CLI
// and a standby all leave the tables empty and pay nothing.

// MaxOutboxBytes is where streaming stops. A standby that falls this far behind
// is faster to repair with a full snapshot than with a backlog of changes.
const MaxOutboxBytes = 100 << 20

// execer is the part of *sql.DB and *sql.Tx a capture needs.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// OutboxEntry is one replicated change. Seq is the local stream position that a
// peer acknowledges; (Origin, OriginSeq) identify the change itself, so a
// redelivery or a second hop cannot apply it twice.
type OutboxEntry struct {
	Seq       int64  `json:"seq"`
	Origin    string `json:"origin"`
	OriginSeq int64  `json:"origin_seq"`
	Kind      string `json:"kind"`
	Op        string `json:"op"`
	RowID     string `json:"row_id,omitempty"`
	Payload   []byte `json:"payload"`
	CreatedAt string `json:"created_at"`
}

// rowDump is the payload of one change: the whole row, so the standby does not
// have to reconstruct it from somewhere else. Key names the columns a delete
// matches.
type rowDump struct {
	Columns []string `json:"columns"`
	Row     []Value  `json:"row"`
	Key     []string `json:"key"`
}

// haCapture is the HA toggle state, behind one pointer so every site-scoped
// copy of a Store shares it. A promotion turns capture on while requests are
// already in flight, so the fields are atomic.
type haCapture struct {
	nodeID   atomic.Value // string
	auditOff atomic.Bool
}

// SetNodeID enables change capture under this node's identity. Empty leaves the
// outbox inert; a promotion sets it before the node starts serving.
func (s *Store) SetNodeID(id string) {
	if s.capture != nil {
		s.capture.nodeID.Store(strings.TrimSpace(id))
	}
}

func (s *Store) nodeIdentity() string {
	if s.capture == nil {
		return ""
	}
	id, _ := s.capture.nodeID.Load().(string)
	return id
}

// Capturing reports whether this handle writes an outbox row with each change.
func (s *Store) Capturing() bool { return s.nodeIdentity() != "" }

// captureRow records the row identified by key as an upsert.
func (s *Store) captureRow(tx execer, table string, keyCols []string, key []any) error {
	if !s.Capturing() {
		return nil
	}
	if len(keyCols) == 0 || len(keyCols) != len(key) {
		return fmt.Errorf("store: %s capture needs one value per key column", table)
	}
	dump, ok, err := readRowByKey(tx, table, keyCols, key)
	if err != nil || !ok {
		return err
	}
	return s.enqueue(tx, table, "upsert", dump)
}

func (s *Store) enqueue(tx execer, table, op string, dump rowDump) error {
	if !s.Capturing() {
		return nil
	}
	payload, err := json.Marshal(dump)
	if err != nil {
		return err
	}
	res, err := tx.Exec(`INSERT INTO ha_outbox(origin, origin_seq, kind, op, row_id, payload, created_at)
		VALUES(?, 0, ?, ?, ?, ?, ?)`,
		s.nodeIdentity(), table, op, rowIDOf(dump), payload, stamp(time.Now()))
	if err != nil {
		return fmt.Errorf("store: enqueue %s %s: %w", table, op, err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return err
	}
	// A change's own identity is its first stream position. Copying a change to
	// another node keeps the origin and origin_seq, so the peer can tell a
	// redelivery from a new change.
	_, err = tx.Exec(`UPDATE ha_outbox SET origin_seq = ? WHERE seq = ?`, seq, seq)
	return err
}

func rowIDOf(dump rowDump) string {
	parts := make([]string, 0, len(dump.Key))
	for _, name := range dump.Key {
		for i, col := range dump.Columns {
			if col != name || i >= len(dump.Row) {
				continue
			}
			parts = append(parts, fmt.Sprint(decodeValue(dump.Row[i])))
		}
	}
	return strings.Join(parts, "\x00")
}

// upsertChanged runs a write and captures the row it wrote. fn returns the key
// of that row. Without capture it runs on the pool directly, as before.
func (s *Store) upsertChanged(table string, keyCols []string, fn func(execer) ([]any, error)) error {
	if !s.Capturing() {
		_, err := fn(s.db)
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	key, err := fn(tx)
	if err != nil {
		return err
	}
	if err := s.captureRow(tx, table, keyCols, key); err != nil {
		return err
	}
	return tx.Commit()
}

// deleteCaptured removes every row matching where, recording each one first so
// the standby can remove the same rows. It returns the number deleted.
func (s *Store) deleteCaptured(table string, keyCols []string, where string, args ...any) (int64, error) {
	if !s.Capturing() {
		res, err := s.db.Exec(`DELETE FROM `+quoteIdent(table)+` WHERE `+where, args...)
		if err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	n, err := s.deleteCapturedTx(tx, table, keyCols, where, args...)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// deleteCapturedTx is deleteCaptured inside a transaction the caller owns, so a
// multi-step write can keep its state change and its captures together.
func (s *Store) deleteCapturedTx(tx *sql.Tx, table string, keyCols []string, where string, args ...any) (int64, error) {
	q := `SELECT ` + joinIdents(keyCols) + ` FROM ` + quoteIdent(table) + ` WHERE ` + where
	rows, err := tx.Query(q, args...)
	if err != nil {
		return 0, err
	}
	var keys [][]any
	for rows.Next() {
		vals := make([]any, len(keyCols))
		ptrs := make([]any, len(keyCols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			rows.Close()
			return 0, err
		}
		keys = append(keys, vals)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, key := range keys {
		dump, ok, err := readRowByKey(tx, table, keyCols, key)
		if err != nil {
			return 0, err
		}
		if !ok {
			continue
		}
		if err := s.enqueue(tx, table, "delete", dump); err != nil {
			return 0, err
		}
	}
	res, err := tx.Exec(`DELETE FROM `+quoteIdent(table)+` WHERE `+where, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func readRowByKey(tx execer, table string, keyCols []string, key []any) (rowDump, bool, error) {
	q := `SELECT * FROM ` + quoteIdent(table) + ` WHERE ` + keyWhere(keyCols)
	rows, err := tx.Query(q, key...)
	if err != nil {
		return rowDump{}, false, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return rowDump{}, false, err
	}
	if !rows.Next() {
		return rowDump{}, false, rows.Err()
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return rowDump{}, false, err
	}
	dump := rowDump{Columns: cols, Key: append([]string(nil), keyCols...)}
	for _, v := range vals {
		dump.Row = append(dump.Row, encodeValue(v))
	}
	return dump, true, rows.Err()
}

func keyWhere(cols []string) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = quoteIdent(c) + ` IS ?`
	}
	return strings.Join(parts, " AND ")
}

// OutboxEntries reads the stream after a sequence, oldest first.
func (s *Store) OutboxEntries(after int64, limit int) ([]OutboxEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT seq, origin, origin_seq, kind, op, row_id, payload, created_at
		FROM ha_outbox WHERE seq > ? ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OutboxEntry{}
	for rows.Next() {
		var e OutboxEntry
		if err := rows.Scan(&e.Seq, &e.Origin, &e.OriginSeq, &e.Kind, &e.Op, &e.RowID, &e.Payload, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// OutboxSeq is the newest stream position.
func (s *Store) OutboxSeq() (int64, error) {
	var seq int64
	err := s.db.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM ha_outbox`).Scan(&seq)
	return seq, err
}

// OutboxStats is what `ha status` and the diagnostics endpoint report.
type OutboxStats struct {
	Depth   int64            `json:"depth"`
	Bytes   int64            `json:"bytes"`
	MaxSeq  int64            `json:"max_seq"`
	MinSeq  int64            `json:"min_seq"`
	Oldest  string           `json:"oldest,omitempty"`
	Pending map[string]int64 `json:"pending_by_kind"`
}

// OutboxStats reads the queue size and its per-kind breakdown in one go.
func (s *Store) OutboxStats() (OutboxStats, error) {
	out := OutboxStats{Pending: map[string]int64{}}
	var oldest sql.NullString
	err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(LENGTH(payload)), 0),
		COALESCE(MAX(seq), 0), COALESCE(MIN(seq), 0), MIN(created_at) FROM ha_outbox`).
		Scan(&out.Depth, &out.Bytes, &out.MaxSeq, &out.MinSeq, &oldest)
	if err != nil {
		return out, err
	}
	out.Oldest = oldest.String
	rows, err := s.db.Query(`SELECT kind, COUNT(*) FROM ha_outbox GROUP BY kind ORDER BY kind`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var n int64
		if err := rows.Scan(&kind, &n); err != nil {
			return out, err
		}
		out.Pending[kind] = n
	}
	return out, rows.Err()
}

// PruneOutbox discards changes a peer has acknowledged, and the dedupe records
// that can no longer be redelivered.
func (s *Store) PruneOutbox(seq int64) error {
	if seq <= 0 {
		return nil
	}
	if _, err := s.db.Exec(`DELETE FROM ha_outbox WHERE seq <= ?`, seq); err != nil {
		return err
	}
	return s.PruneApplied(seq)
}

// PruneApplied drops applied markers below a stream position. A marker below
// the peer's watermark can never be delivered again.
func (s *Store) PruneApplied(seq int64) error {
	if seq <= 0 {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM ha_applied WHERE origin_seq <= ?`, seq)
	return err
}

// AckPeer records how far this node has consumed a peer's stream.
func (s *Store) AckPeer(peer string, seq int64) error {
	_, err := s.db.Exec(`INSERT INTO ha_peer_ack(peer, acked_seq, updated_at) VALUES(?, ?, ?)
		ON CONFLICT(peer) DO UPDATE SET acked_seq = MAX(ha_peer_ack.acked_seq, excluded.acked_seq),
		updated_at = excluded.updated_at`, peer, seq, stamp(time.Now()))
	return err
}

// PeerAck reports the acknowledged position and when it was last advanced.
func (s *Store) PeerAck(peer string) (int64, time.Time, error) {
	var seq int64
	var updated string
	err := s.db.QueryRow(`SELECT acked_seq, updated_at FROM ha_peer_ack WHERE peer = ?`, peer).Scan(&seq, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, time.Time{}, nil
	}
	if err != nil {
		return 0, time.Time{}, err
	}
	return seq, parseStamp(updated), nil
}

// ApplyResult summarises one applied batch.
type ApplyResult struct {
	Applied int `json:"applied"`
	// LastSeq is the highest stream position examined, applied or already
	// known. The caller uses it to decide whether the batch was contiguous.
	LastSeq int64 `json:"last_seq"`
}

// ApplyOutbox replays a peer's changes in order. Entries already applied are
// skipped by (origin, origin_seq), so a redelivery is harmless; a change this
// node made itself is skipped too. Only streamed tables are accepted, so a
// peer cannot use the outbox to rewrite configuration behind the snapshot.
func (s *Store) ApplyOutbox(entries []OutboxEntry) (ApplyResult, error) {
	res := ApplyResult{}
	if len(entries) == 0 {
		return res, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, e := range entries {
		if e.Seq > res.LastSeq {
			res.LastSeq = e.Seq
		}
		if own := s.nodeIdentity(); e.Origin == own && own != "" {
			continue
		}
		var seen int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM ha_applied WHERE origin = ? AND origin_seq = ?`,
			e.Origin, e.OriginSeq).Scan(&seen); err != nil {
			return res, err
		}
		if seen > 0 {
			continue
		}
		if err := applyEntry(tx, e); err != nil {
			return res, err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO ha_applied(origin, origin_seq, applied_at) VALUES(?, ?, ?)`,
			e.Origin, e.OriginSeq, stamp(time.Now())); err != nil {
			return res, err
		}
		res.Applied++
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	return res, nil
}

func applyEntry(tx *sql.Tx, e OutboxEntry) error {
	var dump rowDump
	if err := json.Unmarshal(e.Payload, &dump); err != nil {
		return fmt.Errorf("store: outbox payload for %s: %w", e.Kind, err)
	}
	if len(dump.Columns) == 0 || len(dump.Columns) != len(dump.Row) {
		return fmt.Errorf("store: outbox payload for %s is malformed", e.Kind)
	}
	// The authenticator replay guard is the one users column that travels as a
	// change rather than in the configuration snapshot.
	if e.Kind == "users" {
		return applyTOTPStep(tx, dump)
	}
	class, ok := ClassOf(e.Kind)
	if !ok {
		return fmt.Errorf("store: outbox names unknown table %q", e.Kind)
	}
	if class != ClassStreamed {
		return fmt.Errorf("store: outbox change to %s table %q refused", class, e.Kind)
	}
	switch e.Op {
	case "upsert":
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(dump.Columns)), ",")
		args := make([]any, len(dump.Row))
		for i, v := range dump.Row {
			args[i] = decodeValue(v)
		}
		q := `INSERT OR REPLACE INTO ` + quoteIdent(e.Kind) + ` (` + joinIdents(dump.Columns) + `) VALUES (` + placeholders + `)`
		if _, err := tx.Exec(q, args...); err != nil {
			return fmt.Errorf("store: apply %s upsert %s: %w", e.Kind, e.RowID, err)
		}
		if e.Kind == "audit" {
			if err := refreshAuditHead(tx, dump); err != nil {
				return err
			}
		}
	case "delete":
		if len(dump.Key) == 0 {
			return fmt.Errorf("store: outbox delete for %s names no key", e.Kind)
		}
		args := make([]any, len(dump.Key))
		for i, name := range dump.Key {
			found := false
			for j, col := range dump.Columns {
				if col == name {
					args[i] = decodeValue(dump.Row[j])
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("store: outbox delete for %s has no %s column", e.Kind, name)
			}
		}
		q := `DELETE FROM ` + quoteIdent(e.Kind) + ` WHERE ` + keyWhere(dump.Key)
		if _, err := tx.Exec(q, args...); err != nil {
			return fmt.Errorf("store: apply %s delete %s: %w", e.Kind, e.RowID, err)
		}
	default:
		return fmt.Errorf("store: unknown outbox operation %q", e.Op)
	}
	return nil
}

// applyTOTPStep replays an accepted authenticator step. It never inserts a
// user (configuration is the snapshot's job) and never lowers a stored step, so
// a delayed or replayed change cannot reopen a code that was already spent.
func applyTOTPStep(tx *sql.Tx, dump rowDump) error {
	if len(dump.Columns) != 2 || dump.Columns[0] != "id" || dump.Columns[1] != "totp_last_step" {
		return errors.New("store: a users change may only carry the authenticator step")
	}
	userID, step := dump.Row[0].Int, dump.Row[1].Int
	_, err := tx.Exec(`UPDATE users SET totp_last_step = MAX(totp_last_step, ?) WHERE id = ?`, step, userID)
	return err
}

// refreshAuditHead keeps the standby's head pointer equal to the newest applied
// audit row, so a failover does not report a truncated chain.
func refreshAuditHead(tx *sql.Tx, dump rowDump) error {
	var head string
	for i, col := range dump.Columns {
		if col == "hash" && i < len(dump.Row) {
			head = dump.Row[i].Text
		}
	}
	if head == "" {
		return nil
	}
	_, err := tx.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, auditHeadKey, head)
	return err
}
