package store

import (
	"database/sql"
	"errors"
	"time"
)

// VulnSource is one external vulnerability source's recorded state. Payload is
// the last good snapshot: a failed refresh records the error and leaves the
// snapshot in place, so a bad download never replaces a good one.
type VulnSource struct {
	Source    string
	LastOK    time.Time
	LastError string
	ETag      string
	SHA256    string
	Bytes     int64
	Records   int
	Payload   []byte
}

// SaveVulnSource records a successful sync and its snapshot in one write.
func (s *Store) SaveVulnSource(v VulnSource) error {
	_, err := s.db.Exec(`INSERT INTO vuln_sources(source, last_ok, last_error, etag, sha256, bytes, records, payload)
		VALUES(?, ?, '', ?, ?, ?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET last_ok = excluded.last_ok, last_error = '',
			etag = excluded.etag, sha256 = excluded.sha256, bytes = excluded.bytes,
			records = excluded.records, payload = excluded.payload`,
		v.Source, stamp(v.LastOK), v.ETag, v.SHA256, v.Bytes, v.Records, v.Payload)
	return err
}

// RecordVulnFailure records why a sync failed. The last good snapshot and the
// time it was confirmed stay untouched.
func (s *Store) RecordVulnFailure(source, message string) error {
	_, err := s.db.Exec(`INSERT INTO vuln_sources(source, last_error) VALUES(?, ?)
		ON CONFLICT(source) DO UPDATE SET last_error = excluded.last_error`,
		source, message)
	return err
}

// VulnSource returns one source with its snapshot, or nil when it never synced.
func (s *Store) VulnSource(name string) (*VulnSource, error) {
	row := s.db.QueryRow(`SELECT source, last_ok, last_error, etag, sha256, bytes, records, payload
		FROM vuln_sources WHERE source = ?`, name)
	var v VulnSource
	var lastOK string
	if err := row.Scan(&v.Source, &lastOK, &v.LastError, &v.ETag, &v.SHA256,
		&v.Bytes, &v.Records, &v.Payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	v.LastOK = parseStamp(lastOK)
	return &v, nil
}

// VulnSources lists every source's state without its snapshot, which is all the
// feed page needs.
func (s *Store) VulnSources() ([]VulnSource, error) {
	rows, err := s.db.Query(`SELECT source, last_ok, last_error, etag, sha256, bytes, records
		FROM vuln_sources ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VulnSource{}
	for rows.Next() {
		var v VulnSource
		var lastOK string
		if err := rows.Scan(&v.Source, &lastOK, &v.LastError, &v.ETag, &v.SHA256,
			&v.Bytes, &v.Records); err != nil {
			return nil, err
		}
		v.LastOK = parseStamp(lastOK)
		out = append(out, v)
	}
	return out, rows.Err()
}
