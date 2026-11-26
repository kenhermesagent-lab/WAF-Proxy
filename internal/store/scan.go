package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// CreateScanRun records a scan that is about to start.
func (s *Store) CreateScanRun(run *model.ScanRun) (int64, error) {
	// A skipped run is finished the moment it is written, so its end is set
	// here; only a run that starts probing leaves it empty.
	ended := ""
	if run.EndedAt != nil {
		ended = stamp(*run.EndedAt)
	}
	res, err := s.db.Exec(`INSERT INTO scan_runs(site_id, target, trigger, actor, path, started_at, ended_at, agent_node)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		s.site, run.Target, run.Trigger, run.Actor, run.Path, stamp(run.StartedAt), ended, run.AgentNode)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishScanRun closes a run with its verdict counts, the path it proved and
// the reason it stopped early. Path is only known after preflight, so it is
// written here and not at INSERT.
func (s *Store) FinishScanRun(id int64, ended time.Time, verdicts, path, skipped string) error {
	_, err := s.db.Exec(`UPDATE scan_runs SET ended_at = ?, verdicts = ?, path = ?, skipped_reason = ?
		WHERE id = ? AND (? = 0 OR site_id = ?)`,
		stamp(ended), verdicts, path, skipped, id, s.site, s.site)
	return err
}

// AddScanEvidence stores one run's probe results in a single transaction.
func (s *Store) AddScanEvidence(rows []model.ScanEvidence) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, e := range rows {
		if _, err := tx.Exec(`INSERT INTO scan_evidence(run_id, seq, stage, class, method, path, verdict,
			wan_status, upstream_status, wan_hash, upstream_hash, similarity, detail, note)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			e.RunID, e.Seq, e.Stage, e.Class, e.Method, e.Path, e.Verdict, e.WANStatus, e.UpStatus,
			e.WANHash, e.UpHash, e.Similarity, e.Detail, e.Note); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListScanRuns returns recent runs, newest first.
func (s *Store) ListScanRuns(limit int) ([]model.ScanRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id, site_id, target, trigger, actor, path, started_at, ended_at,
		verdicts, skipped_reason, agent_node FROM scan_runs
		WHERE (? = 0 OR site_id = ?) ORDER BY started_at DESC LIMIT ?`, s.site, s.site, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ScanRun{}
	for rows.Next() {
		r, err := scanRunRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ScanRunByID returns one run this site owns, or ErrNotFound. A run outside
// the newest page of history is still readable, and so is its evidence.
func (s *Store) ScanRunByID(id int64) (*model.ScanRun, error) {
	row := s.db.QueryRow(`SELECT id, site_id, target, trigger, actor, path, started_at, ended_at,
		verdicts, skipped_reason, agent_node FROM scan_runs
		WHERE id = ? AND (? = 0 OR site_id = ?)`, id, s.site, s.site)
	r, err := scanRunRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &r, nil
}

func scanRunRow(row interface{ Scan(...any) error }) (model.ScanRun, error) {
	var r model.ScanRun
	var started, ended string
	if err := row.Scan(&r.ID, &r.SiteID, &r.Target, &r.Trigger, &r.Actor, &r.Path,
		&started, &ended, &r.Verdicts, &r.Skipped, &r.AgentNode); err != nil {
		return r, err
	}
	r.StartedAt = parseStamp(started)
	if ended != "" {
		at := parseStamp(ended)
		r.EndedAt = &at
	}
	return r, nil
}

// ListScanEvidence returns one run's probe results in probe order.
func (s *Store) ListScanEvidence(runID int64) ([]model.ScanEvidence, error) {
	rows, err := s.db.Query(`SELECT e.run_id, e.seq, e.stage, e.class, e.method, e.path, e.verdict,
		e.wan_status, e.upstream_status, e.wan_hash, e.upstream_hash, e.similarity, e.detail, e.note
		FROM scan_evidence e JOIN scan_runs r ON r.id = e.run_id
		WHERE e.run_id = ? AND (? = 0 OR r.site_id = ?) ORDER BY e.seq`, runID, s.site, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ScanEvidence{}
	for rows.Next() {
		var e model.ScanEvidence
		if err := rows.Scan(&e.RunID, &e.Seq, &e.Stage, &e.Class, &e.Method, &e.Path, &e.Verdict,
			&e.WANStatus, &e.UpStatus, &e.WANHash, &e.UpHash, &e.Similarity, &e.Detail, &e.Note); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeScanEvidence drops evidence of runs that ended before the cutoff. The
// run row stays: the record that a scan happened is not evidence.
func (s *Store) PurgeScanEvidence(before time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM scan_evidence WHERE run_id IN (
		SELECT id FROM scan_runs WHERE ended_at <> '' AND ended_at < ? AND (? = 0 OR site_id = ?))`,
		stamp(before), s.site, s.site)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
