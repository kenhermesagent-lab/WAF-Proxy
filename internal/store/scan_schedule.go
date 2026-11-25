package store

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// ScanSchedule returns one site's scan cadence, or nil when it never saved one.
func (s *Store) ScanSchedule(siteID int64) (*model.ScanSchedule, error) {
	row := s.db.QueryRow(`SELECT site_id, cadence, hour, day, enabled, triggers, signature, updated_by
		FROM scan_schedules WHERE site_id = ? AND (? = 0 OR site_id = ?)`, siteID, s.site, s.site)
	return scanScheduleRow(row)
}

// ListScanSchedules returns every site's schedule, for the scheduler's tick.
func (s *Store) ListScanSchedules() ([]model.ScanSchedule, error) {
	rows, err := s.db.Query(`SELECT site_id, cadence, hour, day, enabled, triggers, signature, updated_by
		FROM scan_schedules ORDER BY site_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ScanSchedule{}
	for rows.Next() {
		sched, err := scanScheduleRow(rows)
		if err != nil {
			return nil, err
		}
		if sched != nil {
			out = append(out, *sched)
		}
	}
	return out, rows.Err()
}

// SaveScanSchedule stores a site's cadence and triggers. The signature is the
// last run's own record, so a save from the page never clears it.
func (s *Store) SaveScanSchedule(sched model.ScanSchedule) error {
	// A tenant's save always lands on the tenant's own site, never on the id in
	// the body.
	if s.site != 0 {
		sched.SiteID = s.site
	}
	_, err := s.db.Exec(`INSERT INTO scan_schedules(site_id, cadence, hour, day, enabled, triggers, updated_by)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(site_id) DO UPDATE SET cadence = excluded.cadence, hour = excluded.hour,
			day = excluded.day, enabled = excluded.enabled, triggers = excluded.triggers,
			updated_by = excluded.updated_by`,
		sched.SiteID, defaultStr(sched.Cadence, "weekly"), sched.Hour, sched.Day,
		b2i(sched.Enabled), strings.Join(sched.Triggers, ","), sched.UpdatedBy)
	return err
}

// SetScanSignature records what the last run saw, so the next tick can skip an
// unchanged site.
func (s *Store) SetScanSignature(siteID int64, signature string) error {
	_, err := s.db.Exec(`UPDATE scan_schedules SET signature = ? WHERE site_id = ? AND (? = 0 OR site_id = ?)`,
		signature, siteID, s.site, s.site)
	return err
}

// scheduleScanner is the shared half of QueryRow and Rows.
type scheduleScanner interface {
	Scan(dest ...any) error
}

func scanScheduleRow(row scheduleScanner) (*model.ScanSchedule, error) {
	var sched model.ScanSchedule
	var triggers string
	var enabled int
	if err := row.Scan(&sched.SiteID, &sched.Cadence, &sched.Hour, &sched.Day,
		&enabled, &triggers, &sched.Signature, &sched.UpdatedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	sched.Enabled = enabled != 0
	sched.Triggers = splitList(triggers)
	return &sched, nil
}

func splitList(raw string) []string {
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
