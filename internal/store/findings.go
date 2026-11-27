package store

import (
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// MergeScanFindings records a run's findings and returns what opened and what
// resolved. An accepted finding keeps its state; a resolved one that appears
// again reopens.
func (s *Store) MergeScanFindings(siteID int64, target string, found []model.ScanFinding, now time.Time) (opened, resolved []model.ScanFinding, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback() }()

	prior := map[string]model.ScanFinding{}
	rows, err := tx.Query(`SELECT key, target, stage, class, title, severity, cvss, exploitation,
		cve_ids, product, version, recommendation, note, covered, accepted_note, state, first_seen
		FROM scan_findings WHERE site_id = ? AND target = ?`, siteID, target)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		f, err := scanFindingRow(rows, siteID)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		prior[f.Key] = f
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	seen := map[string]bool{}
	for _, f := range found {
		seen[f.Key] = true
		prev, existed := prior[f.Key]
		state := "open"
		if existed && prev.State == "accepted" {
			state = "accepted"
		}
		first := stamp(now)
		if existed {
			first = stamp(prev.FirstSeen)
		}
		// The stages build findings without a target; the run's hostname is the
		// one that found them, so the page never shows a finding with no site.
		if f.Target == "" {
			f.Target = target
		}
		if !existed || prev.State == "resolved" {
			f.State = state
			opened = append(opened, f)
		}
		if _, err := tx.Exec(`INSERT INTO scan_findings(site_id, key, target, stage, class, title, severity,
			cvss, exploitation, cve_ids, product, version, recommendation, note, covered, accepted_note, state, first_seen, last_seen)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?)
			ON CONFLICT(site_id, key) DO UPDATE SET target = excluded.target, stage = excluded.stage,
				class = excluded.class, title = excluded.title, severity = excluded.severity,
				cvss = excluded.cvss, exploitation = excluded.exploitation, cve_ids = excluded.cve_ids,
				product = excluded.product, version = excluded.version,
				recommendation = excluded.recommendation, note = excluded.note, covered = excluded.covered,
				-- accepted_note is the operator's, never the excluded scan note.
				state = excluded.state, last_seen = excluded.last_seen`,
			siteID, f.Key, f.Target, f.Stage, f.Class, f.Title, f.Severity, f.CVSS, f.Exploitation,
			strings.Join(f.CVEIDs, ","), f.Product, f.Version, f.Recommendation, f.Note, b2i(f.Covered), state,
			first, stamp(now)); err != nil {
			return nil, nil, err
		}
	}
	for key, f := range prior {
		if seen[key] || f.State != "open" {
			continue
		}
		if _, err := tx.Exec(`UPDATE scan_findings SET state = 'resolved', last_seen = ?
			WHERE site_id = ? AND key = ?`, stamp(now), siteID, key); err != nil {
			return nil, nil, err
		}
		resolved = append(resolved, f)
	}
	return opened, resolved, tx.Commit()
}

// ListScanFindings returns one site's findings, newest first, filtered by state
// and severity. Empty filters return everything.
func (s *Store) ListScanFindings(state, severity string) ([]model.ScanFinding, error) {
	rows, err := s.db.Query(`SELECT key, target, stage, class, title, severity, cvss, exploitation,
		cve_ids, product, version, recommendation, note, covered, accepted_note, state, first_seen
		FROM scan_findings WHERE (? = '' OR state = ?) AND (? = '' OR severity = ?)
			AND (? = 0 OR site_id = ?)
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
			WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC`,
		state, state, severity, severity, s.site, s.site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ScanFinding{}
	for rows.Next() {
		f, err := scanFindingRow(rows, s.site)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// UpdateScanFinding changes a finding's state and, when one is given, the
// operator's acceptance reason. The scan's own note is never changed here.
// The state is validated by the caller; this returns ErrNotFound when the site
// has no such finding.
func (s *Store) UpdateScanFinding(key, state string, reason *string) error {
	res, err := s.db.Exec(`UPDATE scan_findings SET state = ?,
		accepted_note = CASE WHEN ? THEN ? ELSE accepted_note END
		WHERE key = ? AND (? = 0 OR site_id = ?)`,
		state, reason != nil, derefString(reason), key, s.site, s.site)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func scanFindingRow(row interface{ Scan(...any) error }, siteID int64) (model.ScanFinding, error) {
	var f model.ScanFinding
	var cves, firstSeen string
	var covered int
	if err := row.Scan(&f.Key, &f.Target, &f.Stage, &f.Class, &f.Title, &f.Severity, &f.CVSS,
		&f.Exploitation, &cves, &f.Product, &f.Version, &f.Recommendation, &f.Note, &covered, &f.Reason, &f.State,
		&firstSeen); err != nil {
		return model.ScanFinding{}, err
	}
	f.SiteID = siteID
	f.Covered = covered != 0
	f.FirstSeen = parseStamp(firstSeen)
	f.CVEIDs = splitList(cves)
	return f, nil
}
